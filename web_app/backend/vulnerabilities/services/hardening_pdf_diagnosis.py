"""Device-first PDF for the additive VISOR OT hardening diagnosis contract.

Pure ReportLab presentation. No ORM, no NVD requests or CVE re-evaluation.
Legacy PDF rendering lives in hardening_pdf.py and remains separately callable.
"""
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
from xml.sax.saxutils import escape
import re

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    HRFlowable, KeepTogether, LongTable, PageBreak, Paragraph,
    SimpleDocTemplate, Spacer, TableStyle,
)

INK = colors.HexColor("#172C46")
BLUE = colors.HexColor("#1263A3")
MUTED = colors.HexColor("#536579")
BORDER = colors.HexColor("#D7E2EC")
PALE = colors.HexColor("#F2F7FB")


def _fonts():
    # Bundled system fonts are optional; the renderer must work on Linux,
    # Windows and macOS even when DejaVu is unavailable.
    candidates = [
        Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
        Path("/usr/local/share/fonts/DejaVuSans.ttf"),
    ]
    for normal in candidates:
        bold = normal.with_name("DejaVuSans-Bold.ttf")
        if normal.is_file() and bold.is_file():
            if "VisorDiag" not in pdfmetrics.getRegisteredFontNames():
                pdfmetrics.registerFont(TTFont("VisorDiag", str(normal)))
                pdfmetrics.registerFont(TTFont("VisorDiagBold", str(bold)))
                pdfmetrics.registerFontFamily("VisorDiag", normal="VisorDiag",
                                              bold="VisorDiagBold")
            return "VisorDiag", "VisorDiagBold"
    return "Helvetica", "Helvetica-Bold"


def _styles():
    font, bold = _fonts()
    def make(name, size, leading, *, color=INK, before=0, after=5,
             weight=False):
        return ParagraphStyle(
            name, fontName=bold if weight else font, fontSize=size,
            leading=leading, textColor=color, spaceBefore=before,
            spaceAfter=after, splitLongWords=True,
        )
    return {
        "cover": make("diagnosis-cover", 24, 31, after=16, weight=True),
        "kicker": make("diagnosis-kicker", 11, 15, color=BLUE, after=13, weight=True),
        "subtitle": make("diagnosis-subtitle", 11, 17, color=MUTED, after=12),
        "h1": make("diagnosis-h1", 15, 21, before=13, after=8, weight=True),
        "h2": make("diagnosis-h2", 11, 16, before=9, after=6, color=BLUE, weight=True),
        "h3": make("diagnosis-h3", 9.5, 14, before=6, after=5, weight=True),
        "body": make("diagnosis-body", 8.7, 13.5, after=6),
        "small": make("diagnosis-small", 8, 12, after=4),
        "muted": make("diagnosis-muted", 8, 12, after=6, color=MUTED),
        "cell": make("diagnosis-cell", 7.5, 11, after=0),
        "cellhead": make("diagnosis-cellhead", 7.6, 10.8, after=0,
                         color=colors.white, weight=True),
        "ref": make("diagnosis-ref", 7.4, 11, after=5),
    }


def _value(value, missing="No registrado"):
    return missing if value is None or value == "" or value == [] else str(value)


def _xml(value, missing="No registrado"):
    return escape(_value(value, missing), {'"': '&quot;'}).replace("\n", "<br/>")


def _paragraph(value, style):
    return Paragraph(_xml(value), style)


def _field(story, label, value, styles):
    story.append(Paragraph("<b>" + _xml(label) + ":</b> " + _xml(value),
                           styles["small"]))


def _date(value):
    if not value:
        return "No registrado"
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo:
            parsed = parsed.astimezone(timezone.utc)
            return parsed.strftime("%Y-%m-%d %H:%M UTC")
        return parsed.strftime("%Y-%m-%d %H:%M")
    except (ValueError, TypeError):
        return str(value)


def _table(headers, rows, widths, styles):
    body = [[_paragraph(v, styles["cellhead"]) for v in headers]]
    for row in rows:
        body.append([v if isinstance(v, Paragraph)
                     else _paragraph(v, styles["cell"]) for v in row])
    table = LongTable(body, colWidths=widths, repeatRows=1, hAlign="LEFT",
                      splitByRow=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), INK),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PALE]),
        ("GRID", (0, 0), (-1, -1), .25, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    return table


def _section(story, title, styles):
    story.append(Paragraph(_xml(title), styles["h1"]))
    story.append(HRFlowable(width="100%", thickness=.6,
                            color=BORDER, spaceAfter=8))


def _ref(device):
    # Stable anchor identity from hardware ID, never from a mutable name.
    return "hw-" + str(int(device["hardware_id"]))


def _jump(device, styles, text=None):
    label = text if text is not None else "[{}]".format(device["display_number"])
    return Paragraph('<link href="#{}" color="#1263A3"><u>{}</u></link>'.format(
        _ref(device), _xml(label)), styles["cell"])


def _linked_numbers(devices, styles):
    if not devices:
        return ""
    html = " ".join(
        '<link href="#{}" color="#1263A3"><u>[{}]</u></link>'.format(
            _ref(d), int(d["display_number"])) for d in devices
    )
    return Paragraph(html, styles["cell"])


def _metric(value):
    names = {
        "attackVector": "Vector de ataque", "attackComplexity": "Complejidad",
        "privilegesRequired": "Privilegios requeridos", "userInteraction": "Interacción humana",
        "scope": "Alcance", "confidentialityImpact": "Confidencialidad",
        "integrityImpact": "Integridad", "availabilityImpact": "Disponibilidad",
        "accessVector": "Vector de acceso", "accessComplexity": "Complejidad de acceso",
        "authentication": "Autenticación",
    }
    return names.get(value, value)


def _relevant_references(finding, limit=2):
    """Choose distinct, grounded technical URLs; retain all URLs in the JSON."""
    ranked = {}
    for ref in finding.get("nvd_references") or []:
        if not isinstance(ref, dict):
            continue
        url = ref.get("url")
        if not isinstance(url, str) or not url.startswith(("https://", "http://")):
            continue
        parsed = urlparse(url)
        if not parsed.netloc:
            continue
        tags = ref.get("tags") or []
        if not isinstance(tags, list):
            tags = []
        host = parsed.netloc.lower()
        score = 0
        if "Vendor Advisory" in tags:
            score += 10
        if "Patch" in tags:
            score += 5
        if any(name in host for name in ("siemens.com", "cert.vde.com",
                                                 "openssl.org", "phoenixcontact.com")):
            score += 7
        ranked[url] = max(score, ranked.get(url, -1))
    return [url for url, _ in sorted(ranked.items(), key=lambda x: (-x[1], x[0]))[:limit]]


def _cve(story, finding, styles, references):
    identifier = _value(finding.get("cve_id"))
    story.append(Paragraph(_xml(identifier), styles["h3"]))
    _field(story, "Severidad CVSS / puntuación",
           "{} / {}".format(_value(finding.get("severity")),
                            _value(finding.get("cvss_base_score"))), styles)
    _field(story, "Evaluación vigente",
           "{} ({})".format(_value(finding.get("applicability_status")),
                            _value(finding.get("applicability_source"))), styles)
    story.append(_paragraph(finding.get("description") or "Descripción no disponible en NVD local.",
                            styles["body"]))
    cvss = finding.get("cvss") or {}
    if cvss:
        _field(story, "CVSS versión / vector",
               "{} / {}".format(_value(cvss.get("version")),
                                _value(cvss.get("vector"))), styles)
        metrics = cvss.get("metrics") or {}
        if metrics:
            summary = "; ".join("{}: {}".format(_metric(k), v)
                                for k, v in metrics.items())
            _field(story, "Métricas reportadas por NVD", summary, styles)
        story.append(_paragraph(
            "Las métricas CVSS describen condiciones de evaluación del registro; "
            "no prueban una ruta de explotación real en esta instalación.",
            styles["muted"]))
    else:
        story.append(_paragraph("No se dispone del vector CVSS en el corte.",
                                styles["muted"]))
    for sw in finding.get("evaluated_software") or []:
        _field(story, "Software asociado a la evidencia",
               "{}; versión {}".format(_value(sw.get("name")),
                                       _value(sw.get("version"))), styles)
    automatic = finding.get("automatic_nvd_evidence")
    if isinstance(automatic, dict):
        _field(story, "Configuración NVD evaluada",
               automatic.get("configuration_position"), styles)
        for condition in automatic.get("criteria") or []:
            if isinstance(condition, dict):
                _field(story, "Criterio NVD / CPE confirmado",
                       "{} / {} / vulnerable={}".format(
                           _value(condition.get("criterion")),
                           _value(condition.get("confirmed_cpe")),
                           _value(condition.get("vulnerable"))), styles)
    for review in finding.get("justifications") or []:
        if not isinstance(review, dict):
            continue
        _field(story, "Justificación del analista", review.get("justification"), styles)
        _field(story, "Revisor / fecha",
               "{} / {}".format(_value(review.get("decided_by")),
                                _date(review.get("decided_at"))), styles)
        chosen = review.get("selected_nvd_criterion")
        if isinstance(chosen, dict):
            _field(story, "Criterio elegido", chosen.get("criteria"), styles)
    _field(story, "Última consulta NVD almacenada", _date(finding.get("nvd_retrieved_at")), styles)
    if re.fullmatch(r"CVE-\d{4}-\d{4,}", identifier):
        references.add((identifier, "https://nvd.nist.gov/vuln/detail/" + identifier))
    for url in _relevant_references(finding):
        references.add((identifier, url))
        _field(story, "Aviso técnico asociado", url, styles)
    story.append(Spacer(1, 2*mm))


def _device(story, device, styles, references, width):
    hw = device["hardware"]
    anchor = _ref(device)
    # Paragraph creates the PDF named destination at the actual page location.
    story.append(Paragraph('<a name="{}"/>[{}] {}'.format(
        anchor, int(device["display_number"]), _xml(hw.get("name"))), styles["h2"]))
    _field(story, "Prioridad de revisión", device.get("priority") or "Sin clasificar", styles)
    _field(story, "Criticidad hardware / severidad máxima",
           "{} / {} (CVSS máximo {})".format(
               _value(hw.get("criticality")),
               _value(device.get("priority_basis", {}).get("max_cvss_severity")),
               _value(device.get("priority_basis", {}).get("max_cvss_base_score"))), styles)
    _field(story, "Hardware / rol / ubicación",
           "#{} / {} / {}".format(hw.get("id"), _value(hw.get("role")),
                                _value(hw.get("physical_location"))), styles)
    _field(story, "Fabricante / modelo / CPU",
           "{} / {} / {}".format(_value(hw.get("manufacturer")),
                                _value(hw.get("model")), _value(hw.get("cpu_model"))), styles)
    _field(story, "Serie", hw.get("serial_number"), styles)
    _field(story, "Descripción", hw.get("description"), styles)
    _field(story, "Impacto operativo registrado", hw.get("impact"), styles)
    _field(story, "Reposición registrada", "{} {}".format(
        _value(hw.get("replacement_cost")),
        _value(hw.get("replacement_currency"))), styles)
    _field(story, "Sistemas asociados", ", ".join(
        item.get("name", "") for item in device.get("systems") or []), styles)

    story.append(_paragraph("Software instalado", styles["h3"]))
    installs = device.get("installed_software") or []
    if installs:
        story.append(_table(["Software / producto", "Tipo", "Versión"], [
            ["{} / {}".format(_value(item.get("software_name")),
                              _value(item.get("product"))),
             item.get("software_type"), item.get("version")]
            for item in installs], [width*.57, width*.19, width*.24], styles))
    else:
        story.append(_paragraph("Sin software instalado registrado.", styles["muted"]))

    story.append(_paragraph("Interfaces e identificación", styles["h3"]))
    interfaces = hw.get("interfaces") or []
    if interfaces:
        story.append(_table(["Interfaz", "MAC", "IP declarada"], [
            ["#{}".format(n.get("id")), n.get("mac"), n.get("declared_ip")]
            for n in interfaces], [width*.19, width*.38, width*.43], styles))
    else:
        story.append(_paragraph("Sin interfaces vinculadas en el inventario.", styles["muted"]))
    for cpe in hw.get("confirmed_cpes") or []:
        _field(story, "CPE hardware confirmado", cpe.get("cpe_name"), styles)
    for item in installs:
        for cpe in item.get("confirmed_cpes") or []:
            _field(story, "CPE software confirmado ({})".format(
                _value(item.get("software_name"))), cpe.get("cpe_name"), styles)

    story.append(_paragraph("Comunicaciones atribuibles observadas", styles["h3"]))
    traffic = device.get("attributed_communications") or []
    if traffic:
        story.append(_table(["Origen → destino", "Servicio / puerto",
                             "Paquetes", "Clasificación"], [
            ["{} → {}".format(_value(c.get("source_ip")),
                              _value(c.get("destination_ip"))),
             "{} / {}:{}".format(_value(c.get("service")),
                                  _value(c.get("transport_protocol")),
                                  _value(c.get("service_port"))),
             "{:,}".format(c.get("packets_observed") or 0),
             c.get("classification_status")]
            for c in traffic], [width*.37, width*.27, width*.15, width*.21], styles))
        _field(story, "Alcance de atribución",
               "Identificación mediante ARP de captura y vínculo manual vigente; "
               "no equivale a IP declarada del inventario.", styles)
        for c in traffic:
            _field(story, "Estado de extremos (origen / destino)",
                   "{} / {}".format(_value(c.get("source_resolution_status")),
                                     _value(c.get("destination_resolution_status"))), styles)
    else:
        story.append(_paragraph(
            "No se identificaron comunicaciones atribuibles con evidencia suficiente "
            "en la consulta acotada. Esto NO demuestra ausencia de tráfico.",
            styles["muted"]))
    if device.get("communications_search_limited"):
        story.append(_paragraph("La búsqueda de comunicaciones alcanzó un límite "
                                "de volumen; selección potencialmente parcial.",
                                styles["muted"]))
    _field(story, "Estado de evidencia de red",
           device.get("communications_evidence_status"), styles)

    story.append(_paragraph("Vulnerabilidades aplicables y evidencia", styles["h3"]))
    findings = device.get("findings") or []
    if findings:
        story.append(_table(["CVE", "Severidad", "CVSS", "Origen"], [
            [f.get("cve_id"), f.get("severity"), f.get("cvss_base_score"),
             f.get("applicability_source")] for f in findings],
            [width*.31, width*.23, width*.17, width*.29], styles))
    for finding in findings:
        _cve(story, finding, styles, references)
    story.append(Spacer(1, 4*mm))


def _footer(canvas, document):
    if document.page < 2:
        return
    canvas.saveState()
    w, h = A4
    canvas.setStrokeColor(BORDER)
    canvas.line(19*mm, h-16*mm, w-19*mm, h-16*mm)
    canvas.line(19*mm, 18*mm, w-19*mm, 18*mm)
    canvas.setFillColor(MUTED)
    canvas.setFont("Helvetica", 7.5)
    canvas.drawString(19*mm, h-13*mm, "VISOR OT / DIAGNÓSTICO POR DISPOSITIVOS")
    canvas.drawString(19*mm, 13*mm, "CVE aplicables y evidencia OT")
    canvas.drawRightString(w-19*mm, 13*mm, "Página {}".format(document.page))
    canvas.restoreState()


def render_diagnostic_hardening_pdf(data, destination):
    """Render the approved device-first diagnosis projection from snapshot JSON."""
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ValueError("Contrato JSON inválido: schema_version=1 requerido.")
    diagnosis = data.get("diagnosis")
    if not isinstance(diagnosis, dict) or diagnosis.get("version") != 1:
        raise ValueError("Se requiere diagnosis.version=1 para el PDF nuevo.")
    required = ("summary", "priority_matrix", "prioritized_hardware",
                "prioritized_systems", "conditional_vulnerabilities",
                "inventory_coverage", "evidence_observations")
    if any(name not in diagnosis for name in required):
        raise ValueError("Proyección diagnosis incompleta.")
    devices = diagnosis["prioritized_hardware"]
    if not isinstance(devices, list):
        raise ValueError("prioritized_hardware debe ser una lista.")
    ids = [d.get("hardware_id") for d in devices]
    if any(not isinstance(value, int) or value <= 0 for value in ids) or len(ids) != len(set(ids)):
        raise ValueError("IDs de hardware priorizado inválidos o duplicados.")
    if any(not isinstance(d.get("display_number"), int) for d in devices):
        raise ValueError("Faltan identificadores de presentación.")
    s = _styles()
    width = A4[0] - 38*mm
    story = []
    references = set()

    # Portada
    story.extend([
        Spacer(1, 37*mm),
        Paragraph("VISOR OT / DIAGNÓSTICO TÉCNICO", s["kicker"]),
        Paragraph("Diagnóstico de exposición<br/>de dispositivos OT", s["cover"]),
        HRFlowable(width="92%", thickness=2, color=BLUE, spaceAfter=15),
        Paragraph("Dispositivos con vulnerabilidades conocidas evaluadas como "
                  "aplicables, prioridades de revisión y evidencia técnica", s["subtitle"]),
        Spacer(1, 21*mm),
    ])
    _field(story, "Fecha del corte", _date(data.get("generated_at")), s)
    _field(story, "Fuente", "Inventario VISOR OT, evaluaciones CVE locales, "
           "NVD almacenada y observaciones de PCAP activos.", s)
    story.append(_paragraph(
        "El diagnóstico no constituye certificación de controles ni prueba "
        "de explotación o compromiso de dispositivos.", s["muted"]))
    story.append(PageBreak())

    summary = diagnosis["summary"]
    _section(story, "1. Resumen ejecutivo", s)
    story.append(_paragraph(
        "Identificar dispositivos OT con CVE de aplicabilidad vigente y "
        "organizar su revisión según la criticidad registrada del hardware "
        "y la mayor severidad CVSS aplicable.", s["body"]))
    counts = summary.get("priority_counts") or {}
    rows = [
        ("Hardware activo inventariado", summary.get("active_hardware")),
        ("Dispositivos con CVE aplicables", summary.get("hardware_with_applicable_cves")),
        ("Sistemas con dispositivos priorizados", summary.get("systems_with_prioritized_hardware")),
        ("Pares hardware-CVE aplicables", summary.get("applicable_hardware_cve_pairs")),
        ("Pares hardware-CVE condicionados (apéndice)", summary.get("conditional_hardware_cve_pairs")),
        ("P1 / P2 / P3 / sin clasificar", "{} / {} / {} / {}".format(
            counts.get("P1", 0), counts.get("P2", 0), counts.get("P3", 0),
            counts.get("UNCLASSIFIED", 0))),
    ]
    story.append(_table(["Indicador", "Corte"], rows,
                        [width*.75, width*.25], s))
    story.append(_paragraph(
        "P1, P2 y P3 indican una prioridad ORIENTATIVA de revisión de "
        "hardware, no riesgo calculado ni severidad CVSS nueva. Los equipos "
        "sin hallazgos APPLIES identificados no se consideran libres de vulnerabilidades.",
        s["muted"]))

    _section(story, "2. Matriz de priorización", s)
    story.append(_paragraph(
        "Cada número abre la ficha del dispositivo. La clasificación cruza "
        "criticidad del hardware y máxima severidad CVSS de sus CVE APPLIES.",
        s["small"]))
    by_id = {d["hardware_id"]: d for d in devices}
    matrix_rows = []
    for entry in diagnosis["priority_matrix"]:
        cells = [entry["hardware_criticality"]]
        for cell in entry["cells"]:
            members = [by_id[hid] for hid in cell.get("hardware_ids") or []
                       if hid in by_id]
            html = '<b>{}</b>'.format(_xml(cell.get("priority")))
            if members:
                html += '  ' + ' '.join(
                    '<link href="#{}" color="#1263A3"><u>[{}]</u></link>'.format(
                        _ref(d), int(d["display_number"])) for d in members
                )
            cells.append(Paragraph(html, s["cell"]))
        matrix_rows.append(cells)
    story.append(_table(["Criticidad / CVSS", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
                        matrix_rows, [width*.29]+[width*.1775]*4, s))
    story.append(_paragraph(
        "La clasificación es del equipo, nunca de cada CVE individual.", s["muted"]))

    _section(story, "3. Dispositivos priorizados", s)
    if devices:
        table_rows = []
        for device in devices:
            hw = device["hardware"]
            system_names = ", ".join(
                entry.get("name", "") for entry in device.get("systems") or []
            ) or "Sin sistema asociado"
            table_rows.append([
                _jump(device, s),
                "{} (#{}); {}".format(_value(hw.get("name")),
                                     device["hardware_id"], system_names),
                hw.get("criticality"),
                "{} / {}".format(
                    _value(device.get("priority_basis", {}).get("max_cvss_severity")),
                    _value(device.get("priority_basis", {}).get("max_cvss_base_score"))),
                str(device.get("applicable_cve_count", 0)),
                device.get("priority") or "Sin clasificar",
            ])
        story.append(_table(["Nº", "Equipo y sistema", "Crit.", "Mayor CVSS",
                             "CVE", "Prior."], table_rows,
                            [width*.075, width*.43, width*.09, width*.17,
                             width*.08, width*.155], s))
    else:
        story.append(_paragraph(
            "No existen equipos con APPLIES vigente en este corte; esto "
            "no demuestra ausencia de vulnerabilidades.", s["muted"]))

    story.append(PageBreak())
    _section(story, "4. Diagnóstico por sistemas y dispositivos", s)
    rendered = set()
    for system in diagnosis["prioritized_systems"]:
        story.append(_paragraph(system.get("name"), s["h2"]))
        _field(story, "Criticidad del sistema", system.get("criticality"), s)
        _field(story, "Justificación", system.get("criticality_justification"), s)
        _field(story, "Descripción", system.get("description"), s)
        _field(story, "Impacto", system.get("impact"), s)
        for hid in system.get("prioritized_hardware_ids") or []:
            if hid not in by_id:
                continue
            if hid in rendered:
                story.append(Paragraph(
                    "Dispositivo también asociado: " +
                    '<link href="#{}" color="#1263A3">{}</link>'.format(
                        _ref(by_id[hid]), _xml(by_id[hid]["hardware"].get("name"))),
                    s["small"]))
                continue
            rendered.add(hid)
            _device(story, by_id[hid], s, references, width)
    for device in devices:
        if device["hardware_id"] not in rendered:
            _device(story, device, s, references, width)
            rendered.add(device["hardware_id"])

    _section(story, "Apéndice A. CVE de aplicabilidad condicionada", s)
    conditional = diagnosis["conditional_vulnerabilities"]
    story.append(_paragraph(
        "Los hallazgos condicionados no cuentan como APPLIES, ni generan "
        "prioridad de revisión por sí solos.", s["muted"]))
    if not conditional:
        story.append(_paragraph("No se registraron hallazgos condicionados.", s["muted"]))
    for finding in conditional:
        _cve(story, finding, s, references)

    _section(story, "Apéndice B. Cobertura del inventario", s)
    coverage = diagnosis["inventory_coverage"]
    story.append(_table(["Cobertura", "Cantidad"], [
        ("Hardware activo", coverage.get("active_hardware", 0)),
        ("Software registrado", coverage.get("active_software", 0)),
        ("Sistemas OT registrados", coverage.get("registered_systems", 0)),
        ("CPE confirmados en inventario", coverage.get("confirmed_cpes", 0)),
        ("Hardware sin APPLIES identificado en este corte",
         summary.get("hardware_without_identified_applies", 0)),
    ], [width*.74, width*.26], s))
    story.append(_paragraph(
        "La falta de hallazgos aplicables identificados no certifica "
        "la ausencia de vulnerabilidades ni de superficies de exposición.",
        s["muted"]))

    _section(story, "Apéndice C. Observaciones sobre la evidencia", s)
    observations = diagnosis["evidence_observations"]
    if not observations:
        story.append(_paragraph("No se generaron observaciones adicionales.",
                                s["muted"]))
    for item in observations:
        _field(story, "{} / HW-{} / {}".format(
            _value(item.get("code")), _value(item.get("hardware_id")),
            _value(item.get("cve_id"))), item.get("description"), s)
    story.append(_paragraph(
        "Estas observaciones no sustituyen decisiones de analistas, "
        "no alteran veredictos y no constituyen hallazgos CVE adicionales.", s["muted"]))

    _section(story, "5. Metodología, límites y orientación general", s)
    for paragraph in (
        "Se trabaja con hardware activo, CPE confirmados vigentes y "
        "evaluaciones de aplicabilidad Hardware-CVE existentes; "
        "el PDF no reevalúa condiciones NVD ni consulta Internet.",
        "Las comunicaciones se seleccionan por paquetes, a partir de "
        "ingestas activas. La atribución exige correspondencia ARP "
        "con observación de captura y asociación manual actual. "
        "La falta de atribución no prueba ausencia de tráfico; "
        "su presencia no confirma una ruta de ataque.",
        "Las prioridades P1/P2/P3 son una guía para revisar dispositivos, "
        "no son puntuaciones de riesgo ni evidencias de intrusión.",
        "Como orientación general, contrastar la configuración y versión "
        "instalada con los avisos del fabricante y evaluar cambios con "
        "responsables OT, en ventanas de mantenimiento autorizadas. "
        "No se propone aquí un parche o mitigación específica sin evidencia.",
        "Las asociaciones CPE, versiones y justificaciones humanas "
        "requieren corroboración técnica. Este corte no garantiza "
        "integridad legal, actualización en tiempo real ni cumplimiento "
        "integral de NIST CSF 2.0.",
    ):
        story.append(_paragraph(paragraph, s["body"]))

    _section(story, "Referencias técnicas seleccionadas", s)
    story.append(_paragraph(
        "NVD y avisos almacenados pertinentes a cada CVE. "
        "Se deduplican referencias en esta vista; el JSON conserva "
        "todas las referencias originales.", s["muted"]))
    for ident, url in sorted(references):
        story.append(_paragraph("{}: {}".format(ident, url), s["ref"]))
    if not references:
        story.append(_paragraph("No hay referencias registradas para este corte.", s["muted"]))

    document = SimpleDocTemplate(
        destination, pagesize=A4, leftMargin=19*mm, rightMargin=19*mm,
        topMargin=22*mm, bottomMargin=22*mm,
        title="VISOR OT - Diagnóstico de exposición por dispositivos",
        author="VISOR OT",
    )
    document.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return destination