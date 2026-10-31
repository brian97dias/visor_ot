"""PDF renderer for the version-one VISOR OT hardening evidence contract.

Rendering is pure: no database writes, NVD calls, or new CVE assessments.
Descriptions, CPEs and references are taken from the provided report snapshot.
"""
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
import re
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    HRFlowable, LongTable, PageBreak, Paragraph, SimpleDocTemplate,
    Spacer, TableStyle,
)

INK = colors.HexColor("#172C46")
BLUE = colors.HexColor("#1263A3")
MUTED = colors.HexColor("#536579")
BORDER = colors.HexColor("#D7E2EC")
PALE = colors.HexColor("#F2F7FB")


def _fonts():
    regular = Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf")
    bold = regular.with_name("DejaVuSans-Bold.ttf")
    if regular.exists() and bold.exists():
        if "VisorOT" not in pdfmetrics.getRegisteredFontNames():
            pdfmetrics.registerFont(TTFont("VisorOT", str(regular)))
            pdfmetrics.registerFont(TTFont("VisorOT-Bold", str(bold)))
            pdfmetrics.registerFontFamily(
                "VisorOT", normal="VisorOT", bold="VisorOT-Bold"
            )
        return "VisorOT", "VisorOT-Bold"
    return "Helvetica", "Helvetica-Bold"


def _styles():
    font, bold = _fonts()
    def p(name, size, leading, color=INK, space=4, **kw):
        return ParagraphStyle(
            name, fontName=font, fontSize=size, leading=leading,
            textColor=color, spaceAfter=space, splitLongWords=True, **kw
        )
    return {
        "cover": ParagraphStyle("ot-cover", fontName=bold, fontSize=25,
                                leading=33, textColor=INK, spaceAfter=18),
        "kicker": ParagraphStyle("ot-kicker", fontName=bold, fontSize=11,
                                 leading=15, textColor=BLUE, spaceAfter=12),
        "subtitle": p("ot-subtitle", 12, 18, MUTED, 10),
        "head": ParagraphStyle("ot-head", fontName=bold, fontSize=14,
                              leading=19, textColor=INK, spaceBefore=13,
                              spaceAfter=9, keepWithNext=True),
        "subhead": ParagraphStyle("ot-subhead", fontName=bold, fontSize=10.5,
                                  leading=14, textColor=BLUE, spaceBefore=9,
                                  spaceAfter=5, keepWithNext=True),
        "body": p("ot-body", 9, 14, space=7),
        "small": p("ot-small", 8, 12, space=4),
        "muted": p("ot-muted", 8, 12, MUTED, 6),
        "cell": p("ot-cell", 7.5, 11, space=0, wordWrap="CJK"),
        "cell_head": ParagraphStyle("ot-cell-head", fontName=bold,
                                    fontSize=7.7, leading=11,
                                    textColor=colors.white, wordWrap="CJK"),
        "ref": p("ot-ref", 7.4, 11, space=6, wordWrap="CJK"),
    }


def _val(value, missing="No registrado"):
    if value is None or value == "" or value == []:
        return missing
    return str(value)


def _esc(value, missing="No registrado"):
    return escape(_val(value, missing)).replace("\n", "<br/>")


def _date(value):
    if not value:
        return "No registrada"
    try:
        date = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if date.tzinfo is None:
            return date.strftime("%Y-%m-%d %H:%M")
        return date.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except (ValueError, TypeError):
        return str(value)


def _p(value, style):
    return Paragraph(_esc(value), style)


def _table(headers, rows, widths, s):
    body = [[_p(v, s["cell_head"]) for v in headers]]
    body.extend([[_p(v, s["cell"]) for v in row] for row in rows])
    table = LongTable(
        body, colWidths=widths, repeatRows=1, hAlign="LEFT", splitByRow=1
    )
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), INK),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PALE]),
        ("GRID", (0, 0), (-1, -1), 0.3, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    return table


def _header(story, number, title, s):
    story.append(Paragraph(f"{number}. {_esc(title)}", s["head"]))
    story.append(HRFlowable(width="100%", thickness=.6,
                            color=BORDER, spaceAfter=8))


def _item(story, label, value, s):
    story.append(Paragraph(
        f"<b>{_esc(label)}:</b> {_esc(value)}", s["small"]
    ))


def _bullets(story, values, s):
    for value in values:
        story.append(Paragraph("• " + _esc(value), s["small"]))


def _finding(story, finding, s, conditional=False):
    story.append(Paragraph(
        f"{_esc(finding.get('cve_id'))} · {_esc(finding.get('hardware_name'))}",
        s["subhead"],
    ))
    _item(story, "Aplicabilidad", finding.get("applicability_status"), s)
    _item(story, "Fuente del veredicto", finding.get("applicability_source"), s)
    _item(story, "Criticidad de hardware", finding.get("hardware_criticality"), s)
    _item(story, "Severidad / CVSS",
          f"{_val(finding.get('severity'))} / {_val(finding.get('cvss_base_score'))}", s)
    story.append(_p(finding.get("description") or "Descripción no almacenada.", s["body"]))
    for sw in finding.get("evaluated_software") or []:
        _item(story, "Software asociado a evidencia",
              f"{_val(sw.get('name'))}; versión {_val(sw.get('version'))}; rol NVD {_val(sw.get('role_nvd'))}", s)
    proof = finding.get("automatic_nvd_evidence")
    if isinstance(proof, dict):
        _item(story, "Configuración NVD evaluada", proof.get("configuration_position"), s)
        for criterion in proof.get("criteria") or []:
            _item(story, "Criterio",
                  f"{_val(criterion.get('criterion'))} (vulnerable: {criterion.get('vulnerable')})", s)
    for review in finding.get("justifications") or []:
        _item(story, "Justificación analista", review.get("justification"), s)
        _item(story, "Revisor / fecha",
              f"{_val(review.get('decided_by'))} / {_date(review.get('decided_at'))}", s)
        criterion = review.get("selected_nvd_criterion")
        if isinstance(criterion, dict):
            _item(story, "Criterio seleccionado", criterion.get("criteria"), s)
    _item(story, "Evidencia NVD recuperada", _date(finding.get("nvd_retrieved_at")), s)
    story.append(Spacer(1, 2*mm))


def _footer(canvas, document):
    if document.page < 2:
        return
    canvas.saveState()
    w, h = A4
    canvas.setStrokeColor(BORDER)
    canvas.line(19*mm, h - 16*mm, w - 19*mm, h - 16*mm)
    canvas.line(19*mm, 18*mm, w - 19*mm, 18*mm)
    canvas.setFillColor(MUTED)
    canvas.setFont("Helvetica", 7.5)
    canvas.drawString(19*mm, h - 13*mm, "VISOR OT  /  INFORME DE HARDENING")
    canvas.drawString(19*mm, 13*mm, "Inventario y evidencia OT activa")
    canvas.drawRightString(w - 19*mm, 13*mm, f"Página {document.page}")
    canvas.restoreState()


def render_legacy_hardening_pdf(data, destination):
    """Write a complete PDF from an immutable-in-practice snapshot, not ORM."""
    required = ("summary", "systems", "hardware", "software",
                "communications", "applicable_vulnerabilities",
                "conditional_vulnerabilities")
    if (not isinstance(data, dict) or data.get("schema_version") != 1
            or any(key not in data for key in required)):
        raise ValueError("Contrato JSON inválido: se requiere schema_version=1 completo.")
    s = _styles()
    width = A4[0] - 38*mm
    story = []

    # Portada
    story.extend([
        Spacer(1, 35*mm),
        Paragraph("VISOR OT  /  DIAGNÓSTICO TÉCNICO", s["kicker"]),
        Paragraph("Informe de exposición y<br/>robustecimiento de seguridad<br/>de activos OT", s["cover"]),
        HRFlowable(width="92%", thickness=2, color=BLUE, spaceAfter=19),
        Paragraph("Inventario, comunicaciones y vulnerabilidades conocidas potencialmente aplicables", s["subtitle"]),
        Spacer(1, 22*mm),
    ])
    _item(story, "Fecha del corte", _date(data.get("generated_at")), s)
    _item(story, "Alcance", "Inventario OT activo y tráfico de ingestas activas", s)
    _item(story, "Versión de contrato", data.get("schema_version"), s)
    story.append(_p(
        "El documento refleja evidencia disponible, no una certificación NIST, "
        "una constatación de incidentes ni prueba de ejecución de controles.", s["muted"]))
    story.append(PageBreak())

    # 1. Resumen ejecutivo
    _header(story, 1, "Resumen ejecutivo", s)
    summary = data["summary"]
    metrics = [
        ("Sistemas OT", summary.get("systems", 0)),
        ("Hardware activo", summary.get("hardware", 0)),
        ("Software", summary.get("software_variants", 0)),
        ("Interfaces de red", summary.get("network_interfaces", 0)),
        ("CPE confirmados", summary.get("confirmed_cpes", 0)),
        ("Pares hardware–CVE aplicables", summary.get("applicable_hardware_cve_pairs", 0)),
        ("Pares hardware–CVE condicionados", summary.get("conditional_hardware_cve_pairs", 0)),
    ]
    story.append(_table(["Indicador", "Cantidad"], metrics,
                        [width*.73, width*.27], s))
    story.append(Spacer(1, 4*mm))
    story.append(_p(
        "Los conteos Hardware–CVE son parejas contextualizadas, no incidentes "
        "de explotación ni identificadores CVE únicos. Los casos condicionados "
        "solo aparecen en el apéndice.", s["muted"]))

    # 2. Alcance
    _header(story, 2, "Alcance y metodología", s)
    _bullets(story, [
        "Fuente: inventario activo y evaluaciones CVE vigentes almacenadas en VISOR OT.",
        "Solo se incorporan CPE confirmados, con huella actual y no obsoletos en el catálogo local.",
        "Comunicaciones: tres firmas con mayor suma de paquetes de ingestas ACTIVE; no todos los flujos.",
        "La atribución de hardware a IP requiere captura ARP y asociación manual vigente; no se adivinan extremos ambiguos.",
        "La generación no escanea dispositivos, no consulta NVD ni ejecuta medidas de seguridad.",
        "La clasificación de un flujo es manual y no significa que se haya detectado un ataque.",
        "Este corte no es una instantánea legalmente sellada ni prueba de mitigación.",
    ], s)
    story.append(_p(
        "Alineación de información: NIST CSF 2.0 ID.AM-01, ID.AM-02, "
        "ID.AM-03 e ID.AM-05. No constituye declaración de cumplimiento integral.", s["body"]))

    # 3. Sistemas OT
    _header(story, 3, "Sistemas OT", s)
    for system in data["systems"]:
        story.append(_p(system.get("name"), s["subhead"]))
        for label, key in [
            ("Criticidad", "criticality"), ("Justificación", "criticality_justification"),
            ("Descripción", "description"), ("Impacto operativo", "impact"),
        ]:
            _item(story, label, system.get(key), s)
        _item(story, "ID hardware asociado",
              ", ".join(map(str, system.get("hardware_ids") or [])), s)
    if not data["systems"]:
        story.append(_p("No se registran sistemas OT activos.", s["muted"]))

    # 4. Inventario
    _header(story, 4, "Inventario", s)
    story.append(_p("4.1 Hardware", s["subhead"]))
    hardware = data["hardware"]
    if hardware:
        story.append(_table(["Equipo / ID", "Fabricante y modelo", "Rol", "Criticidad"],
            [[f"{_val(h.get('name'))} (#{h.get('id')})",
              f"{_val(h.get('manufacturer'))} / {_val(h.get('model'))}",
              h.get("role"), h.get("criticality")] for h in hardware],
            [width*.32, width*.34, width*.18, width*.16], s))
    else:
        story.append(_p("Sin hardware activo.", s["muted"]))
    story.append(_p("4.2 Software e instalaciones", s["subhead"]))
    if data["software"]:
        story.append(_table(["Software", "Tipo", "Versión", "Hardware ID"],
            [[sw.get("name"), sw.get("software_type"), sw.get("version"),
              ", ".join(map(str, sw.get("hardware_ids") or [])) or "Sin instalación vigente"]
             for sw in data["software"]],
            [width*.39, width*.20, width*.17, width*.24], s))
    else:
        story.append(_p("Sin software activo.", s["muted"]))
    story.append(_p("4.3 Interfaces y CPE confirmados", s["subhead"]))
    for h in hardware:
        interfaces = h.get("interfaces") or []
        cpes = h.get("confirmed_cpes") or []
        if interfaces or cpes:
            story.append(_p(f"{_val(h.get('name'))} (#{h.get('id')})", s["subhead"]))
        for iface in interfaces:
            _item(story, "Interfaz",
                  f"#{iface.get('id')} · MAC {_val(iface.get('mac'))} · IP declarada {_val(iface.get('declared_ip'))}", s)
        for cpe in cpes:
            _item(story, "CPE hardware confirmado", cpe.get("cpe_name"), s)
    for sw in data["software"]:
        for cpe in sw.get("confirmed_cpes") or []:
            _item(story, f"CPE software ({_val(sw.get('name'))})",
                  cpe.get("cpe_name"), s)
    story.append(_p(
        "Un CPE confirmado refleja una decisión registrada de identificación; "
        "se debe verificar su correspondencia real de producto y versión. "
        "No implica que exista una vulnerabilidad.", s["muted"]))

    # 5. Comunicaciones
    _header(story, 5, "Comunicaciones observadas", s)
    comms = data["communications"]
    if comms:
        story.append(_table(["Origen → destino", "Servicio / puerto",
                             "Paquetes", "Clasificación"],
            [[f"{c.get('source_ip')} → {c.get('destination_ip')}",
              f"{_val(c.get('service'))} / {c.get('transport_protocol')}:{c.get('service_port')}",
              f"{c.get('packets_observed') or 0:,}", c.get("classification_status")]
             for c in comms],
            [width*.40, width*.23, width*.16, width*.21], s))
    else:
        story.append(_p("No hay observaciones activas en este corte.", s["muted"]))
    for c in comms:
        story.append(_p(
            f"{_val(c.get('source_ip'))} → {_val(c.get('destination_ip'))}",
            s["subhead"]))
        _item(story, "Primera / última observación",
              f"{_val(c.get('first_seen'))} / {_val(c.get('last_seen'))}", s)
        for side, title in (("source", "Origen"), ("destination", "Destino")):
            identified = c.get(side + "_hardware")
            name = (f"{identified.get('name')} (#{identified.get('id')})"
                    if isinstance(identified, dict) else "No atribuido")
            _item(story, title + " hardware",
                  f"{name}; resolución {_val(c.get(side + '_resolution_status'))}", s)
    story.append(_p(
        "El ranking es por paquetes observados, no sesiones ni eventos de seguridad. "
        "No permite inferir exposición directa a Internet o intrusión.", s["muted"]))

    # 6. CVEs efectivamente aplicables
    _header(story, 6, "Vulnerabilidades conocidas potencialmente aplicables", s)
    if not data["applicable_vulnerabilities"]:
        story.append(_p(
            "Sin pares APPLIES vigentes; esto no demuestra ausencia de vulnerabilidades.",
            s["muted"]))
    for record in data["applicable_vulnerabilities"]:
        _finding(story, record, s)

    # 7. Hardening: recomendaciones vinculadas con evidencia, no soluciones aplicadas
    _header(story, 7, "Hardening y recomendaciones", s)
    story.append(_p(
        "Son recomendaciones para evaluación y aprobación por responsables OT; "
        "no constatan actualizaciones realizadas ni mitigaciones verificadas.", s["muted"]))
    for finding in data["applicable_vulnerabilities"]:
        _item(story, "Referencia", f"{_val(finding.get('hardware_name'))} / {_val(finding.get('cve_id'))}", s)
        story.append(_p(
            "Consultar el aviso técnico del fabricante, comprobar condiciones de "
            "aplicabilidad y planificar, si corresponde, mitigaciones o actualización "
            "compatible con el equipo y con ventanas de mantenimiento aprobadas.", s["small"]))
        refs = [r.get("url") for r in finding.get("nvd_references") or []
                if isinstance(r, dict) and r.get("url")]
        if refs:
            _item(story, "Fuente almacenada", refs[0], s)
        else:
            story.append(_p(
                "Sin referencia técnica almacenada: investigar antes de actuar.",
                s["muted"]))
    for c in comms:
        if c.get("classification_status") == "NO_AUTORIZADA":
            story.append(_p(
                f"Validar la necesidad operacional de {_val(c.get('source_ip'))} → "
                f"{_val(c.get('destination_ip'))} ({_val(c.get('service'))}); "
                "revisar autorizaciones y segmentación sin interrumpir procesos OT.",
                s["small"]))
    story.append(_p(
        "Revisar periódicamente versiones, asociaciones CPE y dependencias "
        "operativas; ninguna recomendación constituye una instrucción de "
        "actualización automática.", s["small"]))

    # 8. Conclusiones
    _header(story, 8, "Conclusiones y limitaciones", s)
    _bullets(story, [
        f"Se documentan {summary.get('hardware', 0)} activos hardware y {summary.get('software_variants', 0)} variantes de software.",
        f"Se registran {summary.get('applicable_hardware_cve_pairs', 0)} pares Hardware–CVE aplicables y {summary.get('conditional_hardware_cve_pairs', 0)} condicionados.",
        f"Se resumen {len(comms)} firmas de comunicaciones observadas, no la totalidad de la red.",
        "La exactitud del diagnóstico depende de la vigencia de inventario, asociaciones CPE y verificaciones humanas.",
        "Cualquier acción requiere evaluación del impacto operacional y revisión posterior de los resultados.",
    ], s)

    # Apéndice y referencias
    story.append(Paragraph(
        "Apéndice A. CVE de aplicabilidad condicionada", s["head"]))
    story.append(_p(
        "Estos resultados requieren verificación adicional y no forman parte "
        "del conteo de parejas APPLIES.", s["muted"]))
    if not data["conditional_vulnerabilities"]:
        story.append(_p("No hay hallazgos condicionados.", s["muted"]))
    for record in data["conditional_vulnerabilities"]:
        _finding(story, record, s, conditional=True)

    story.append(Paragraph("Referencias técnicas", s["head"]))
    story.append(_p(
        "NVD y fuentes técnicas conservadas en el catálogo local. Los enlaces "
        "no se consultan ni validan nuevamente al generar este documento.", s["muted"]))
    unique_urls = defaultdict(set)
    all_findings = (data["applicable_vulnerabilities"] +
                    data["conditional_vulnerabilities"])
    for record in all_findings:
        identifier = record.get("cve_id")
        if isinstance(identifier, str) and re.fullmatch(r"CVE-\d{4}-\d{4,}", identifier):
            story.append(_p(
                f"NVD {identifier}: https://nvd.nist.gov/vuln/detail/{identifier}",
                s["ref"]))
        for reference in record.get("nvd_references") or []:
            if isinstance(reference, dict) and isinstance(reference.get("url"), str):
                url = reference["url"]
                if url.startswith(("http://", "https://")):
                    unique_urls[url].add(_val(identifier))
    for index, (url, ids) in enumerate(sorted(unique_urls.items()), start=1):
        story.append(_p(f"[{index}] {url}  | CVE: {', '.join(sorted(ids))}", s["ref"]))
    if not unique_urls:
        story.append(_p("No se almacenaron referencias externas adicionales.", s["muted"]))

    document = SimpleDocTemplate(
        destination, pagesize=A4, leftMargin=19*mm, rightMargin=19*mm,
        topMargin=22*mm, bottomMargin=22*mm,
        title="VISOR OT - Diagnóstico de hardening", author="VISOR OT",
    )
    document.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return destination



def render_hardening_pdf(data, destination, *, legacy=False):
    """Render device-first diagnosis or explicitly preserve the previous PDF.

    Old schema-v1 JSON snapshots without a diagnosis block retain the legacy
    renderer. New snapshots use the approved hardware-centred presentation.
    The pure renderers never access the Django ORM.
    """
    if legacy or (isinstance(data, dict) and "diagnosis" not in data):
        return render_legacy_hardening_pdf(data, destination)
    from .hardening_pdf_diagnosis import render_diagnostic_hardening_pdf
    return render_diagnostic_hardening_pdf(data, destination)
