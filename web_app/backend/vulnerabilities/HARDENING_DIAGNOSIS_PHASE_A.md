# VISOR OT — Fase 4 ampliada, subfase A: diagnóstico JSON

## Objetivo y alcance
La nueva unidad principal es el hardware con una evaluación vigente APPLIES.
Prioridad P1/P2/P3 = orden editorial de revisión del hardware, no CVSS nuevo,
probabilidad de explotación, riesgo calculado ni declaración de compromiso.

Esta entrega amplía el JSON, sin cambiar el PDF, la interfaz, el motor NVD
ni las reglas de integridad del inventario.

## Compatibilidad
Se mantienen schema_version = 1, todos los campos anteriores y el top de
tres comunicaciones globales del JSON previo. Se añade el bloque diagnosis,
version = 1, para el nuevo PDF. El renderizador actual seguirá utilizando
los campos anteriores hasta la subfase B.

## Contrato diagnosis
- summary: hardware total, equipos con APPLIES, pares Hardware–CVE,
  condicionados y distribución P1/P2/P3/UNCLASSIFIED.
- priority_matrix: criticidad de hardware (HIGH/MEDIUM/LOW) cruzada con mayor
  severidad CVSS aplicable (CRITICAL/HIGH/MEDIUM/LOW); cada equipo aparece
  una vez.
- prioritized_hardware: ficha única por hardware, con device_ref estable
  HW-<id>, posición, sistemas activos, identificación, instalaciones de
  software con CPE, CVE aplicables y hasta tres comunicaciones atribuibles.
- prioritized_systems: sistemas con hardware priorizado; las pertenencias
  múltiples no duplican fichas principales.
- conditional_vulnerabilities: únicamente APPLIES_CONDITIONAL, fuera del
  ranking; PENDING_REVIEW y NOT_APPLICABLE no se publican como hallazgos.
- inventory_coverage: contexto de cobertura, sin afirmar ausencia de riesgo.
- evidence_observations: prioridades no clasificables, justificaciones
  humanas breves y contexto de versión condicionada, sin cambiar veredictos.

Cada hallazgo CVE incorpora el objeto opcional cvss, con versión, vector y
métricas NVD almacenadas. Si faltan datos: null. No se inventa el vector.

## Matriz editorial aprobada

| Criticidad | CRITICAL | HIGH | MEDIUM | LOW |
| ---------- | -------- | ---- | ------ | --- |
| HIGH       | P1       | P1   | P2     | P3  |
| MEDIUM     | P1       | P2   | P2     | P3  |
| LOW        | P2       | P2   | P3     | P3  |

Orden por prioridad, mayor severidad, puntuación CVSS, número de CVE
aplicables y hardware ID. Severidad desconocida = sin prioridad inventada.

## Comunicaciones relevantes
Se reutilizan agregación SQL, ingestas ACTIVE, conteos de paquetes y la
resolución conservadora IP/MAC + ARP + asociación manual. Se estudian
candidatos relacionados con IP observadas y MAC coincidente. El resultado
presenta máximo tres firmas por hardware, ordenadas por paquetes.
Límites: lote de 30 firmas, máximo 300 candidatas, máximo 200 IPs y máximo
1000 observaciones de una firma para intentar su atribución.
Sin evidencia atribuible no significa que un dispositivo no se comunica.
Los límites aparecen explícitamente en los estados del JSON.

## Verificación en web_app/backend

    python manage.py audit_inventory_integrity
    python manage.py preview_hardening_data
    python manage.py test vulnerabilities.tests_hardening_diagnosis vulnerabilities.tests_hardening_diagnostic_network --settings=config.settings_test_sqlite
    python manage.py test vulnerabilities --settings=config.settings_test_sqlite

Inspección resumida del JSON:

    python - <<'PY'
    import json
    d=json.load(open("vulnerabilities/output/visor_ot_hardening_data.json",encoding="utf-8"))["diagnosis"]
    print(json.dumps(d["summary"],ensure_ascii=False,indent=2))
    for x in d["prioritized_hardware"]:
        print(x["device_ref"],x["hardware"]["name"],x["priority"],x["applicable_cve_count"],x["communications_evidence_status"])
    PY

Caso experimental esperado, NO codificado como constantes:
24 hardware; Siemens #10 P1, 5 CVE; Phoenix Contact #2 P2, 1 CVE;
seis parejas Hardware–CVE aplicables y un condicionado CVE-2022-30694.

## Puerta de aprobación
Revisar primero el JSON real. No comenzar subfase B ni modificar
hardening_pdf.py hasta confirmar equipos priorizados, matriz, CVSS,
evidencia de red y observaciones. Después:
B = PDF centrado en dispositivos y enlaces internos;
C = descarga autenticada desde Análisis CVE;
D = regresiones completas.

Una asociación CPE validada en el sistema puede todavía necesitar
comprobación de producto/versión. No se modifica el motor CVE para
forzar hallazgos.
