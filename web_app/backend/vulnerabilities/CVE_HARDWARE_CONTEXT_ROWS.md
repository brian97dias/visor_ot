# Análisis CVE — filas por dispositivo evaluado

## Decisión de producto

El identificador CVE sigue siendo **único** en el catálogo oficial de NVD.
Una misma vulnerabilidad puede afectar a varios dispositivos del inventario;
cada evaluación es independiente por la clave **(CVE, hardware)**, aunque dos
equipos compartan fabricante, modelo, firmware e incluso instalación de la
misma variante de software.

El endpoint `GET /api/vulnerabilities/cves/` expande cada CVE a tantas filas
como dispositivos relacionados correspondan, antes de filtrar por estado y
paginar. Si hay un CVE almacenado sin ningún hardware asociado, permanece una
fila informativa sin evaluación (hardware_id=null, PENDING_REVIEW), para que
los registros NVD oficiales no desaparezcan silenciosamente.

La respuesta por fila incluye `hardware_id`, `row_key` estable,
`related_assets` limitado al hardware de esa fila, y su
`applicability_status` / `applicability_source` individual. El filtro libre
por nombre de dispositivo o por software evaluado se aplica también por
hardware: nunca devuelve otro PLC únicamente porque comparte el mismo CVE.

**Vista general:** `summary.total` mantiene el número de identificadores CVE
distintos (contrato anterior), y `evaluation_summary` presenta conteos por
pareja hardware-CVE. Los contadores de validaciones de React usan
`evaluation_summary`; no se deben sumar como si fueran CVE oficiales
distintos. La página muestra `catalogue.count` como número de filas de
evaluación y las pagina por `row_key`, no por CVE.

El botón `Ver` abre `/vulnerabilities/cve/<CVE>?hardware=<ID>`, fijando el
dispositivo evaluado de esa fila. El detalle de CVE conserva el historial
aislado por hardware; otros PLC no heredan veredictos ni justificaciones.

## Ejemplo de salida

| CVE | Hardware | Software evaluado | Aplicabilidad |
| --- | --- | --- | --- |
| CVE-2021-42029 | PLC-MEZ-01 | Según evidencia del equipo | No aplica (analista) |
| CVE-2021-42029 | PLC-TRA-01 | Según evidencia del equipo | Por validar |

Cuando una coincidencia NVD está probada para TRA, su segunda fila podría
mostrar «Aplica», sin modificar la decisión previa de MEZ.

## Informe de diagnóstico

La generación del PDF NO cambia. Ya utiliza
`applicable_vulnerabilities` como registros `(cve_id, hardware_id)`,
agrupa el diagnóstico por hardware, busca las justificaciones vigentes en
`_current_justifications()` con la misma clave, y muestra «Justificación
del analista» en el apartado de cada dispositivo. Si dos PLC comparten CVE
y tienen justificaciones de aplicabilidad distintas, ambas se conservan
por separado; una fila CVE en React no es una fila extra en el modelo.

**Límite vigente del PDF:** es un diagnóstico de CVE aplicables y
condicionados. Una conclusión `NOT_APPLICABLE` o `PENDING_REVIEW` no se
presenta como vulnerabilidad aplicable ni se incluye por defecto en los
hallazgos priorizados. El historial completo de esas decisiones sigue en
la pantalla de evaluación de cada hardware. Cambiar ese alcance del PDF
sería una decisión funcional independiente, no parte de esta corrección.

## Pruebas

```bash
python manage.py test \
  vulnerabilities.tests_cve_catalogue_context_rows \
  vulnerabilities.tests_cve_catalogue_http \
  vulnerabilities.tests_cve_catalogue_status \
  vulnerabilities.tests_hardening_report_data \
  vulnerabilities.tests_hardening_pdf_diagnosis \
  --settings=config.settings_test_sqlite

python manage.py test vulnerabilities --settings=config.settings_test_sqlite
```

Desde `web_app/frontend`:
```bash
npm run test:unit
npm run lint
npm run build
```

Los tests adicionales cubren el mismo CVE con dos PLC de estados
independientes (no aplica/pendiente y no aplica/aplica), búsqueda por
hardware y firmware evaluado, filtros por estado, paginación y enlaces
inequívocos, la conservación de la unicidad técnica de variantes de
software y la separación de justificaciones en el contrato y renderer PDF.

No requiere migraciones ni reimportar CVE/activos; no registra nuevas
decisiones, y no realiza llamadas NVD.
