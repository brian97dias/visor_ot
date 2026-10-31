# VISOR OT — Informe de hardening (fase 4 ampliada, subfase B)

## Propósito del PDF

El informe responde a la pregunta: **¿qué hardware OT tiene evaluaciones
Hardware–CVE vigentes APPLIES, qué equipos requieren revisión primero y qué
evidencia técnica sustenta esos hallazgos?**

Los datos llegan desde `collect_hardening_report_data()` y su proyección
aditiva `diagnosis.version=1`. El renderizador de ReportLab es **puro**:
no accede al ORM, no llama a NVD, no reevalúa CVE y no cambia inventarios.

## Dependencia

Desde `web_app/backend`:

```bash
python -m pip install -r requirements-hardening-report.txt
```

## Generar el diagnóstico actual

```bash
python manage.py audit_inventory_integrity
python manage.py generate_hardening_pdf
```

Destino predeterminado:
`vulnerabilities/output/visor_ot_hardening_report.pdf`.

El nuevo PDF es el formato predeterminado cuando el JSON contiene
`diagnosis.version=1`. El documento se organiza así:

1. Portada.
2. Resumen ejecutivo con alcance, equipos priorizados y P1/P2/P3.
3. Matriz de priorización navegable, con números clicables por hardware.
4. Tabla compacta de dispositivos con enlaces a sus fichas.
5. Fichas agrupadas por sistema, sin duplicar hardware multisistema: identidad,
   software instalado, IP/MAC declaradas, CPE confirmados, comunicaciones
   atribuibles, CVE APPLIES, CVSS 3.1/otras versiones según NVD y evidencias
   automáticas o del analista.
6. Apéndice A: únicamente APPLIES_CONDITIONAL.
7. Apéndice B: cobertura del inventario completo, sin convertir equipos sin
   hallazgos en equipos libres de vulnerabilidades.
8. Apéndice C: observaciones sobre suficiencia de evidencia, sin modificar
   decisiones.
9. Metodología, limitaciones, orientación general y referencias deduplicadas.

El vector y las métricas CVSS se reproducen desde NVD local, sin convertir
sus valores en evidencia de una ruta real de ataque o vulnerabilidad
explotada. Las recomendaciones no prescriben parches específicos ni afirman
que se implementaron mitigaciones.

## Comparar con el PDF anterior usando exactamente el mismo corte

```bash
python manage.py preview_hardening_data
python manage.py generate_hardening_pdf \
  --input-json vulnerabilities/output/visor_ot_hardening_data.json \
  --output vulnerabilities/output/diagnostico_dispositivos.pdf

python manage.py generate_hardening_pdf \
  --input-json vulnerabilities/output/visor_ot_hardening_data.json \
  --legacy \
  --output vulnerabilities/output/informe_inventario_anterior.pdf
```

`--legacy` ejecuta el renderizador anterior, sin perder información ni
modificar el JSON. Los cortes JSON v1 antiguos **sin diagnosis** se siguen
renderizando con el formato anterior por compatibilidad. Si un corte contiene
`diagnosis` pero esta está incompleta o tiene versión incorrecta, el PDF
nuevo falla explícitamente en lugar de inventar o degradar información.

La escritura sigue siendo atómica (archivo temporal seguido de sustitución):
los PDF existentes no se truncan si falla la generación.

## Validación

```bash
python manage.py test \
  vulnerabilities.tests_hardening_pdf \
  vulnerabilities.tests_hardening_pdf_diagnosis \
  --settings=config.settings_test_sqlite

python manage.py test vulnerabilities \
  --settings=config.settings_test_sqlite
```

Revisar el PDF en un lector: números en la matriz y en el listado
deben conducir a cada ficha. Revisar separaciones de páginas,
tablas, descripciones extensas, controles de legitimidad de las
referencias y congruencia con `diagnosis`.

**Puerta B → C:** no se añade todavía API, botón React ni descarga:
primero se revisa visualmente el documento generado con datos reales.

## Revisión de legibilidad en español (fase B)

- El PDF orientado a dispositivos muestra la criticidad y la severidad CVSS
  en español (Crítica/Alta/Media/Baja), sin alterar las métricas NVD.
- Los hallazgos exportan `description_es` solo cuando `Cve.descriptions`
  contiene una descripción `es` realmente almacenada. Si no existe, el
  informe conserva la descripción original en inglés. **No traduce en línea**.
- Publicación, última modificación y fecha de recuperación NVD se muestran
  por separado en cada CVE. Las condiciones del vector CVSS se acompañan
  de etiquetas y lectura orientativa en español, sin afirmar rutas de ataque
  verificadas ni incidentes.
- Las comunicaciones presentan IP de origen e IP de destino, más el nombre
  de hardware en la misma celda solo cuando existe atribución confirmada.
  Los nombres enlazan a fichas del PDF si esos equipos fueron priorizados.
  Se eliminan los estados internos `UNKNOWN/IDENTIFIED/ATTRIBUTED`
  redundantes.
- El resumen ejecutivo muestra únicamente P1/P2/P3. Si faltan datos
  para la matriz, la situación se describe aparte como pendiente, sin
  asignar una nueva prioridad ni eliminar el hallazgo.
- El responsable debe identificarse en CLI explícitamente, ya que un
  comando Django no conoce el usuario web autenticado:

```bash
python manage.py preview_hardening_data
python manage.py generate_hardening_pdf \
  --input-json vulnerabilities/output/visor_ot_hardening_data.json \
  --author "Nombre del responsable" \
  --output vulnerabilities/output/diagnostico_dispositivos.pdf
```

Cuando `--author` no se proporciona, la portada indica
"No indicado (generación desde consola)". El informe lleva una fecha
de corte y aclara que la evidencia de PCAP puede corresponder a fechas
históricas distintas de la generación. La API web, prevista para una
fase posterior, deberá proporcionar el autor desde el usuario autenticado.

El argumento `--legacy` conserva el formato anterior; no incorpora
la nueva maquetación ni las opciones visuales de autor.

Pruebas específicas:

```bash
python manage.py test \
  vulnerabilities.tests_hardening_pdf_diagnosis \
  vulnerabilities.tests_hardening_report_data \
  --settings=config.settings_test_sqlite
```
