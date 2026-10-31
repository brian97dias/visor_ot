# VISOR OT — Fase 4: informe PDF de diagnóstico y hardening

La fase 4 convierte el **contrato JSON `schema_version=1`** existente en un
PDF paginado. No modifica la base de datos, no llama a NVD y no inicia nuevas
evaluaciones de CVE. Los hallazgos se derivan de las evaluaciones actuales,
y las recomendaciones **no implican que una medida haya sido aplicada**.

## Preparación

Desde `web_app/backend` con el entorno virtual activo:

```bash
python -m pip install -r requirements-hardening-report.txt
python manage.py audit_inventory_integrity
```

## Generar desde la base de datos vigente

```bash
python manage.py generate_hardening_pdf
```

Se guardará en
`web_app/backend/vulnerabilities/output/visor_ot_hardening_report.pdf`
(la carpeta `output/` ya está ignorada por Git).

Para escribir en otro archivo:

```bash
python manage.py generate_hardening_pdf --output /ruta/informe_ot.pdf
```

## Reproducir exactamente un corte JSON previo

```bash
python manage.py preview_hardening_data
python manage.py generate_hardening_pdf \
    --input-json vulnerabilities/output/visor_ot_hardening_data.json
```

La opción `--input-json` evita una nueva consulta a PostgreSQL. El PDF se
crea **a partir de ese archivo**, de modo que no cambia el corte de datos
aunque se haya modificado posteriormente el inventario. En cambio, sin esta
opción, el comando consulta el estado vigente al ejecutarse.

El generador guarda el resultado de manera atómica (archivo temporal en el
directorio destino y sustitución al concluir), evitando truncar un PDF previo
si falla el renderizado. El servicio puro es
`vulnerabilities.services.hardening_pdf.render_hardening_pdf(data, destination)`.

## Contenido

1. Portada: sistema, alcance y fecha de corte.
2. Resumen ejecutivo: cifras provenientes del contrato.
3. Alcance y metodología: fuentes, filtro de ingestas y límites.
4. Sistemas OT: contexto y criticidad registrada.
5. Inventario: hardware, software, interfaces y CPE confirmados vigentes.
6. Comunicaciones: tres firmas de mayor cantidad de paquetes observados.
7. Vulnerabilidades: exclusivamente parejas Hardware–CVE `APPLIES`.
8. Hardening: recomendaciones **sujetas a revisión y aprobación OT**, ligadas
   a CVE y flujos clasificados como no autorizados.
9. Conclusiones y apéndice A: limitaciones y CVE `APPLIES_CONDITIONAL`.
10. Referencias: enlaces NVD por CVE y URLs técnicas de la base local.

Los títulos impresos conservan la numeración acordada (1–8, Apéndice A y
Referencias). No se confunden `APPLIES_CONDITIONAL` con `APPLIES`, ni la
clasificación manual de una comunicación con un incidente detectado.

La información fuente puede ser incompleta o incorrecta, incluso cuando
una asociación CPE haya sido confirmada. El PDF la reproduce sin
modificarla: **deben validarse manualmente fabricante, producto, versión y
compatibilidad real antes de decidir mitigaciones**. Para entornos OT, las
actualizaciones o filtros requieren ventana de mantenimiento y valoración
de consecuencias físicas.

## Pruebas

```bash
python manage.py test vulnerabilities.tests_hardening_pdf \
    --settings=config.settings_test_sqlite

python manage.py test vulnerabilities.tests_hardening_report_data \
    --settings=config.settings_test_sqlite

python manage.py test vulnerabilities --settings=config.settings_test_sqlite
```

Revisar el PDF resultante en un lector real: texto extenso, tablas,
paginación, referencias y congruencia con el contrato JSON.

## Alcance de este incremento

No incorpora botón React, endpoint HTTP, gestión de trabajos ni permisos
de descarga. Esa integración pertenece a la fase 5.
