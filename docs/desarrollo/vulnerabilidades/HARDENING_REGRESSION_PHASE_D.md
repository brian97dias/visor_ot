# VISOR OT — Subfase D: regresión final de hardening

El objetivo es probar que exportar el PDF desde Análisis CVE no altera el
inventario OT, las capturas/observaciones, la clasificación de red, los
CPE, el catálogo CVE ni los veredictos existentes.

## Nuevas pruebas reales (sin falsificar el recopilador)

Archivo: vulnerabilities/tests_hardening_regression.py (5 tests).
Se crea un controlador Siemens con firmware/CPE confirmado, CVSS 3.1
con descripción española almacenada y capturas activas/excluidas.
Se recorre HTTP POST -> recolector real -> agregación SQL -> PDF real.
Las pruebas validan:

- Ingestas excluidas no inflan paquetes ni aparecen en el informe.
- La pareja hardware–CVE aplicable coincide con la evidencia vigente.
- Cambiar la versión del firmware no resucita un hallazgo obsoleto.
- Inventario incompleto: HTTP 400 JSON y ningún PDF servido.
- Descargas consecutivas no crean registros ni modifican ninguna fila.
- Los clientes NVD no reciben solicitudes externas durante la exportación.

Para detectar modificaciones silenciosas se comparan las filas completas
de los modelos de inventario, red, CPE/CVE y su historial, no solo conteos.

Archivo: frontend/src/utils/hardeningReportDownload.test.js.
También comprueba el tratamiento de respuestas PDF válidas, HTML,
cuerpos vacíos, bytes sin firma %PDF-, errores HTTP y nombres seguros.
El parser compartido parseHardeningPdfResponse() valida los bytes
sin modificar el flujo JWT ni la pantalla React.

## Comandos

En web_app/backend con el venv activo:

```bash
git pull --ff-only
python manage.py test vulnerabilities.tests_hardening_regression vulnerabilities.tests_hardening_report_http --settings=config.settings_test_sqlite
python manage.py test vulnerabilities --settings=config.settings_test_sqlite
python manage.py test network ingestion assets users --settings=config.settings_test_sqlite
python manage.py test --settings=config.settings_test_sqlite
```

En web_app/frontend:

```bash
npm run test:unit
npm run lint
npm run build
```

## Lista de verificación manual

1. ADMIN/ANALYST accede a Análisis CVE y genera el PDF con el botón.
2. El archivo se descarga, se abre y muestra el usuario real en portada.
3. Cifras y P1/P2/P3 concuerdan con el corte de datos actual.
4. Las parejas CVE aplicables solo aparecen en sus hardware; casos
   condicionados se mantienen fuera de la matriz y en el apéndice.
5. Se muestran fechas, etiquetas CVSS españolas y descripción en español
   únicamente cuando estaba almacenada en la fuente NVD.
6. Las IP sin atribución siguen como IP; identidades confirmadas enlazan
   a las fichas. Ingestas excluidas no se cuentan.
7. Volver al inventario, comunicaciones y CVE: la descarga no cambió estados.
8. OPERATOR no ve el botón y el backend deniega solicitudes directas (403).
9. Una prueba aislada con inventario incompleto produce error, nunca PDF.

## Puerta de cierre

Fase D permanece pendiente hasta ejecutar las pruebas de Django,
test:unit/lint/build de frontend y completar la verificación manual.
No hay migraciones, endpoints nuevos ni cambios a evaluadores CVE en D.
El renderer anterior --legacy se conserva para comparaciones.
