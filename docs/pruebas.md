# Organización y ejecución de pruebas

## Criterio actual

**Se conservan los archivos de pruebas en sus directorios originales.** Django acepta módulos `tests.py` y `tests_*.py` por aplicación; también hay pruebas `tests_*.py` de FastAPI/Scapy. En el frontend los `*.test.js` están junto a las utilidades comprobadas. No es código generado para eliminar: constituye evidencia de regresión y trazabilidad.

Moverlos en bloque exigiría actualizar referencias explícitas (`assets.tests_excel_import`, `network.tests_profinet_import`, etc.) e importaciones entre fixtures. En esta preparación de entrega **no se refactorizaron rutas de test**.

## Comandos de verificación

Backend (desde `web_app/backend`, con Python del entorno virtual):

```bash
python manage.py check
python manage.py test --settings=config.settings_test_sqlite
```

Pruebas enfocadas en los módulos de observación y resultados:

```bash
python manage.py test assets ingestion network users vulnerabilities --settings=config.settings_test_sqlite
python manage.py test network.tests_profinet_import --settings=config.settings_test_sqlite
python manage.py test vulnerabilities.tests_hardening_regression --settings=config.settings_test_sqlite
```

Analizador pasivo (desde `passive_analyzer`, con Scapy y dependencias disponibles):

```bash
python -m unittest discover -s . -p 'tests_*.py' -v
```

Frontend (desde `web_app/frontend`):

```bash
npm ci
npm run test:unit
npm run lint
npm run build
```

## Qué no prueban automáticamente

- La configuración `settings_test_sqlite.py` crea una base SQLite efímera; no sustituye pruebas reales de PostgreSQL, sus bloqueos y restricciones específicas.
- Las pruebas no prueban por sí solas la explotación de CVE ni la autenticidad del tráfico PCAP.
- Tras cambios de versión o dependencias, las pruebas deben ejecutarse de nuevo **localmente** y registrarse sus resultados; esta documentación no declara un resultado «aprobado».
- Antes de la entrega, completar la validación manual de importación de PCAP, asociación MAC→activo, clasificación de comunicaciones e informe PDF.

Para la regresión específica de informes consultar [el registro de fase D](desarrollo/vulnerabilidades/HARDENING_REGRESSION_PHASE_D.md).
