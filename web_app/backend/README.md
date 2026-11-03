# VISOR OT — Backend

API Django/DRF y persistencia PostgreSQL del inventario OT, relaciones, ingestas PCAP, clasificaciones de comunicación, CPE/CVE y generación de informes. Incluye el worker de procesamiento de consultas NVD.

## Preparación local

Desde este directorio, con PostgreSQL disponible y una base/usuario creados:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
cp .env.example .env
# Editar .env con SECRET_KEY y DB_NAME/DB_USER/DB_PASSWORD/DB_HOST/DB_PORT reales
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver 127.0.0.1:8000
```

El backend usa `PASSIVE_ANALYZER_URL`, que por defecto apunta a `http://127.0.0.1:8001`.

En **otra terminal**, usando el mismo entorno virtual y la base PostgreSQL:

```bash
python manage.py run_cpe_worker
```

Las búsquedas CPE/CVE externas son procesos encolados; el worker no sustituye la API Django ni el analizador pasivo.

## Dependencias

El archivo principal es `requirements.txt`; incluye los archivos especializados `requirements-import.txt` y `requirements-hardening-report.txt`. La configuración SQLite de test es únicamente para pruebas y no sustituye el motor PostgreSQL de la aplicación.

## Tests

```bash
python manage.py check
python manage.py test --settings=config.settings_test_sqlite
```

Los módulos `tests.py` y `tests_*.py` permanecen en cada aplicación para conservar imports y comandos históricos. Véase [la guía de pruebas](../../docs/pruebas.md).

## Precauciones

`.env` se excluye de Git; el archivo versionado `.env.example` contiene marcadores y **no credenciales reales**. La configuración actual `config/settings.py` tiene `DEBUG=True` y es de **desarrollo local**. No publicar esta API en Internet sin trabajo adicional de seguridad y despliegue.

- [README del proyecto](../../README.md)
- [Arquitectura](../../docs/arquitectura.md)
- [Guía de publicación](../../docs/seguridad-publicacion.md)
