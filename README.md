# VISOR OT

**Prototipo académico de visibilidad, inventario y contextualización de activos de tecnología operativa (OT).**

VISOR OT relaciona sistemas industriales, hardware, software y firmware, interfaces de red, comunicaciones observadas en capturas PCAP/PCAPNG y referencias públicas CPE/CVE de NVD. Permite revisar la aplicabilidad de vulnerabilidades y generar un diagnóstico orientativo de exposición. Su escenario reproducible de validación utiliza **datos sintéticos** de dos procesos: *Sistema de preparación y mezcla* y *Sistema de transferencia y envasado*.

> **Alcance:** prototipo de laboratorio para evaluación académica. No realiza un escaneo activo de una planta, no demuestra explotación ni certifica seguridad, cumplimiento o ausencia de vulnerabilidades. La criticidad y la autorización de comunicaciones requieren contextualización y decisiones del analista.

## Componentes

| Directorio | Responsabilidad |
| --- | --- |
| `passive_analyzer/` | API FastAPI (puerto 8001): analiza capturas Ethernet, ARP, IPv4, TCP/UDP y tramas PROFINET RT representativas; produce observaciones estructuradas. |
| `web_app/backend/` | API Django/DRF (puerto 8000): inventario, sistemas OT, ingesta, asociaciones, comunicaciones, CPE/CVE, evaluaciones e informes PDF. |
| `web_app/frontend/` | Interfaz React/Vite para gestión del inventario, revisión de evidencia y generación de informes. |
| `visor_ot_simulacion_pcap/` | Generador offline reproducible de dos capturas PCAP y tablas TSV de referencia. |
| `docs/` | Instalación, evaluación, pruebas, seguridad de publicación y documentación de desarrollo histórica. |

**Procesos de la aplicación:** analizador FastAPI, servidor Django, worker de consultas NVD y frontend Vite. PostgreSQL debe estar disponible de forma independiente. El generador PCAP es una herramienta bajo demanda, no otro servicio residente.

## Inicio rápido en entorno local

Requisitos: Python 3 compatible con Django 5.2, Node.js compatible con Vite 8, npm y PostgreSQL. Se recomiendan entornos virtuales Python **independientes** para el analizador y el backend.

**1. Analizador pasivo**

```bash
cd passive_analyzer
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m uvicorn api:app --reload --host 127.0.0.1 --port 8001
```

**2. Backend Django** (en otra terminal)

Crear previamente una base PostgreSQL y un usuario con permisos apropiados; copiar `web_app/backend/.env.example` a `web_app/backend/.env` y configurar las credenciales locales.

```bash
cd web_app/backend
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver 127.0.0.1:8000
```

**3. Worker de CPE/CVE** (tercera terminal, con el entorno del backend activado)

```bash
cd web_app/backend
source .venv/bin/activate
python manage.py run_cpe_worker
```

**4. Frontend** (cuarta terminal)

Copiar `web_app/frontend/.env.example` a `web_app/frontend/.env.local`.

```bash
cd web_app/frontend
npm ci
npm run dev
```

Interfaz local predeterminada: **http://localhost:5173**. Todas las instrucciones anteriores son para **desarrollo local**, no para despliegue público; la configuración Django contiene `DEBUG=True`.

## Reproducir la demostración de laboratorio

El generador no envía paquetes a la red y usa únicamente la biblioteca estándar de Python.

```bash
cd visor_ot_simulacion_pcap
python3 generar_pcaps_visor_ot.py --output ../passive_analyzer/pcaps/demo
```

Se generan dos capturas: operación normal (día 1) y operación con flujos adicionales (día 2). Para observarlas, iniciar FastAPI, entrar en **Análisis pasivo**, analizarlas e importar la evidencia desde la aplicación. Vincular manualmente las interfaces a los activos siguiendo la tabla `visor_ot_asociaciones_interfaces.tsv`; clasificar comunicaciones con la política propuesta en `visor_ot_baseline_comunicaciones.tsv`. **El PCAP por sí solo no determina si una comunicación está autorizada.**

El inventario de referencia es `datos_sinteticos.xlsx`. Antes de usarlo para una importación masiva, revisar registros repetidos y las asociaciones ya existentes; las instalaciones de software y relaciones con sistemas no se infieren automáticamente del Excel.

- [Guía de simulación](visor_ot_simulacion_pcap/README.md)
- [Alcance y arquitectura](docs/arquitectura.md)
- [Pruebas](docs/pruebas.md)
- [Documentación y antecedentes](docs/README.md)
- [Precauciones de publicación](docs/seguridad-publicacion.md)

## Verificación

```bash
# En web_app/backend, con su entorno activado
python manage.py check
python manage.py test --settings=config.settings_test_sqlite

# En web_app/frontend, tras npm ci
npm run test:unit
npm run lint
npm run build

# En passive_analyzer, con su entorno activado
python -m unittest discover -s . -p 'tests_*.py' -v
```

Estas son instrucciones de verificación, **no una afirmación de que toda la suite haya sido ejecutada en el equipo del autor**. Las pruebas SQLite no sustituyen las validaciones que requieren PostgreSQL (por ejemplo, bloqueos del worker).

## Nota sobre los resultados generados

Los JSON de `passive_analyzer/output/` y los informes locales son artefactos derivados, no código fuente. Las capturas históricas y los ejemplos sintéticos no deben interpretarse como actividad observada en una instalación industrial de producción.

**Estado de entrega:** la rama funcional revisada es `fix/general`. La rama predeterminada del repositorio podría seguir siendo `main`; antes de compartir la URL general, verificar que el evaluador vea el código final. No asumir que GitHub Actions equivale a un despliegue.
