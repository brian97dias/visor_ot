
1. Analizador pasivo
* Recibe PCAP/PCAPNG.
* Invoca los disectores de protocolo.
* Produce observaciones normalizadas.

comandos para arrancar host

analizador pasivo
python -m uvicorn api:app --reload --host 127.0.0.1 --port 8001

web-app/backend 
python manage.py runserver
python manage.py run_cpe_worker

web-app/frontend
npm run dev

## Capturas grandes (cientos de miles de comunicaciones)

Antes de arrancar el **Passive Analyzer** con las rutas de importación/paginación,
instala su parser incremental en el mismo entorno virtual que ejecuta FastAPI:

```bash
cd passive_analyzer
python -m pip install -r requirements-large-pcap.txt
python -m uvicorn api:app --reload --host 127.0.0.1 --port 8001
```

Luego reinicia Django. La importación de observaciones ahora usa un flujo NDJSON
y lotes de hasta 100 filas. Los vínculos con comunicaciones se crean también en
lotes. La importación se confirma de forma atómica y se revierte si el flujo se
interrumpe o el hash del análisis cambia. Los resultados se consultan mediante
el endpoint paginado; **no abras** JSON enormes de `passive_analyzer/output/`
en el editor de código.

Comprobación:

```bash
cd web_app/backend
python manage.py test ingestion.tests_streaming network.tests_large_consolidation --settings=config.settings_test_sqlite -v 2
```

Para investigar cierres del editor o del proceso por falta de memoria en Linux:

```bash
free -h
journalctl -k -b --no-pager | grep -Ei 'out of memory|oom-kill|killed process'
```

La importación continúa siendo síncrona. Para capturas enormes, evita
depender de una solicitud larga del navegador y usa el comando de Django
(con FastAPI ya iniciado y con `ijson` instalado en su entorno):

```bash
cd web_app/backend
python manage.py import_pcap_stream <PCAP_ID> --username <USUARIO_ANALYST_O_ADMIN>
```

Reemplaza los marcadores por el ID de la captura y un usuario real. El comando
utiliza la misma importación atómica, guarda toda la evidencia y reporta los
conteos al finalizar. Después actualiza «Observaciones importadas» en el
navegador. No abras el JSON gigante en Visual Studio Code.
