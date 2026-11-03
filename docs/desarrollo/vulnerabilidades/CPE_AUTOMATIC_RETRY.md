# VISOR OT — reanudación CPE ante fallos transitorios NVD

Incidente observado: trabajo #9, activo #4 `FW-PHX-ILPN-1.13`,
22 consultas registradas, snapshot #16 sobre
`cpe:2.3:o:phoenixcontact:il_pn*`, `FETCH_FAILED: TimeoutError`,
`checkpoint=0`, cero páginas. Las consultas anteriores se conservan.

## Diseño implementado

- El cliente NVD mantiene su política previa: dos intentos HTTP por
  consulta, temporizador inicial de 30 segundos y mínimo 7 segundos entre
  solicitudes bajo el bloqueo exclusivo PostgreSQL.
- Si una recuperación de catálogo falla por timeout, error de conexión
  o HTTP transitorio 429/500/502/503/504, se agenda una **recuperación**
  de snapshot con tres intentos adicionales; espera 30, 60 y 120 segundos.
- `CpeQuerySnapshot.automatic_retry_count` y `.retry_after` se guardan
  en PostgreSQL (migración `0012_cpe_catalogue_retry.py`).
- El snapshot permanece FAILED pero con reintento programado hasta su
  vencimiento. El trabajo de activo permanece QUEUED y WAITING_CATALOGUE;
  NO se marca FAILED durante esa espera.
- Mientras vence la espera, el worker puede continuar con otros
  trabajos, sin volver a consultar las variantes ya COMPLETED.
- Al vencer la espera, el worker usa `retry_failed_snapshot` para marcar
  el snapshot INCOMPLETE y prosigue desde `next_start_index`. Una página
  ya confirmada nunca se descarga de nuevo ni se borra de la caché.
- Tras recuperar el catálogo, el trabajo de activo continúa desde
  la consulta donde esperó, luego con el resto de su plan de búsqueda.
- Si se agotan los reintentos, el snapshot queda FAILED definitivo; el
  trabajo dependiente también terminará FAILED y conservará el rastro.
- Respuestas válidas NVD con `totalResults=0` finalizan COMPLETED con
  cero productos. Errores de paginación, duplicados, cambios de totales
  o HTTP 400 no se reintentan como fallos transitorios.
- La UI muestra la fecha de reintento y conserva el mensaje de búsqueda
  incompleta durante fallos; no interpreta un timeout como 'sin CPE'.

## Recuperar específicamente el trabajo histórico #9

Las búsquedas terminadas antes de esta mejora se mantienen FAILED por
seguridad. Existe un comando explícito, de forma predeterminada SIN
escrituras, que valida identidad vigente, estado y snapshot `FETCH_FAILED`:

```bash
cd ~/Desktop/Tesis/visor_ot/web_app/backend
source .venv/bin/activate
git switch fix/general
git pull --ff-only
python manage.py migrate
python manage.py retry_failed_cpe_search 9
```

Si confirma la identidad, que no se haya modificado el software y que
el snapshot final corresponda a un fallo recuperable:

```bash
python manage.py retry_failed_cpe_search 9 --execute
python manage.py run_cpe_worker
```

Se reactiva el MISMO trabajo, conserva las consultas completadas y
convierte el snapshot #16 en INCOMPLETE desde el checkpoint 0.
El reintento explícito inicia un presupuesto nuevo de tres intentos
automáticos, sin crear CVE ni aprobar CPE. Si el proceso del worker
estaba abierto, detenlo y reinícialo tras `git pull` y `migrate`.

Para verificar el progreso sin alterar la base de datos:

```bash
python manage.py shell -c '
from vulnerabilities.models import CpeSearchRun, CpeQuerySnapshot
r=CpeSearchRun.objects.get(pk=9)
s=CpeQuerySnapshot.objects.get(pk=16)
print('Trabajo:', r.status, 'consultas:', len(r.queries or []))
print('Snapshot:', s.status, s.error_code, 'offset:', s.next_start_index)
print('Reintentos:', s.automatic_retry_count, 'próximo:', s.retry_after)
'
```

## Regresión

```bash
python manage.py test vulnerabilities.tests_cpe_recovery \
  vulnerabilities.tests_catalogue \
  vulnerabilities.tests_software_http \
  vulnerabilities.tests_software_query_plan \
  --settings=config.settings_test_sqlite
python manage.py test vulnerabilities --settings=config.settings_test_sqlite
python manage.py makemigrations --check --dry-run
```

Desde `web_app/frontend`:

```bash
npm run test:unit
npm run lint
npm run build
```

Las pruebas verifican recuperación desde checkpoint, 3 reintentos
persistentes, no bloqueo de otros trabajos, ausencia de peticiones
repetidas sobre consultas COMPLETED, rechazo de fallos no transitorios,
reanudación explícita del trabajo histórico y conservación de la
identidad CPE sin confirmaciones automáticas. Ninguna hace llamadas NVD.

**No se ejecutaron pruebas de Django en el agente**: debes confirmarlas
en tu entorno Pop!_OS antes de considerar la recuperación validada.
