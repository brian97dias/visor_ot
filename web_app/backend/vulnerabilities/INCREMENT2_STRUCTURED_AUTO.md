# VISOR OT — Incremento 2: búsqueda automática estructurada

## Alcance

Solo se modifica la ejecución automática de descubrimiento CPE. La búsqueda
avanzada manual continúa permitiendo keywordSearch y cpeMatchString; tampoco
se modifican vistas React, modelos, migraciones ni decisiones AssetCpe.

El generador probado en Incremento 1 (build_cpe_match_plan) alimenta ahora
execute_run. El plan es SPECIFIC → FAMILY → MANUFACTURER y todas sus consultas
utilizan cpeMatchString. Si se recibe una coincidencia is_pertinent() después
de examinar la consulta completa, se detiene la ampliación. RELATED nunca
es tratado como específico ni confirmado.

### Vista previa por modelo/familia

Se permiten como máximo 3 páginas por consulta y 40 páginas totales antes de
llegar al fabricante. Estos son límites operativos, no pruebas de ausencia.
Si NVD anuncia más páginas que las procesadas, la consulta queda PARTIAL,
result_truncated=True y NO se continúa a búsquedas más generales. Las
consultas ya completadas, sus parámetros, motivos, páginas y candidatos
quedan en CpeSearchRun. La consulta NVD fallida deja FAILED.

### Catálogo completo por fabricante

En MANUFACTURER se llama enqueue_catalogue_query() para el cpeMatchString
fabricante + *. Esto reutiliza la caché durante siete días o crea un nuevo
CpeQuerySnapshot. Si se está recuperando, el CpeSearchRun vuelve a QUEUED
con una consulta WAITING_CATALOGUE y snapshot_id. El worker único prioriza
la recuperación compartida, respetando pacing/locking. Al reanudar,
execute_run salta consultas completadas y procesa los CpeQueryProduct originales
por lotes de 500. **Nunca examina solo las primeras páginas como si fueran
un catálogo completo.** Si falla la recuperación, el run deja FAILED con
el error del snapshot y no certifica ausencia de CPE.

El catálogo preserva todos los CPE encontrados. Los candidatos sugeridos
siguen limitados a MAX_TOTAL_CANDIDATES=250 y filtran hardware
relacionado por fabricante/modelo. Si se supera ese límite, result_truncated
queda True sin afectar la completitud del snapshot NVD.

### Compatibilidad

El ejecutor anterior permanece explícito como execute_legacy_run, utilizado
en las regresiones de búsquedas históricas. Los trabajos ADVANCED siguen
usando execute_advanced_run con sus políticas originales.

### Pruebas automatizadas

tests_auto_engine.py incluye ocho pruebas simuladas (sin red):

- Siemens CPU 1215C: SPECIFIC y parada anticipada sin keywordSearch.
- Advantech ADAM-5000 Series: RELATED y espera/reanudación de snapshot.
- Caché: reutilización por dos activos distintos.
- Paginación parcial: nunca extrapola ausencia ni amplía sin completar.
- Rockwell: alias y prefijo 1783 sin identificación falsa.
- Snapshot FAILED: evidencia preservada y error visible.
- Timeout: no continuar la exploración sobre una página fallida.
- Worker: una búsqueda QUEUED que espera snapshot no bloquea al recuperador.

Las 166 pruebas previas siguen presentes; el total esperado es **174 tests**.

Desde web_app/backend:

    python manage.py check
    python manage.py makemigrations --check --dry-run
    python manage.py test vulnerabilities --settings=config.settings_test_sqlite

El worker productivo sigue requiriendo PostgreSQL:

    python manage.py run_cpe_worker

Nota: con --once el worker procesa un único trabajo por invocación. Si la
búsqueda deja un snapshot en cola, inicia el worker en modo continuo para
permitir su recuperación y la reanudación de la búsqueda solicitante.

No se han consultado servicios NVD reales automáticamente durante las pruebas.
