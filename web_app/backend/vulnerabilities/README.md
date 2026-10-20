# VISOR OT — Módulo de identificación CPE

**Rama:** `feature/vulnerability`  
**Fase 2:** catálogo CPE, asociaciones y decisiones auditadas implementadas. El caché, CVE y búsqueda de software siguen pendientes.

## Alcance aprobado

El módulo descubre candidatos CPE oficiales desde NVD, los compara con el inventario de activos y permite que un analista los confirme o rechace. **No** consulta CVE, evalúa vulnerabilidades, calcula riesgo ni genera recomendaciones de hardening en este incremento.

Responsabilidades: `assets` conserva `Asset`, `Hardware`, `Software` y `SoftwareInstallation`; `vulnerabilities` conserva ejecuciones de búsqueda, CPE de NVD, asociaciones y decisiones de revisión. Se reutilizarán los servicios existentes de inventario, sin duplicar activos.

## Modelo de datos propuesto (antes de migrar)

`CpeSearchRun` pertenece a `0001_initial`; `Cpe`, `AssetCpe` y `AssetCpeDecision` se crean en `0002_cpe_validation`. El caché de fase 3 sigue pendiente.

### Fase 1 — `CpeSearchRun`

Una ejecución de descubrimiento ligada a `assets.Asset` (`ForeignKey`, `PROTECT`).

| Campo lógico | Propósito |
| --- | --- |
| `id`, `asset`, `requested_by` | Referencia a la ejecución, activo y usuario |
| `status` | `QUEUED`, `RUNNING`, `COMPLETED`, `FAILED` |
| `scope`, `trigger` | `SPECIFIC`/`BROAD` y `MANUAL`/`AUTO`/`REFRESH` |
| `identity_snapshot` | Identidad técnica **en el instante de inicio** (JSON normalizado, sin editar el inventario) |
| `identity_fingerprint` | SHA-256 de los campos técnicos pertinentes; permite detectar resultados obsoletos |
| `queries` | Estrategia (`keywordSearch` o `cpeMatchString`), parámetros, estado, páginas y procedencia (JSON normalizado) |
| `candidates` | CPE obtenidos en esta ejecución: `cpeNameId`, `cpeName`, `title`, `deprecated`, `methods`, clasificación explicable (JSON normalizado) |
| `result_truncated`, `error_message` | Paginación incompleta o fallo documentado |
| `created_at`, `started_at`, `finished_at` | Tiempos del trabajo y auditoría |

**Separación importante:** una fila de `CpeSearchRun` y sus candidatos no constituyen una asociación CPE–Activo confirmada. No se persistirá el JSON original completo de NVD. Los resultados se marcarán como *desactualizados* cuando su huella técnica difiera de la identidad del activo.

### Fase 2 — `Cpe` y `AssetCpe`

`Cpe` es el catálogo local compartido por activos; la clave externa de identidad será `cpe_name_id` (UUID oficial único de NVD), además de `cpe_name`, `title`, `deprecated`, `created` y `last_modified` de NVD. Registrar también la fecha de última recuperación.

`AssetCpe` materializa la relación N:M entre `Asset` y `Cpe`. Contendrá `asset`, `cpe`, `validation_status` (`PENDING` histórico, `CONFIRMED`, `REJECTED`, `REOPENED`), `justification`, `validated_at`, `validated_by` y `validated_identity_fingerprint`. Restricción única para el par (`asset`, `cpe`). **Sin `is_primary`.**

Los candidatos automáticos permanecerán en `CpeSearchRun`; solo la acción de un usuario creará o modificará `AssetCpe`, mientras el estado `PENDING` solo se conserva para decisiones históricas. Para conservar decisiones previas se implementó `AssetCpeDecision`, con estado previo/nuevo, justificación, actor, búsqueda de origen, fecha y huella de identidad. No hay endpoints para editar o borrar estas evidencias.

Las asociaciones confirmadas no se eliminan tras cambiar fabricante, modelo, CPU, producto o versión. Una comparación con `validated_identity_fingerprint` deberá indicarlas como **requieren revisión**.

### Fase 3 — `CpeQueryCache`

Una entrada por consulta individual equivalente (`strategy`, parámetros normalizados, llave/hash, `candidates` normalizados, `fetched_at`, `expires_at`), compartida entre activos. Duración configurable; una actualización forzada invalida/reconsulta. No guardar el JSON bruto de NVD. Se revisará el esquema exacto al comenzar esta fase para evitar tablas redundantes.

## Contrato HTTP propuesto

Los endpoints de las fases 1 y 2 están implementados. Los de fases 3 a 5 siguen siendo propuestas. Todos requieren autenticación y permisos específicos por rol.

| Fase | Método y endpoint | Resultado |
| --- | --- | --- |
| 1 | `POST /api/vulnerabilities/assets/{asset_id}/cpe-searches/` | Encola una búsqueda (HTTP 202, `run_id`, `status: QUEUED`); `scope: SPECIFIC` por defecto o `BROAD` bajo acción explícita |
| 1 | `GET /api/vulnerabilities/assets/{asset_id}/cpe-searches/latest/` | Última búsqueda o 404 si no existe |
| 1 | `GET /api/vulnerabilities/assets/{asset_id}/cpe-searches/{run_id}/` | Estado, identidad consultada, consultas, candidatos, procedencia, truncamiento y error |
| 2 | `GET /api/vulnerabilities/assets/{asset_id}/cpes/` | Asociaciones registradas y su estado |
| 2 | `POST /api/vulnerabilities/assets/{asset_id}/cpes/` | Crea decisión para `cpe_name_id` con estado y justificación |
| 2 | `PATCH /api/vulnerabilities/assets/{asset_id}/cpes/{association_id}/` | Revisa una decisión con trazabilidad |
| 5 | Endpoint de exportación JSON (por definir) | Resultados normalizados y evidencia de laboratorio |

El `GET` de búsqueda deberá devolver `identity_is_current` (comparación de huella actual vs. snapshot). `COMPLETED` con `candidates: []` significa **sin resultados en las consultas ejecutadas**, no inexistencia de CPE. Si la paginación se acota, indicar `result_truncated`.

### Autorización propuesta

- Lectura: usuarios autenticados `ADMIN`, `ANALYST` y `OPERATOR`.
- Solicitar búsquedas y confirmar/rechazar CPE: `ADMIN` y `ANALYST` (no modifica el inventario).
- Descubrimiento automático: desencadenado por acciones válidas del dominio `assets`, independientemente del rol que creó el activo.

Confirmar las reglas finales al implementar los endpoints; nunca confiar en permisos definidos únicamente en React.

## Servicio NVD y trabajos — decisiones técnicas

- Endpoint único de esta funcionalidad: `https://services.nvd.nist.gov/rest/json/cpes/2.0`.
- Estrategias: `keywordSearch` y `cpeMatchString`. La segunda es **una consulta estructurada**, no una identidad oficial que debamos almacenar como si existiera.
- Normalizar solo para la búsqueda (espacios, guiones, guiones bajos, términos repetidos, denominaciones Siemens). Mantener intacto el dato original del inventario. `CPU 1215C` conocida prioriza búsqueda específica; ausencia de CPU amplía por familia.
- Un resultado oficial se identifica y deduplica por `cpeNameId`, conservando los métodos que lo recuperaron. Clasificar coincidencia específica, de familia, requiere información o posible incompatibilidad; **sin porcentajes arbitrarios**.
- `resultsPerPage`, `startIndex` y `totalResults` controlan la paginación; indicar truncamiento si una búsqueda debe detenerse antes de agotar resultados. Diferenciar fallos de consulta de resultados vacíos.
- El endpoint HTTP **solo encola** el trabajo. Primera alternativa de despliegue: un proceso independiente `python manage.py run_cpe_worker` que procesa las ejecuciones persistidas; **nunca** lanzar hilos efímeros por petición ni realizar llamadas a NVD dentro de una transacción HTTP.
- Como despliegue local inicial, habrá un trabajador efectivo a la vez, protegido mediante un *advisory lock* de PostgreSQL. La fase 1 debe implementar pausas conservadoras (al menos siete segundos entre solicitudes, incluyendo páginas y reintentos) y precaución de 30 segundos al reiniciar, para cumplir el límite público de cinco solicitudes cada treinta segundos aun sin API key.
- Futuros reintentos ante 429/5xx deberán respetar `Retry-After` cuando exista y usar espera acotada; registrar errores recuperables, estado y fecha. Las consultas HTTP tendrán timeout.
- Desde la fase 3, añadir caché con caducidad configurable, actualización voluntaria y descubrimiento automático tras confirmarse las transacciones de `assets` (usar `transaction.on_commit`, no duplicar búsquedas dentro de transacciones que luego revierten).
- Preparar configuración para posible API key futura **sin activarla todavía**.

## Interfaz y validación incremental

En fase 1, mostrar en `AssetDetail.jsx` una sección *Identificación CPE* y una vista dedicada de candidatos. Título oficial como texto principal, CPE técnico secundario, método de hallazgo, explicación de correspondencia, deprecación y advertencias sobre identidad obsoleta. Permitir ampliar manualmente la búsqueda cuando sea demasiado específica. En fase 2, añadir las decisiones del analista.

**Verificaciones por fase:**
1. Fase 0: `python manage.py check` y `python manage.py test vulnerabilities --settings=config.settings_test_sqlite`; no hay migraciones nuevas.
2. Fase 1: desde React, el Siemens SIMATIC S7-1200 CPU 1215C obtiene candidatos reales de NVD; comprobar cola, paginación, límites y estados.
3. Fase 2: relación N:M, confirmación/rechazo, auditoría y no duplicación.
4. Fase 3: reutilización de consultas, refresco, búsqueda automática y resultados obsoletos identificados.
5. Fase 4: firmware Siemens sin/con versión y con/sin contexto de hardware.
6. Fase 5: exportación y pruebas de regresión completas.

**Pendientes de las próximas fases:** caché y búsquedas automáticas (fase 3), software (fase 4) y exportación (fase 5). La migración de fase 2 ya incorpora las decisiones auditadas.


## Fase 1 — Primer descubrimiento funcional de hardware

**Disponible en `feature/vulnerability`:** búsqueda manual para activos `HARDWARE`, colas persistidas y dos estrategias `keywordSearch`/`cpeMatchString`, con candidatos deduplicados, correspondencia explicable y paginación limitada.

### Cómo ejecutar (tres terminales)

Desde `web_app/backend` con el virtualenv activado y PostgreSQL disponible:

```bash
python manage.py migrate
python manage.py check
python manage.py test vulnerabilities --settings=config.settings_test_sqlite
python manage.py runserver
```

Abre **otra terminal**, también en `web_app/backend`, y ejecuta:

```bash
python manage.py run_cpe_worker
```

Deja este proceso abierto durante las búsquedas. El worker requiere PostgreSQL y rechaza una segunda instancia. **Es intencional** que espere hasta 30 segundos antes de la primera petición NVD y un mínimo de siete segundos entre peticiones (incluidas páginas y reintentos). La cola continúa almacenada aunque cierres React.

Desde `web_app/frontend`:

```bash
npm run build
npm run dev
```

Abre un hardware Siemens con `manufacturer=Siemens`, `model=SIMATIC S7-1200`, `cpu_model=1215C`. En su detalle, entra a **Identificación CPE** y usa **Buscar candidatos**. El estado debe cambiar `QUEUED → RUNNING → COMPLETED`. Los resultados proceden de NVD; los tests usan respuestas simuladas. La opción **Ampliar búsqueda por familia** omite deliberadamente la CPU para consultar candidatos de la familia.

Solo `ADMIN` y `ANALYST` pueden solicitar búsquedas; `OPERATOR` puede verlas. Si no se conoce fabricante o familia, el backend responde 400. Si un candidato específico no aparece, no presupongas que NVD carece de ese CPE: amplía la búsqueda.

### Límites de la fase 1

- Por consulta se recuperan hasta tres páginas de cien resultados; por ejecución se conservan hasta 250 candidatos distintos. `result_truncated` advierte sobre búsquedas parciales. No hay todavía caché entre ejecuciones (fase 3).
- No se automatiza el disparo tras registrar/editar activos (fase 3). No se buscan CPE de `Software` (fase 4).
- Si el worker es terminado bruscamente, las ejecuciones `RUNNING` antiguas se marcarán `FAILED` al reiniciar. Las `QUEUED` permanecerán. Solicita otra búsqueda para reintentar.
- El historial de búsqueda conserva datos técnicos y candidatos normalizados pero no la respuesta JSON bruta de NVD. No se persisten asociaciones validadas; eso corresponde a la fase 2.
- El código de pruebas NO envía peticiones reales a NVD. Para confirmar conectividad y nomenclatura es necesaria la prueba visual de laboratorio.


## Navegación global de identificación CPE (entre fases 1 y 2)

Se habilitó `/vulnerabilities/cpe` y el grupo **VULNERABILIDADES** con iconos en el menú lateral. La vista global consulta mediante `GET /api/vulnerabilities/cpe-overview/` un resumen de activos inventariados y su última búsqueda: sin búsqueda, en cola, consultando, candidatos por revisar, sin resultados, error o identidad modificada. Para Software indica explícitamente que las búsquedas estarán disponibles en la fase 4. No muestra asociaciones confirmadas antes de la fase 2. La vista incluye búsqueda, filtros y paginación de quince activos siguiendo el patrón de URL del Inventario. El resumen muestra hardware y software dentro de una sola tarjeta. Al revisar un activo y volver mediante la miga de pan `Vulnerabilidades / Identificación CPE / Activo`, los filtros y la página se conservan. La vista global se recarga al navegar a ella; se eliminó el botón redundante de actualización manual. `Análisis CVE (futuro)` es un elemento informativo deshabilitado, no una ruta funcional.

Este endpoint global es **solo lectura**, autorizado para los tres roles del inventario y no invoca NVD. No requiere nuevas migraciones ni modifica los mecanismos del worker.


### Diagnóstico de búsquedas que permanecen en cola

La pantalla de identificación CPE consulta periódicamente el estado almacenado en PostgreSQL. Los `GET 200` del navegador **no equivalen a peticiones NVD**, y el trabajo sigue guardado incluso si se cambia de pantalla o se cierra React.

Durante `QUEUED` y `RUNNING`, el backend incluye `worker_active`: `true` indica que se detecta el bloqueo exclusivo del trabajador en `pg_locks`, `false` que no se detecta, y `null` que no puede determinarse fuera de PostgreSQL. No garantiza que NVD responda correctamente. Pasados cinco minutos, la pantalla pausa la consulta automática y permite refrescar el estado manualmente.

Si una ejecución permanece pendiente, comprueba el comando `python manage.py run_cpe_worker` en una segunda terminal. Para revisar un trabajo concreto sin hacer nuevas peticiones externas:

```bash
python manage.py shell -c "from vulnerabilities.models import CpeSearchRun; print(list(CpeSearchRun.objects.filter(pk=2).values('id','status','created_at','started_at','finished_at','error_message','queries')))"
```

Al reiniciar el trabajador, los trabajos abandonados en `RUNNING` pasan a `FAILED`; los `QUEUED` se conservan y se procesan. Un fallo temporal de autenticación JWT normalmente genera un `401` seguido de renovación de token y de otro `GET 200`, sin afectar el trabajador.

El menú usa geometrías SVG oficiales de Lucide y la vista global tiene filtros explícitos Hardware/Software; la búsqueda de software sigue reservada para la fase 4.


### Filtrado de candidatos de hardware (refinamiento de fase 1)

La respuesta `keywordSearch` de NVD puede incluir CPE de hardware (`h`), sistemas operativos/firmware (`o`) y aplicaciones (`a`). Este módulo solo propone candidatos con la tercera parte de `cpeName` igual a `h`, tanto para búsquedas nuevas como al consultar ejecuciones históricas. Para auditoría, se mantienen los datos históricos en `CpeSearchRun.candidates`; el filtrado de historiales anteriores se hace en la lectura de la API. El conteo global y el conteo por búsqueda reflejan **candidatos de hardware**, mientras `queries[*].retrieved` sigue siendo el total bruto recuperado de NVD, antes del filtro. No confundir ambos contadores.

En los resultados de hardware no se muestra una etiqueta de versión; el valor original permanece en el `cpeName` oficial y en el registro JSON normalizado. Una revisión o versión de hardware puede existir según la nomenclatura de NVD, pero no se debe interpretar como firmware. La identificación de firmware y software sigue planificada para la fase 4. **Filtrar por tipo h no confirma que un candidato corresponda al dispositivo:** el analista decidirá en la fase 2.


## Fase 2 — Validación humana de candidatos CPE

**Migración:** ejecutar `python manage.py migrate` para crear `Cpe`, `AssetCpe` y `AssetCpeDecision`, sin modificar el inventario.

### API de revisión

| Método | Endpoint | Comportamiento |
| --- | --- | --- |
| `GET` | `/api/vulnerabilities/assets/{asset_id}/cpes/` | Asociaciones del activo e historial |
| `POST` | `/api/vulnerabilities/assets/{asset_id}/cpes/` | Decisión inicial para un candidato encontrado |
| `PATCH` | `/api/vulnerabilities/assets/{asset_id}/cpes/{association_id}/` | Nueva decisión sobre asociación existente |

Solicitud de ejemplo:

`{"run_id": 1, "cpe_name_id": "09f448d2-f606-44ab-8891-c27a3ff64002", "status": "CONFIRMED", "justification": "La placa indica CPU 1215C"}`

Los estados de nuevas decisiones permitidos por la API son `CONFIRMED`, `REJECTED` y `REOPENED` (deshacer decisión). `PENDING` únicamente es histórico. La justificación es opcional en todas las decisiones operativas; cuando se informa, se conserva en la asociación y en su historial de auditoría. La decisión sigue siendo explícita y requiere una confirmación final en pantalla. Solo `ADMIN` y `ANALYST` pueden modificar decisiones; `OPERATOR` puede consultarlas. Un CPE pertenece al catálogo global y puede asociarse a varios activos, pero cada par `(asset, cpe)` es único. Intentar crearlo dos veces devuelve `409`; para modificar la decisión se utiliza `PATCH`.

El backend comprueba que la búsqueda pertenece al activo, está `COMPLETED`, contiene el CPE oficial de tipo `h` y conserva la misma huella técnica del activo. La transacción bloquea únicamente la fila de `Asset` para evitar el problema PostgreSQL `FOR UPDATE` sobre un `OUTER JOIN` nullable. Si cambia fabricante, modelo o CPU, las asociaciones permanecen, pero `needs_review: true` indica que hay que repetir la búsqueda antes de volver a validar. Cada acción agrega un registro en `AssetCpeDecision`.

### Demostración con Siemens CPU 1215C

1. Ejecutar `python manage.py migrate` y `python manage.py check`.
2. Comprobar que las migraciones coincidan con los modelos: `python manage.py makemigrations --check --dry-run`.
3. Ejecutar `python manage.py test vulnerabilities --settings=config.settings_test_sqlite`.
4. Desde React, abrir el hardware Siemens SIMATIC S7-1200 y su Identificación CPE (la búsqueda completada se reutiliza).
5. En **CPE candidatos**, pulsar **Seleccionar CPE** en uno de los candidatos `h`. Se abre un formulario con justificación opcional. Pulsar **Confirmar asociación** para guardar.
6. Verificar que el candidato sale de **CPE candidatos** y aparece solo en **CPE revisados** con su estado, motivo como texto (si se informó), autor e historial. Pulsar **Cambiar decisión** y seleccionar **Rechazar candidato**; confirmar la segunda acción y comprobar que ambas decisiones siguen en el historial.
7. Volver a `/vulnerabilities/cpe` y verificar el estado global, sin perder filtros ni paginación.

El proceso `run_cpe_worker` es necesario para ejecutar **nuevas búsquedas NVD**; leer y validar candidatos ya encontrados no lo necesita. Las pruebas nuevas están en `tests_phase2.py`, y el caso previo `test_global_overview_includes_unsearched_and_completed_hardware` fue corregido para incluir un CPE oficial `h` válido.

### Refinamiento visual y de validación de fase 2

La interfaz separa **CPE revisados** de **CPE candidatos**. La lista de candidatos filtra por `cpe_name_id` oficial las asociaciones con decisiones vigentes: `CONFIRMED`, `REJECTED` o `PENDING` heredado. Las asociaciones `REOPENED` (decisiones deshechas) vuelven a candidatos. No se eliminan de NVD ni del historial; únicamente dejan de duplicarse en pantalla. Las decisiones anteriores siguen accesibles en el apartado de revisados, incluso si su CPE ya no aparece entre los resultados actuales.

Las acciones nuevas utilizan controles visuales diferenciados (verde para seleccionar/confirmar y rojo para rechazar). La primera pulsación **elige una acción sin modificar PostgreSQL**. En el segundo paso aparece una explicación y el campo opcional para el motivo, seguido del botón definitivo de confirmación y Cancelar. Tras guardar se cierra el formulario y se actualiza la lista. Para modificar una decisión previa se utiliza **Cambiar decisión**. Confirmar o rechazar exige evidencia actual; **Deshacer decisión** (`REOPENED`) retira una decisión anterior sin requerir otra búsqueda.

El backend valida un límite de 1000 caracteres para el motivo cuando se informa, pero no exige rellenarlo. El historial `AssetCpeDecision` sigue capturando estado, usuario, fuente, fecha y huella técnica aunque la justificación esté vacía. Estas mejoras no requieren migraciones nuevas.

Pruebas del frontend: `npm run test:unit` incluye `src/utils/cpeReview.test.js`; el backend suma un test para motivo omitido y reemplaza la antigua prueba de obligatoriedad por revisiones sin motivo. Ejecutar `npm run build` y `python manage.py test vulnerabilities --settings=config.settings_test_sqlite` antes de cerrar el refinamiento.

## Refinamiento de fase 2 — Trazabilidad NVD y reapertura

La migración `0003_cpe_reopened` incorpora `REOPENED` a `AssetCpe` y `AssetCpeDecision`, sin eliminar decisiones anteriores ni alterar la unicidad de `(asset, cpe)`.

### Enlaces verificables a NVD

Cada candidato y cada asociación muestran el nombre CPE completo y su `cpe_name_id` (UUID). El enlace **Consultar CPE en NVD** utiliza `https://services.nvd.nist.gov/rest/json/cpes/2.0?cpeNameId={uuid}`. Para `keywordSearch` y `cpeMatchString`, el frontend reconstruye enlaces JSON de cada página ejecutada usando `URLSearchParams`, `startIndex` y `resultsPerPage=100`. Son consultas **actuales** a NVD, no instantáneas históricas. No almacenamos respuestas JSON brutas.

El resumen muestra únicamente el total de candidatos de hardware (`h`); las cantidades brutas de NVD siguen en `queries` para auditoría interna. Se mantienen los dos registros Siemens cuando sus `cpeNameId` son distintos; no se deduplican por títulos parecidos ni se alerta sobre supuestas equivalencias. La interfaz muestra el método de descubrimiento, el tipo y la deprecación, sin presentar una coincidencia textual como confirmación. La clasificación interna distingue `cpu_1215c` de la variante `cpu_12_1215c` sin descartar esta última.

### Deshacer decisión (estado interno `REOPENED`)

Solo `ADMIN` y `ANALYST` pueden retirar una decisión; `OPERATOR` tiene lectura. En **CPE revisados → Cambiar decisión → Deshacer decisión**, se abre una confirmación con justificación opcional. La petición `PATCH /api/vulnerabilities/assets/{asset_id}/cpes/{association_id}/` admite `{"status":"REOPENED"}` sin `run_id`. Mantiene `source_run` como evidencia histórica y añade una entrada al historial con usuario, fecha, estado previo y huella actual. La reapertura puede realizarse incluso si el inventario cambió: retirar una decisión no ratifica su aplicabilidad.

Las revisiones reabiertas regresan a **CPE candidatos**. Cuando ese UUID está en la búsqueda vigente, guardar otra decisión hace `PATCH` sobre la misma asociación y preserva toda la auditoría. Si no está en la búsqueda actual, permanece visible como reabierto, pero requiere una nueva búsqueda antes de confirmarse. `REOPENED` no puede crearse por `POST`; el backend impide repetir el mismo estado sin evidencia nueva (HTTP 409). La revalidación del mismo estado sí se permite con una nueva búsqueda válida.

En la vista global aparecen `REOPENED` y `reopened_count`, separados de `reviewed_count`. Las acciones de CPE revisados excluyen el estado ya guardado.

### Validación local

En `web_app/backend`:

```bash
python manage.py migrate
python manage.py check
python manage.py makemigrations --check --dry-run
python manage.py test vulnerabilities --settings=config.settings_test_sqlite
```

En `web_app/frontend`:

```bash
npm run test:unit
npm run build
```

Con el Siemens CPU 1215C, comprobar los dos UUID distintos, abrir el JSON de NVD, reabrir el CPE ya rechazado, volverlo a seleccionar y verificar que siga existiendo una única fila `AssetCpe` con historial completo. Para reabrir una decisión no se requiere ejecutar el worker.


## Refinamiento final de fase 2 — Estados de evaluación y tabla global

Se conservan las columnas Activo, Identidad técnica, Estado, CPE y Acciones. La columna CPE muestra encontrados, confirmados, rechazados y por revisar. El sistema nunca crea asociaciones solo por haber descubierto un candidato.

### Contadores por UUID y estado del activo

La API cuenta CPE de hardware con UUID distinto de la última búsqueda completada cuya identidad técnica es vigente. Confirmados y rechazados son decisiones que corresponden a esos UUID con huella de identidad actual. Por revisar = encontrados - confirmados - rechazados. Los CPE reabiertos y los PENDING históricos cuentan como por revisar si aparecen en esa búsqueda. Los históricos PENDING se muestran en legacy_pending_count, pero el backend rechaza nuevos POST y PATCH con ese estado (HTTP 400).

Los estados de evaluación son TO_REVIEW (Por revisar), IN_REVIEW (En revisión), EVALUATED (Evaluado), NOT_SEARCHED (Sin búsqueda), QUEUED (En cola), RUNNING (Consultando NVD), FAILED (Error), NO_RESULTS (Sin resultados), STALE (Revisión necesaria), y NOT_SUPPORTED (Software fuera del alcance). Evaluado no significa confirmado: todos los CPE pueden haber sido rechazados.

Cuando se ejecuta una búsqueda nueva, el estado refleja QUEUED o RUNNING y los contadores siguen perteneciendo a la última búsqueda completada vigente. Las decisiones ajenas a los UUID de esa búsqueda no se contabilizan como actuales; permanecen auditadas y se informa mediante out_of_scope_count. Una asociación vigente fuera del alcance cambia el estado a STALE para exigir revisión.

### Enlaces y vocabulario

El CPE Name es el único enlace individual a NVD por cpeNameId. El UUID sigue visible pero no es otro enlace. Los enlaces tienen colores suaves con estilos para visitado, hover y foco. El usuario ve Deshacer decisión en lugar de Reabrir revisión. Cancelar solo cierra un formulario, sin guardar cambios. El estado interno REOPENED y el historial permanecen.

### Comprobación con Siemens

Un confirmado y un rechazado entre dos encontrados: EVALUATED, 2 encontrados, 1 confirmado, 1 rechazado y 0 por revisar. Tras deshacer el rechazo: IN_REVIEW, 2 encontrados, 1 confirmado, 0 rechazados y 1 por revisar. Volver a evaluar: EVALUATED.

Desde web_app/backend ejecutar python manage.py check; python manage.py makemigrations --check --dry-run; python manage.py test vulnerabilities --settings=config.settings_test_sqlite. Desde web_app/frontend ejecutar npm run test:unit y npm run build. No se requieren migraciones nuevas en este refinamiento.


## Incremento de fase 2 — Búsquedas CPE masivas desde el inventario

**No requiere migraciones:** usa la tabla persistente `CpeSearchRun` y el worker `python manage.py run_cpe_worker` existentes. No hay llamadas NVD durante las solicitudes HTTP.

### API

Endpoint `POST /api/vulnerabilities/cpe-searches/bulk/` (roles `ADMIN` y `ANALYST`), con cuerpo:

`{"asset_ids":[10,8,3],"scope":"SPECIFIC"}`

`scope` solo admite `SPECIFIC` (o puede omitirse). Se admiten entre 1 y 100 identificadores por solicitud; los IDs repetidos se consolidan. La búsqueda ampliada `BROAD` sigue realizándose individualmente desde la ficha del hardware. Cada activo se valida y encola en una transacción independiente, reutilizando un trabajo `QUEUED` o `RUNNING` con la misma identidad y alcance. Un activo erróneo no impide procesar a los demás.

La respuesta devuelve `results[]` en el orden de los IDs, con `asset_id`, `asset_name`, `asset_type`, `outcome`, `run_id` cuando corresponda y `message` para omisiones o errores. Outcomes: `QUEUED`, `REUSED`, `UNSUPPORTED` (software), `SKIPPED` (archivado), `NOT_FOUND` e `INVALID_IDENTITY`. `summary` incorpora `received`, `queued`, `reused`, `skipped` y `failed`. Se devuelve HTTP 202 si se encoló o reutilizó al menos uno; HTTP 200 cuando todos quedaron omitidos o fallidos. Errores de estructura en la petición devuelven 400, y los operadores obtienen 403.

Actualmente se **puede seleccionar software**, pero su búsqueda se omite de manera explícita y **nunca se crea un CpeSearchRun imposible de ejecutar**. En la fase de software el mismo endpoint podrá implementar el despacho de su tipo de activo sin cambiar la selección frontend.

### Interfaz

La vista `Vulnerabilidades → Identificación CPE` incluye casillas por fila y selección de la página actual. Los IDs permanecen seleccionados al cambiar filtros o páginas; el botón `Limpiar selección` los descarta. La confirmación muestra todos los activos seleccionados, alcance específico, funcionamiento secuencial y advertencia de software diferido, antes de enviar una única petición. Después se muestra una respuesta individual por activo. La selección se limpia al recibir una respuesta exitosa.

En hardware aparecen dos botones: `Buscar`, que encola directamente una búsqueda `SPECIFIC` sin abandonar la tabla, y `Revisar`, que mantiene la navegación y los filtros. En software la selección masiva está permitida, pero el botón individual Buscar está deshabilitado hasta implementar su descubrimiento.

El frontend consulta `cpe-overview` periódicamente cada 10 segundos solo mientras haya búsquedas `QUEUED` o `RUNNING`, con una pausa de seguridad a los cinco minutos y un botón de consulta manual. Nunca invoca NVD directamente. Si el worker está apagado los trabajos quedan pendientes en PostgreSQL.

### Verificación

Desde `web_app/backend`: `python manage.py check` y `python manage.py test vulnerabilities --settings=config.settings_test_sqlite`. La batería `tests_bulk.py` cubre cola, duplicados, roles, búsqueda específica, identidad inválida, hardware/software mixtos, archivos y ejecución HTTP sin NVD.

Desde `web_app/frontend`: `npm run test:unit` y `npm run build`. `cpeBulkSelection.test.js` comprueba persistencia de IDs entre páginas, deselección y selección mixta.

Prueba funcional: con `run_cpe_worker` en otra terminal, seleccionar Siemens + Hirschmann + un software. Confirmar: hardware en cola, software omitido; volver a la tabla y observar `QUEUED` → `RUNNING` → estados posteriores. Volver a pulsar Buscar sobre un hardware todavía en cola debe reutilizar su trabajo, sin crear otro.

## Fase 2 — Descubrimiento progresivo por fabricante (hardware)

La cadena automática de descubrimiento se amplía usando la infraestructura existente, sin migraciones ni búsquedas de software:

- `SPECIFIC`: específico → familia → fabricante, si el nivel anterior se completó sin correspondencias pertinentes.
- `BROAD`: familia → fabricante. `CpeSearchRun.scope` registra el alcance solicitado y `queries[].level` los niveles ejecutados.
- `MANUFACTURER`: consulta NVD Products CPE con `cpeMatchString=cpe:2.3:h:<vendor_normalizado>`. No se usa la API CVE.

**Pertinencia**: solo se almacenan candidatos CPE de tipo hardware, fabricante coincidente y relación explicable con modelo/familia (`SPECIFIC`, `FAMILY`, `RELATED`, `NEEDS_INFO`). La búsqueda puede recuperar otros productos del fabricante, pero quedan filtrados y contabilizados en `queries[].filtered_hardware_results`. Ninguna clasificación confirma automáticamente un CPE.

**Presupuesto global**: se conservan `MAX_TOTAL_PAGE_FETCHES=8`, `MAX_PAGES_PER_STRATEGY=3` y `MAX_TOTAL_CANDIDATES=250`. El nivel fabricante tiene un límite adicional `MAX_MANUFACTURER_PAGES=2`, consumido dentro del mismo presupuesto global. Si faltan páginas: `result_truncated=True` y motivo `MANUFACTURER_PAGE_LIMIT` o `GLOBAL_PAGE_LIMIT`; la vista global informa `PARTIAL_RESULTS` en vez de `NO_RESULTS`. Un error NVD mantiene `FAILED`.

**Compatibilidad**: deduplicación por UUID, procedencia por `methods` y `discovery_levels`; JSON históricos interpretables, sin nuevas migraciones ni cambios en las asociaciones, auditoría, cola PostgreSQL y worker NVD.

**Pruebas**: ocho casos nuevos offline en `tests_progressive.py` para fabricante, relación ADAM-5550, alcance `BROAD`, pertinencia, truncamiento, timeout, presupuesto compartido y deduplicación entre niveles. Ejecutar `python manage.py check`, `python manage.py makemigrations --check --dry-run` y `python manage.py test vulnerabilities --settings=config.settings_test_sqlite` desde `web_app/backend`.

Para la prueba manual de ADAM-5000 Series: ejecutar el worker, lanzar búsqueda específica y revisar `queries[].level`. El nivel `MANUFACTURER` solo aparecerá cuando las etapas anteriores sean insuficientes. ADAM-5550 puede aparecer como `RELATED` si se encuentra en las páginas efectivamente consultadas; nunca se confirma automáticamente.


## Refinamiento fase 2 — Alias controlados y prefijos de producto (2026-10-20)

El inventario conserva el fabricante original. `vendor_variants()` genera alias CPE de búsqueda,
sin alterar identidad técnica, fingerprint ni registros ya confirmados. Las excepciones
documentadas incluyen Rockwell Automation → `rockwellautomation` y
Axis Communications → `axis`, más grafías normalizadas con guion o guion bajo.
Un alias permite recuperar candidatos; no demuestra correspondencia de modelo.

Para modelos con prefijo de catálogo numérico explícito y separador
(1783-EMS08T/B → 1783), el nivel MANUFACTURER consulta primero
`cpe:2.3:h:rockwellautomation:1783*` y variantes antes de las
consultas generales del fabricante. Un CPE 1783-NATR se clasifica como
`RELATED` por prefijo industrial: NO identifica el mismo producto ni se valida
automáticamente. AXIS 206 y 207 no comparten una regla de catálogo:
la proximidad numérica no autoriza relacionarlos.

Presupuestos acumulados: MAX_TOTAL_PAGE_FETCHES=8 por ejecución y
MAX_TOTAL_CANDIDATES=250; máximo 2 páginas por consulta de fabricante y
MAX_MANUFACTURER_LEVEL_PAGES=4 compartidas entre todas las grafías y consultas
del fabricante. Cuando faltan consultas por ejecutar, el resultado se marca
`result_truncated=True` y stop_reason `MANUFACTURER_LEVEL_LIMIT`.
Las solicitudes que fallan conservan estado FAILED. La cola, frecuencia NVD,
los candidatos y las decisiones auditadas mantienen su semántica original.

### Fases siguientes del descubrimiento progresivo (acuerdos vigentes)

- Fase 3 — Explicación y clasificación visual: agrupar consultas por nivel
  SPECIFIC/FAMILY/MANUFACTURER, mostrar alias empleado, razón de ampliación,
  candidatos filtrados y truncamientos. Mantener la categoría RELATED
  diferenciada de una identificación confirmada. Contrastar Rockwell y AXIS.
- Fase 4 — Búsqueda avanzada: consultas controladas keywordSearch/cpeMatchString,
  alias editables propuestos, parámetros auditados y límites compartidos;
  nunca ejecutar URL arbitraria ni consultas desde React a NVD.
- Fase 5 — Referencias oficiales: conservar refs NVD de producto y avisos en
  candidatos y CPE confirmados, con URLs seguras y trazabilidad de origen.

Estas fases de descubrimiento refinado no sustituyen otros pendientes
históricos del sistema, como caché, software, exportación y CVE.
El soporte CPE de software continúa diferido.

Pruebas: `python manage.py test vulnerabilities --settings=config.settings_test_sqlite`
(9 nuevas pruebas para variantes, catálogo, falsos positivos, límites y fallos),
más `npm run test:unit` y `npm run build` desde el frontend.

## Fase 3 — Clasificación y trazabilidad visual del descubrimiento progresivo

Se incorporó un recorrido de consultas en `AssetCpeDiscovery` que agrupa
`CpeSearchRun.queries` por `SPECIFIC`, `FAMILY` y `MANUFACTURER`; muestra
términos CPE y keywordSearch, enlaces a JSON NVD, páginas, resultados por consulta,
hardware procesado, productos filtrados, motivos de ampliación, límites y
finalizaciones parciales. Los registros recuperados por consulta NO equivalen
a candidatos únicos (pueden repetirse entre estrategias y páginas).

Cada candidato revisable muestra clasificación automática `match_level`,
explicación `match_reason`, niveles `discovery_levels` y métodos `methods`.
Los CPE con decisión registrada también muestran su clasificación de la
última búsqueda únicamente si ese candidato sigue apareciendo en ella.
Las decisiones del analista (CONFIRMED / REJECTED), justificación e historial
son independientes y siguen siendo la única validación oficial.

Se preserva la lectura de búsquedas históricas sin nivel o clasificación,
con aviso de metadatos no registrados; no se atribuyen niveles retroactivamente.
No hay cambios en modelos, migraciones, endpoint, worker ni llamadas adicionales
a NVD. Las fases 4 (búsqueda avanzada controlada) y 5 (refs NVD oficiales)
siguen pendientes.

Pruebas nuevas: 5 casos en `cpeDiscoveryPresentation.test.js` sobre agrupación,
conteo no único, búsqueda histórica, Rockwell 1783-NATR (RELATED),
AXIS 206/207 (no equivalencia) y Siemens CPU 1215C.

Verificar desde `web_app/frontend`: `npm run test:unit` y `npm run build`.
Desde `web_app/backend`: `python manage.py check` y
`python manage.py test vulnerabilities --settings=config.settings_test_sqlite`.
Validación funcional: revisar consultas agrupadas del Rockwell,
evidencia de límites parciales en AXIS y clasificación específica Siemens.
