# VISOR OT — Módulo de identificación CPE

**Rama:** `feature/vulnerability`  
**Fase 0:** integración y especificación; **sin modelos persistentes, migraciones ni consultas HTTP a NVD**.

## Alcance aprobado

El módulo descubre candidatos CPE oficiales desde NVD, los compara con el inventario de activos y permite que un analista los confirme, rechace o deje pendientes. **No** consulta CVE, evalúa vulnerabilidades, calcula riesgo ni genera recomendaciones de hardening en este incremento.

Responsabilidades: `assets` conserva `Asset`, `Hardware`, `Software` y `SoftwareInstallation`; `vulnerabilities` conserva ejecuciones de búsqueda, CPE de NVD, asociaciones y decisiones de revisión. Se reutilizarán los servicios existentes de inventario, sin duplicar activos.

## Modelo de datos propuesto (antes de migrar)

Las tablas siguientes **todavía no existen**. Se revisarán antes de aplicar sus respectivas migraciones.

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

`AssetCpe` materializa la relación N:M entre `Asset` y `Cpe`. Contendrá `asset`, `cpe`, `validation_status` (`PENDING`, `CONFIRMED`, `REJECTED`), `justification`, `validated_at`, `validated_by` y `validated_identity_fingerprint`. Restricción única para el par (`asset`, `cpe`). **Sin `is_primary`.**

Los candidatos automáticos permanecerán en `CpeSearchRun`; solo la acción de un usuario creará o modificará `AssetCpe`, incluso cuando el usuario elija `PENDING` explícitamente. Para conservar decisiones previas, se propone `AssetCpeDecision` como historial inmutable (`asset_cpe`, estado previo/nuevo, justificación, actor, fecha y huella de identidad) en la fase 2. **Validar este detalle antes de la migración**.

Las asociaciones confirmadas no se eliminan tras cambiar fabricante, modelo, CPU, producto o versión. Una comparación con `validated_identity_fingerprint` deberá indicarlas como **requieren revisión**.

### Fase 3 — `CpeQueryCache`

Una entrada por consulta individual equivalente (`strategy`, parámetros normalizados, llave/hash, `candidates` normalizados, `fetched_at`, `expires_at`), compartida entre activos. Duración configurable; una actualización forzada invalida/reconsulta. No guardar el JSON bruto de NVD. Se revisará el esquema exacto al comenzar esta fase para evitar tablas redundantes.

## Contrato HTTP propuesto

**Estos endpoints no están implementados en la fase 0.** Requieren autenticación JWT y verificación explícita de permisos por rol, igual que el resto de VISOR OT.

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

**Pendientes antes de crear migraciones:** validación definitiva de campos y de la entidad de historial `AssetCpeDecision`; contratos de error y límites máximos de paginación; comportamiento del worker en recuperación de trabajos `RUNNING` tras reinicio. En fase 0 **no se han ejecutado** todavía cambios de esquema ni consultas de NVD.
