# Fase 3 — Explorador visual del catálogo CPE compartido

Esta fase incluye una pantalla React de exploración y tres rutas REST
protegidas. No modifica modelos ni migraciones; no inicia solicitudes NVD
al navegar o filtrar. Todas las consultas leen snapshots ya almacenados.

## Acceso

Desde `Vulnerabilidades > Identificación CPE`, abrir un hardware y
pulsar `Explorar catálogo NVD almacenado`. La ruta nueva es:
`/assets/:assetId/cpe/catalogue`.

El selector de snapshot se inicializa preferentemente con una recuperación
completa y no vacía cuyo fabricante corresponde al inventario. Por ejemplo,
para Phoenix Contact, entre el snapshot #1 con 0 y el #2 con 327 productos,
debe elegir el #2. El usuario puede cambiar de snapshot libremente.

El explorador presenta tres vistas: ALL (todo), CANDIDATES (sugeridos) y
EXCLUDED (no sugeridos). Los filtros por texto, tipo CPE h/o/a y estado de
obsolescencia se aplican en el backend ANTES de paginar. La paginación es
por cursor de evidencia, no por startIndex NVD, para evitar duplicados al
pasar entre filtros. Permite visualizar UUID, CPE Name, referencias Product,
clasificación contextual, razones y cobertura de la recuperación.

Una recuperación parcial o fallida puede explorarse para diagnóstico,
pero la UI advierte de la cobertura incompleta y no permite seleccionar
evidencia hasta que el snapshot esté COMPLETED.

## REST

- GET /api/vulnerabilities/assets/{asset_id}/cpe-catalogue/snapshots/
- GET /api/vulnerabilities/assets/{asset_id}/cpe-catalogue/snapshots/{snapshot_id}/
  Parámetros opcionales: view, q, cpe_type, deprecated, after, limit (1–100).
- POST /api/vulnerabilities/assets/{asset_id}/cpe-catalogue/snapshots/{snapshot_id}/select/
  JSON: {"evidence_id": 123}

Solo ADMIN y ANALYST pueden ejecutar POST. OPERATOR puede consultar.
El backend valida hardware activo, snapshot COMPLETED y pertenencia del ID
de evidencia al snapshot elegido. Un identificador UUID arbitrario enviado
desde React nunca se acepta como sustituto de la evidencia.

La selección crea un CpeSearchRun COMPLETED con trigger CATALOGUE y copia
una única evidencia desde el registro oficial original. En queries almacena
snapshot_id y evidence_id. NO crea AssetCpe ni AssetCpeDecision; únicamente
prepara la evidencia para que el analista confirme o rechace mediante el
componente CandidateCpeReview y los endpoints de auditoría existentes.
El estado REOPENED y los históricos se conservan sin cambios.

Se pueden seleccionar también productos hardware no sugeridos: la UI
advierte que la clasificación automática no los consideró pertinentes.
La revisión humana es explícita; el backend verifica identidad actual al
confirmar y no permite registrar candidatos de software como hardware.

## Verificación

Desde el backend:
    python manage.py check
    python manage.py makemigrations --check --dry-run
    python manage.py test vulnerabilities --settings=config.settings_test_sqlite

Desde el frontend:
    npm run test:unit
    npm run build

Los 147 tests de la fase 2 estaban aprobados. Se agregan 11 pruebas Django
y 4 nuevas pruebas JS, por lo que esperamos 158 tests Django.
Las pruebas utilizan respuestas simuladas; no realizan consultas NVD reales.

Prueba manual: en el activo #2 Phoenix Contact FL IL 24 BK-PAC, entrar al
explorador y elegir snapshot #2 (327 registros). Vista ALL mostrará productos
Phoenix Contact. Probar texto FL IL 24, h, NO deprecados y pasar de página.
Con el activo #10 Siemens, esos productos deberán figurar principalmente
como OTHER_VENDOR sin desaparecer de ALL. Seleccionar un CPE hardware desde
un snapshot completo, comprobar snapshot/evidence en la búsqueda creada,
y confirmar o rechazar expresamente. Verificar historial de decisiones.

## Pendiente — Fase 4

Integrar el catálogo con SPECIFIC/BROAD/ADVANCED y búsquedas masivas.
Por ahora el buscador automático no usa directamente las recuperaciones
almacenadas. La API del explorador es de solo lectura salvo la preparación
explícita de evidencia para revisión.
