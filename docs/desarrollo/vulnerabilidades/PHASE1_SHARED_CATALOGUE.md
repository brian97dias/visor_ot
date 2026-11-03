# Catálogo NVD compartido — Fase 1: persistencia y recuperación

## Alcance y compatibilidad

Se mantienen sin cambios funcionales CpeSearchRun, AssetCpe,
AssetCpeDecision, el frontend y los presupuestos del buscador por activo.
El nuevo recuperador comparte el catálogo Cpe y conserva TODOS los
productos devueltos por cada consulta, estén o no relacionados con
algún hardware. Ningún producto queda confirmado automáticamente.

## Modelos de la migración 0005_cpe_catalogue_cache

- CpeQueryCache: identidad SHA-256 de estrategia, parámetro canónico y
  versión API CPE 2.0. Independiente de activos y offsets.
- CpeQuerySnapshot: una recuperación versionada, con progreso, total,
  checkpoint y estados QUEUED/RUNNING/INCOMPLETE/COMPLETED/FAILED.
- CpeQueryProduct: relación única (snapshot, cpe) con el JSON original
  de NVD, evidencia de esa recuperación conservada históricamente.
- Cpe existente: UUID único de NVD; se actualizan metadatos oficiales
  sin modificar el campo references_source_run ni la auditoría humana.

## Funcionamiento

El worker original mantiene el advisory lock global PostgreSQL y
el intervalo NVD entre peticiones. Se ejecutan las búsquedas del
inventario y las recuperaciones del catálogo por orden de encolado.
El tamaño de página predeterminado es 500 (configurable entre 1 y 1000).
Cada página guarda productos, evidencia y checkpoint en una única
transacción de base de datos. Si la transacción falla, se repite desde
la última página confirmada; no se pierden páginas ya registradas.

El worker reiniciado convierte las recuperaciones RUNNING abandonadas
en INCOMPLETE para reanudarlas. Los errores transitorios se guardan como
FAILED, con el checkpoint y los productos intactos. Puede usarse --resume
para ellos. Cambios en totalResults o resultados inconsistentes nunca
se certifican como COMPLETED y exigen otra versión con --force.

Las consultas completadas durante los últimos 7 días se reutilizan.
Una versión nueva conserva la evidencia de las anteriores. Los productos
que no coinciden con ningún activo igualmente se guardan sin crear
AssetCpe: una asociación siempre requiere decisión del analista.

## Preparación local

Desde web_app/backend:

    python manage.py migrate
    python manage.py check
    python manage.py makemigrations --check --dry-run
    python manage.py test vulnerabilities --settings=config.settings_test_sqlite

Encolar recuperación:

    python manage.py enqueue_cpe_catalogue --strategy cpeMatchString --parameter 'cpe:2.3:h:phoenix_contact'

Crear una versión nueva aunque haya una reciente:

    python manage.py enqueue_cpe_catalogue --strategy cpeMatchString --parameter 'cpe:2.3:h:phoenix_contact' --force

Ejecutar trabajo (en otra terminal del backend):

    python manage.py run_cpe_worker

Reintentar un fallo transitorio de red (sustituir N):

    python manage.py enqueue_cpe_catalogue --resume N

Consultar el progreso:

    python manage.py shell -c "from vulnerabilities.models import CpeQuerySnapshot; print(list(CpeQuerySnapshot.objects.values('id','status','expected_total','retrieved_count','unique_products_count','next_start_index','pages_fetched','error_code').order_by('-id')[:10]))"

## Cobertura

tests_catalogue.py: 17 pruebas con NVD simulado para paginación de 500;
recuperación de 1.902 registros; parada tras 1.000 y reanudación;
consistencia de totales; errores HTTP simulados; duplicados, UUID inválidos,
caché expirado, versiones nuevas y conservación de asociaciones auditadas.

SQLite se utiliza exclusivamente para pruebas. El lock y el comportamiento
real del worker deben comprobarse con PostgreSQL y una sola instancia.

## Fuera del alcance de esta fase

Aún no se conectan las búsquedas SPECIFIC/BROAD/ADVANCED, las operaciones
masivas ni el explorador React al nuevo catálogo. Son las fases 2, 3 y 4.
No se modifica el módulo de software ni se implementa correlación CVE.
