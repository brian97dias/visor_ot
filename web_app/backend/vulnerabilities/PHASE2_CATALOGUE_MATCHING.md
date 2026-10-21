# Catálogo NVD compartido — Fase 2: catálogo y clasificación independiente

## Objetivo

**Recuperación ≠ clasificación ≠ confirmación.** El catálogo CPE guarda
todos los registros devueltos por NVD mediante CpeQueryProduct.nvd_record.
El servicio de fase 2 interpreta esa evidencia para un activo determinado,
sin eliminar productos ni crear/modificar asociaciones AssetCpe.

Las búsquedas actuales SPECIFIC/BROAD/ADVANCED y las búsquedas masivas
siguen utilizando el motor anterior; la integración progresiva se hará
en fase 4. Tampoco se crea todavía el explorador React (fase 3).

## Servicio: services/cpe_catalogue_matching.py

- classify_catalogue_record(evidence, identity): analiza un registro original
  NVD y devuelve su clasificación contextual al activo. Reutiliza las
  reglas existentes de fabricante, modelo, CPU y prefijo de catálogo.
- summarize_catalogue(snapshot, identity): cuenta cada producto, los
  candidatos sugeridos, los descartados de la recomendación y las
  coincidencias técnicas fuertes. Procesa filas por iterador de memoria
  acotada; no modifica los datos.
- browse_catalogue(snapshot, identity, view='ALL', after_id=0, limit=25):
  páginas por cursor, máximo 100 filas. Los cursores son IDs de evidencia,
  no offsets NVD. ALL muestra todos los productos; CANDIDATES solo sugerencias
  revisables; EXCLUDED muestra los productos que NO se sugieren para ese activo.

Clasificaciones: CANDIDATE, NON_HARDWARE, OTHER_VENDOR y OTHER_PRODUCT.
Para cada candidato se conserva la clasificación previa SPECIFIC, FAMILY,
RELATED o NEEDS_INFO, el motivo explicable, y la pertinencia fuerte.
RELATED **no** confirma una asociación, y una coincidencia SPECIFIC tampoco.
Los productos excluidos siguen consultables en ALL y EXCLUDED.

Las páginas consultan el JSON original del snapshot, no los metadatos
posiblemente actualizados del catálogo Cpe. Se conservan el UUID, título
histórico, tipo CPE y referencias originales, sin importar que otros
activos hayan recuperado versiones más nuevas del mismo producto.

## Cobertura de búsqueda

Se retorna el estado del snapshot y coverage_complete=True únicamente si
su estado es COMPLETED. En cualquier otro caso (QUEUED, RUNNING, INCOMPLETE,
FAILED), las cifras describen solo las evidencias **almacenadas hasta ahora**:
cero candidatos encontrados NO es prueba de inexistencia en NVD.

## Inspección por consola (sin NVD ni escritura)

Desde web_app/backend, con el entorno virtual activo:

    python manage.py inspect_cpe_catalogue --snapshot 1 --asset 10 --view ALL --limit 10

Reemplaza 1 y 10 por el snapshot recuperado y un ID válido de hardware.
Para mostrar únicamente candidatos sugeridos:

    python manage.py inspect_cpe_catalogue --snapshot 1 --asset 10 --view CANDIDATES --limit 10

Para auditar productos que fueron excluidos de la sugerencia:

    python manage.py inspect_cpe_catalogue --snapshot 1 --asset 10 --view EXCLUDED --limit 10

Cuando la salida muestre '--after N', repite el comando con ese cursor
para continuar. El comando nunca confirma, rechaza o importa CPE.
Si el snapshot aún figura QUEUED, ejecutar run_cpe_worker previamente.

## Pruebas de regresión

El nuevo archivo tests_catalogue_matching.py añade 14 pruebas simuladas
para: candidatos Rockwell 1783, diferencias AXIS 206/207, CPU Siemens,
productos software, fabricantes distintos, títulos anómalos de NVD,
modelos obsoletos, paginación filtrada sin pérdidas, versiones históricas,
estados de cobertura y ausencia de escrituras/decisiones del analista.

Desde el backend:

    python manage.py check
    python manage.py makemigrations --check --dry-run
    python manage.py test vulnerabilities --settings=config.settings_test_sqlite

Las 133 pruebas de fase 1 estaban aprobadas en el equipo del desarrollador.
Con las 14 nuevas, el total esperado es 147. Se requiere ejecutar la
batería local para confirmar la fase 2.

## Fuera de alcance

No se añadieron migraciones, endpoints REST ni cambios React.
En la fase 3 se expondrá un explorador seguro de los productos con
paginación y filtros visuales. En la fase 4 se reutilizará el catálogo
en las búsquedas automáticas y masivas existentes.
