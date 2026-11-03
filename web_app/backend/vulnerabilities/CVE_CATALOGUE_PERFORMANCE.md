# Diagnóstico de latencia — Análisis CVE

## Síntoma observado

El operador observó aproximadamente **8 segundos** entre abrir
`/vulnerabilities/cve` y visualizar el catálogo. Su PostgreSQL real incluye
88 CVE oficiales, 122 evaluaciones hardware–CVE y varias decisiones de analista.
Esta cifra es una observación del navegador, **no** una medida del backend.

## Hallazgo estático confirmado en `fix/general`

La vista `CveCatalogueView.get()` procesa una página de 15 filas de este modo:

1. Obtiene los CVE filtrados y construye el catálogo por cada hardware:
   `related_assets_for_cves(cves)`, que a su vez llama repetidamente a
   `_context(cve_id, hardware_id)`, `evaluate_configurations()`, lectura
   de auditorías y validación de fingerprints.
2. Calcula `catalogue_statuses(cves)` y pagina los pares evaluados.
3. Para los contadores superiores invoca `_catalogue_summaries()`, que
   **vuelve a ejecutar** `related_assets_for_cves` y
   `catalogue_statuses` sobre todos los CVE oficiales.

Con filtros de búsqueda por nombre de activo, el recorrido
`_cve_ids_for_evaluated_asset_name()` puede construir una proyección
adicional de los CVE candidatos.

La función `_context()` hace varias consultas por pareja CVE–hardware:
obtiene hardware, CVE, CPE hardware confirmados, instalaciones vigentes,
y CPE software confirmados. La tabla exige evaluar los pares para contar,
filtrar por estado y paginar; **la propuesta de optimización futura debe
conservar las decisiones específicas del hardware y sus verificaciones**.

No se debe afirmar todavía qué porcentaje de los 8 segundos corresponde
a cada operación: debe medirse en la base de PostgreSQL del usuario.

## Comando de medición (no muta la base)

Desde `web_app/backend`, con el entorno virtual activo:

```bash
git switch fix/general
git pull --ff-only
python manage.py test vulnerabilities.tests_cve_catalogue_profile \
  --settings=config.settings_test_sqlite
python manage.py profile_cve_catalogue --username analista-brian --runs 2
```

Prueba del filtro por activo:

```bash
python manage.py profile_cve_catalogue \
  --username analista-brian --q PLC-TRA-01 --runs 2
```

Y del filtro por pendientes (opcional):

```bash
python manage.py profile_cve_catalogue \
  --username analista-brian --status PENDING_REVIEW --runs 2
```

Las métricas se imprimen **por ejecución**:

- Milisegundos de la vista DRF incluyendo serialización JSON.
- Número de consultas SQL y tamaño del JSON.
- Conteo de pares evaluados y total de CVE oficiales.
- Funciones medidas: `proyeccion_hardware_cve`,
  `recalculo_indicadores`, `estados_historial`,
  `consultar_inventario`, `evaluacion_nvd`,
  `estado_por_hardware`, `software_evaluado`,
  `verificar_historial_vigente`, `busqueda_por_activo`.
- Hasta tres consultas SQL más lentas (usar `--slow-sql 0` para omitirlas).
- Mediana de las repeticiones. La primera ejecución podría ser más lenta
  por caché fría del sistema/BD, no por un cambio de lógica.

**Advertencia:** los tiempos de fases anidadas son inclusivos; no se
deben sumar como si fueran independientes. La instrumentación de SQL añade
una pequeña sobrecarga propia. El comando no ejecuta peticiones NVD, no
crea trabajos y no escribe decisiones.

## Comparación con el navegador

En Chrome: F12 > Red (Network), recargar Análisis CVE y seleccionar la
petición `/api/vulnerabilities/cves/?...`.

En **Timing**, anotar: duración total, Waiting/TTFB y descarga. Si
Waiting/TTFB domina y el comando muestra un tiempo comparable,
la latencia está en Django/PostgreSQL. Si la consulta HTTP termina
rápidamente pero la pantalla tarda, medir la preparación/renderizado React.

No tomar el número de segundos que tarda en desaparecer la palabra
"Cargando..." como medida de duración SQL: incluye el navegador y la red.

## Siguiente decisión tras ver métricas

1. Si `recalculo_indicadores` y sus proyecciones duplicadas dominan,
   compartir por petición las relaciones y decisiones ya calculadas.
2. Si `consultar_inventario` domina por cantidad de SQL, preparar lecturas
   en lote por hardware sin alterar fingerprint/identidades ni auditorías.
3. Si `evaluacion_nvd` domina en CPU, medir distribuciones de tamaños
   de configuraciones NVD antes de introducir caché.
4. Comprobar que el catálogo mantiene una fila por par hardware–CVE,
   filtros, paginación y contadores sin duplicación de CVE oficiales.
5. Guardar mediciones antes/después y ejecutar
   `python manage.py test vulnerabilities --settings=config.settings_test_sqlite`.

Esta entrega incorpora **solo instrumentación y pruebas**, no una
optimización prematura basada en la cifra no desglosada de 8 segundos.
