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

## Línea base medida (3 de noviembre de 2026)

El operador confirmó con PostgreSQL real:

| Solicitud | Mediana | SQL | Contextos consultados | Filas |
| --- | ---: | ---: | ---: | ---: |
| Catálogo completo | 9955.6 ms | 2310 | 244 | 122 |
| Búsqueda PLC-TRA-01 | 6341.8 ms | 1617 | 170 | 16 |

Las dos ejecuciones del catálogo completo mostraron
`proyeccion_hardware_cve` **dos veces**, con 2174 SQL; el recálculo de
indicadores por sí solo consumía entre 4645 y 4707 ms.

## Corrección de rendimiento aplicada (pendiente de medición local)

Se realizaron **dos optimizaciones sin cambiar los contratos públicos**:

1. La vista proyecta una vez los **todos** CVE completados. El resumen,
   los filtros y las filas paginadas usan `related` y `statuses`
   ya calculados. La búsqueda por nombre de software también usa ese
   mapa en memoria, evitando una tercera proyección.
2. Dentro de esa única proyección, se reutiliza un mapa de evidencias
   **por hardware, exclusivo de la petición**: hardware activo, CPE
   confirmados, instalaciones vigentes y huella de inventario. También
   se utiliza el objeto `Cve` previamente cargado para evitar
   consultar sus configuraciones repetidamente desde PostgreSQL.

No hay caché persistente, caché entre usuarios, reevaluaciones guardadas
ni reglas de aplicabilidad nuevas. La validación del inventario y de la
evidencia sigue haciéndose al empezar **cada petición**; los métodos de
detalle y escritura siguen recibiendo datos frescos.

La cantidad de pasadas de `proyeccion_hardware_cve` debe reducirse
de **2 a 1**. El objetivo es reducir los 2310 SQL observados, pero
**ninguna cifra nueva se considera medida antes de ejecutar el comando
en la máquina del operador**.

Para medir el resultado, repetir exactamente:

```bash
git switch fix/general
git pull --ff-only
python manage.py test \
  vulnerabilities.tests_cve_catalogue_profile \
  vulnerabilities.tests_cve_catalogue_context_rows \
  vulnerabilities.tests_cve_catalogue_http \
  --settings=config.settings_test_sqlite
python manage.py profile_cve_catalogue --username analista-brian --runs 2
python manage.py profile_cve_catalogue --username analista-brian \
  --q PLC-TRA-01 --runs 2
```

### Resultado medido de la primera optimización

El operador ejecutó 48 pruebas de catálogo/perfilador (**OK**) y la suite
de 677 pruebas de vulnerabilidades (**OK**). Con los mismos datos:

| Solicitud | Antes | Después (mediana) | SQL antes/después |
| --- | ---: | ---: | ---: |
| Completo | 9955.6 ms | **3233.0 ms** | 2310 / **581** |
| PLC-TRA-01 | 6341.8 ms | **3557.1 ms** | 1617 / **587** |

Se conservaron 88 CVE, 122 pares evaluados y 16 resultados del filtro.
La proyección pasó de dos llamadas a una. El principal costo que quedó
fue la proyección (aprox. 2.2–2.4 s): 122 evaluaciones NVD (aprox.
1.1 s), 231 SQL para estatus y 122 SQL para software evaluado.

### Segunda optimización: historial de decisiones por lote

Para reducir las consultas remanentes sin cambiar la lógica, se consulta
`AssetCveAssessment` **una sola vez por proyección de catálogo** y
se distribuyen sus registros en memoria por `(cve_id, hardware_id)`,
manteniendo orden descendente por fecha y PK. El mismo conjunto de registros
se utiliza para decidir:

- La correspondencia general revisada por el analista en ese hardware;
- Las decisiones de cada configuración NVD;
- La instalación de software seleccionada para la revisión.

Los endpoints de detalle, escritura y la lectura de vigencia no reciben
historial cacheado, por lo que siguen comprobando el estado actual con
consultas propias. Una nueva petición recarga el historial y las huellas.
No se agregaron migraciones ni se reinterpretaron estados.

El profiler original permanece disponible. Repetir en la máquina del
operador los dos comandos de la sección anterior **después de pasar las
pruebas**. No hay tiempos medidos aún para esta segunda intervención.

La corrección es satisfactoria si mantiene los conteos
88 CVE / 122 evaluaciones y los filtros dan 16 evaluaciones para
PLC-TRA-01 (suponiendo inventario sin cambios), mientras caen el
tiempo, consultas SQL y proyecciones ejecutadas. Si persiste una
latencia considerable, investigar lecturas por evaluación, caché
por hardware y NVD sin alterar las decisiones.

**No se ejecutó Django ni PostgreSQL localmente por el agente**; todas
las pruebas y mediciones requieren la máquina del operador.
