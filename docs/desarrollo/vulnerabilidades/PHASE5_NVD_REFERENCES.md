# Fase 5 — Referencias oficiales incluidas en NVD (hardware)

## Alcance

El motor de búsqueda CPE consulta únicamente NVD, no las páginas externas.
El diccionario CPE de NVD puede devolver refs: [{ref, type}, ...].
Ahora se almacenan de forma limitada y segura como nvd_references en
cada candidato de CpeSearchRun.candidates. Los niveles SPECIFIC, FAMILY,
MANUFACTURER y ADVANCED conservan la misma información.

Cuando un analista CONFIRMA o RECHAZA un CPE, se guarda una copia de
las referencias en Cpe.nvd_references. El FK Cpe.references_source_run
identifica el trabajo NVD del cual se obtuvo esa colección. El mismo
Cpe puede estar asociado a distintos activos; NO se atribuye la
colección del catálogo a una asociación concreta si la fuente real
procede de otra búsqueda. CpeSearchRun.candidates mantiene evidencia
de las búsquedas originales y AssetCpeDecision es append-only.

Cada referencia guarda url, type y source='NVD'. Se preserva el tipo
declarado en NVD y se presenta como Producto, Aviso de seguridad u
Otra referencia, sin clasificar automáticamente la confiabilidad.
La interfaz explica que la inclusión por NVD no verifica el contenido.

Se admiten un máximo de 20 URLs únicas por CPE, de longitud máxima 2048.
Por seguridad se muestran solamente HTTPS a nombres DNS públicos;
se descartan esquemas javascript/data/http, IP literales, URLs con
credenciales, hosts internos/reservados, caracteres de control y
registros inválidos. El frontend valida de nuevo antes de crear enlaces
externos con rel='noopener noreferrer' y target='_blank'.

Una nueva búsqueda con referencias válidas actualiza la copia del
catálogo y su origen, sin alterar las decisiones anteriores. Una
nueva búsqueda sin referencias NO borra enlaces conocidos. Para registros
anteriores a esta fase, la migración establece [] y NULL: no se
inventan referencias ni se descargan automáticamente en segundo plano.

## Migración

vulnerabilities.0004_cpe_nvd_references añade dos campos al modelo Cpe:
- nvd_references: JSONField(default=list, blank=True)
- references_source_run: FK nullable a CpeSearchRun, PROTECT

## Pruebas

Se agregan 14 pruebas Django sin red en tests_references.py:
normalización, unión por UUID, almacenamiento automático y avanzado,
links peligrosos, compatibilidad histórica, persistencia al confirmar,
rechazar, revalidar y deshacer, fuente de procedencia y auditoría.
El frontend agrega 3 pruebas unitarias de URLs y etiquetas.

Desde web_app/backend:
python manage.py migrate
python manage.py check
python manage.py makemigrations --check --dry-run
python manage.py test vulnerabilities --settings=config.settings_test_sqlite

Desde web_app/frontend:
npm run test:unit
npm run build

## Verificación manual

1. Reiniciar run_cpe_worker tras actualizar la rama.
2. Ejecutar búsqueda de Siemens SIMATIC S7-1200 CPU 1215C.
3. Comprobar Product y Advisory en CPE candidatos (si NVD los envía).
4. Confirmar uno; revisar las referencias persistidas en CPE revisados.
5. Revisar que fuente e historial de decisiones siguen disponibles.
6. Revisar un CPE histórico sin refs; debe aparecer sin referencias,
   pero debe conservar su identificación y auditoría.
7. Consultar la URL CPE oficial: su respuesta es en vivo, no un archivo
   de las referencias almacenadas en un trabajo anterior.

Las búsquedas de software y la correlación CVE quedan fuera de esta fase.

## Refinamiento — enlace directo a Product

La interfaz de candidatos y CPE revisados ahora muestra exclusivamente
las entradas cuyo type es Product, con el botón «Ver producto ↗»
que abre la URL exacta que NVD incluye en products[].cpe.refs.

No se muestra Advisory ni otras categorías en esta vista de identidad
técnica. El backend conserva las referencias originales estructuradas
para trazabilidad y para futuras funciones de vulnerabilidades.

Las búsquedas históricas ejecutadas antes de la fase 5 no almacenaban
nvd_references en CpeSearchRun.candidates. Por tanto, un cpeNameId
con referencias en el JSON actual de NVD puede continuar sin Product
en la búsqueda histórica. Hay que ejecutar **una nueva búsqueda**
con el worker actualizado. No se consulta NVD desde el frontend ni en GET.

Para los CPE confirmados o rechazados, GET asociaciones puede obtener
referencias Product desde las últimas diez búsquedas completadas del
mismo activo, comparando exactamente el UUID. De esta forma el analista
no tiene que deshacer ni repetir su decisión. La lectura es de solo
lectura: NO modifica AssetCpe, Cpe ni AssetCpeDecision. Conserva
procedencia con el ID de búsqueda que originalmente obtuvo los enlaces.

Se agregan tres pruebas de regresión para enriquecimiento de asociaciones
históricas, conservación de referencias antiguas y exclusión de UUID
ajenos. React verifica que solamente se presenten URLs Product.

### Verificación

1. Reinicia python manage.py run_cpe_worker después de actualizar.
2. Repite una búsqueda para Advantech ADAM-5000.
3. Verifica ADAM-3600: Producto → Ver producto ↗ cuando NVD devuelve
   una URL Product HTTPS.
4. Repite la búsqueda Siemens SIMATIC S7-1200 CPU 1215C.
5. Verifica que las asociaciones previas del mismo UUID muestren Product
   sin modificar ninguna decisión del historial.
6. CPE Name abre el JSON CPE de NVD, Ver producto abre la URL en refs.
