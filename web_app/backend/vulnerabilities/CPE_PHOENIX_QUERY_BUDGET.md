# Incidencia CPE Phoenix Contact IL PN BK-PAC firmware

## Diagnóstico del 3 de noviembre de 2026

Activo #4: `FW-PHX-ILPN-1.13`, fabricante Phoenix Contact, producto
`IL PN BK-PAC Firmware`, versión `1.13`, tipo FIRMWARE.

Síntoma: la búsqueda individual devuelve HTTP 400 `identity` con
`El software genera demasiadas consultas CPE.`. La masiva puede responder
HTTP 200 con `queued=0` y `failed=1`. **En ningún caso se crea**
`CpeSearchRun` ni se ofrece trabajo al worker NVD para el activo #4.

Origen: `build_software_cpe_match_plan()` en `services/identity.py`
generaba un número de consultas mayor que `MAX_CPE_PLAN_QUERIES=30`,
debido a la combinación de las variantes `phoenixcontact`,
`phoenix_contact`, `phoenix-contact`, formas de producto y prefijos.
La validación ocurre en `cpe_search.create_run` ANTES de encolar.
La espera del worker (30 s inicial y al menos 7 s entre consultas)
y los límites de tasa de NVD son un mecanismo diferente.

## Corrección

- Se mantiene **30** como tope; no se aumentan peticiones permitidas.
- Solo al superar el límite, se descartan desde el final consultas
  `BRANCH_PREFIX` cuya misma identidad de fabricante/producto está
  cubierta por una consulta `PRODUCT_CATALOGUE` (`:producto:*`).
- Se conservan las búsquedas de versión exacta, catálogos por producto
  y las consultas finales de fabricante; no se inventan CPE ni se
  confirman coincidencias automáticamente.
- Si la reducción segura no basta, la identidad sigue siendo rechazada.
- La interfaz masiva indica expresamente cuándo **ningún** trabajo
  pudo encolarse y muestra mensajes de error legibles.

**Una respuesta NVD 200 con `totalResults=0` y `products=[]` NO es
sobrecarga**: es un resultado válido para la consulta específica.
El ejecutor de snapshots ya lo trata como `COMPLETED` con cero productos;
la prueba `tests_catalogue.py::test_valid_empty_result_can_complete_without_products`
impide confundirlo con una falla de red.

Referencias: https://nvd.nist.gov/developers/products

## Validación local

```bash
git switch fix/general
git pull --ff-only
cd web_app/backend
python manage.py test \
  vulnerabilities.tests_software_query_plan \
  vulnerabilities.tests_software_http \
  vulnerabilities.tests_bulk \
  vulnerabilities.tests_catalogue \
  --settings=config.settings_test_sqlite
python manage.py test vulnerabilities --settings=config.settings_test_sqlite
```

Consulta sin mutaciones ni red para el activo #4:

```bash
python manage.py shell -c '
from assets.models import Asset
from vulnerabilities.services.identity import software_identity, build_software_cpe_match_plan
asset = Asset.objects.get(pk=4)
plan = build_software_cpe_match_plan(software_identity(asset))
print('Consultas planificadas:', len(plan))
for row in plan: print(row['level'], row['parameter'])
'
```

Debe imprimir `Consultas planificadas: 30` para la identidad indicada.
La prueba HTTP nueva verifica que la solicitud individual obtiene 202
y que una solicitud masiva sobre el mismo trabajo informa `REUSED`.

Después ejecutar `npm run test:unit`, `npm run lint`, `npm run build`
en `web_app/frontend`. En PostgreSQL, probar la búsqueda individual
del activo #4 con el worker activo. Si no hay coincidencias CPE oficiales
tras procesar el plan, el estado legítimo es `Sin resultados`,
y el analista puede investigar por UUID oficial si dispone de él.

IMPORTANTE: que una consulta concreta del catálogo NVD no encuentre CPE
no demuestra que el firmware sea seguro ni que no tenga vulnerabilidades.
