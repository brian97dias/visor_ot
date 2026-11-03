# VISOR OT — Regla delimitada Siemens 1214C (CVE-2021-44695)

## Incidencia reproducida

Hardware: `PLC-MEZ-01`, CPU 1214C con CPE de hardware confirmado.
Firmware instalado: `FW-S7-1200-V4.4.0`, versión inventariada `4.4.0`.
CPE oficial NVD confirmado para el software:
`cpe:2.3:o:siemens:s7-1200_cpu_1214c_firmware:-:*:*:*:*:*:*:*`.
La configuración 6 del CVE exige:
`cpe:2.3:o:siemens:simatic_s7-1200_cpu_1214c_firmware:*:*:*:*:*:*:*:*`,
con `versionEndExcluding: 4.6.0`, más el CPE de hardware 1214C.

El comprobador era estricto en el identificador `product`, por lo que
marcaba `INDETERMINATE` **antes** de comparar `4.4.0 < 4.6.0`.
El analista tampoco veía un firmware elegible para confirmar, porque la
proyección técnica no encontraba una correspondencia CPE exacta.

## Regla implementada

Solo se admite esta equivalencia de productos CPE concretos:

- Criterio NVD: `siemens:simatic_s7-1200_cpu_1214c_firmware:*`
- CPE confirmado de inventario:
  `siemens:s7-1200_cpu_1214c_firmware:-`

Y solo si **también** se confirma el CPE exacto del hardware:
`cpe:2.3:h:siemens:simatic_s7-1200_cpu_1214c:-:*:*:*:*:*:*:*`.

El guion `-` de la versión del CPE confirmado es **NA, no ANY**.
La identidad del producto se acredita mediante la regla explícita y
la versión `4.4.0` proviene de un campo **independiente del inventario**,
cuya precisión numérica se compara con las restricciones NVD originales.

No se normalizan libremente prefijos `simatic_`, nombres parecidos ni
otros modelos Siemens. La regla no se aplica si faltan CPE confirmados,
la CPU es otra, los componentes CPE son diferentes o la versión no es
numérica. No se alteran datos NVD ni se insertan CPE inventados.

Las observaciones técnicas incluyen
`identity_basis=CURATED_SIEMENS_1214C_FIRMWARE_PRODUCT_EQUIVALENCE`.
El detalle del CVE presenta la distinción entre coincidencia literal y
equivalencia específica para mantener la trazabilidad.

Referencias oficiales:

- Diccionario CPE NVD para la variante sin SIMATIC:
  https://nvd.nist.gov/products/cpe/detail/696056
- Configuración 6 del CVE:
  https://nvd.nist.gov/vuln/detail/CVE-2021-44695

## Flujo de revisión

La casilla `Seleccionar software para esta evaluación` **no equivale
a acreditar automáticamente su identidad**. Si se selecciona una
instalación aún no verificada, el botón pasa a `Revisar correspondencia`;
el resultado permitido continúa siendo condicionado hasta contar con
evidencia suficiente. Cuando el backend demuestra la combinación completa
de plataforma, producto y versión, el estado esperado es
`APPLIES` con origen `SYSTEM` y el usuario no necesita confirmar.

## Pruebas y verificación local

Desde `web_app/backend`:

```bash
git switch fix/general
git pull --ff-only
python manage.py test vulnerabilities.tests_cve_configuration_evaluator \
  vulnerabilities.tests_cve_contextualization \
  vulnerabilities.tests_cve_general_assessment \
  --settings=config.settings_test_sqlite
python manage.py test vulnerabilities --settings=config.settings_test_sqlite
```

Desde `web_app/frontend`:

```bash
npm run test:unit
npm run lint
npm run build
```

Verificación real sin alterar la base de datos:

```bash
python manage.py shell -c '
from vulnerabilities.services.cve_general_assessment import general_assessment_context
c = general_assessment_context("CVE-2021-44695", 1)
cfg = next(x for x in c["configurations"] if x["position"] == 6)
print(c["applicability"])
print(cfg["technical_result"])
print(cfg["candidate_installation_ids"])
'
```

Con los CPE vigentes mencionados y la versión 4.4.0, se espera
`APPLIES`, origen `SYSTEM`, configuración 6 `COMPATIBLE` y una
instalación seleccionable automáticamente. Abrir la pantalla CVE como
analista puede sincronizar una auditoría automática pendiente mediante
el POST existente; las consultas del shell son solo lectura.

**Límite de interpretación:** el resultado automático está soportado
por el *inventario declarado* y las identidades CPE confirmadas por un
analista. No verifica remotamente la versión real del PLC.
