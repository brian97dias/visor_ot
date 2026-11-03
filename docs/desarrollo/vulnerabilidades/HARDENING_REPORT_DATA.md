# VISOR OT — Informe de hardening, fases 2 y 3 (datos)

Estas fases **solo recopilan datos**. No genera PDF, no incorpora una pantalla o API
pública nueva, no ejecuta consultas NVD y no registra evaluaciones CVE.

## Ejecución

Desde `web_app/backend` con el entorno virtual activo:

```bash
python manage.py audit_inventory_integrity
python manage.py preview_hardening_data
python -m json.tool vulnerabilities/output/visor_ot_hardening_data.json > /dev/null
python manage.py test vulnerabilities.tests_hardening_report_data --settings=config.settings_test_sqlite
```

La salida predeterminada se guarda dentro del proyecto en
`web_app/backend/vulnerabilities/output/visor_ot_hardening_data.json`.
La carpeta `output/` se crea automáticamente y está excluida de Git para
evitar versionar datos reales del inventario. El comando acepta `--print-json` (alias compatible: `--stdout`) para
mostrar JSON en terminal y `--output ruta/archivo.json` para elegir una ruta
de salida. No combinar impresión y archivo. `--print-json` es el nombre
principal para no confundir el argumento especial `stdout` de Django
cuando se usa `call_command()` en pruebas.

La función principal es
`vulnerabilities.services.hardening_report_data.collect_hardening_report_data()`.
Devuelve un diccionario de tipos JSON (el timestamp y los decimales se
convierten a texto). No guarda nada en la base de datos.

## Contrato (schema_version: 1)

- `generated_at`: fecha del corte de datos (ISO 8601).
- `scope`: `ACTIVE_INVENTORY`. Se excluyen activos y sistemas archivados,
  instalaciones desvinculadas y sistemas OT sin asociación vigente.
- `summary`: conteos de sistemas, hardware, variantes de software,
  instalaciones, interfaces, CPE confirmados y parejas Hardware–CVE.
- `systems`: sistema, criticidad y su justificación, impacto, IDs de hardware
  activo asociado.
- `hardware`: identificación y clasificación del activo, sistemas activos,
  interfaces registradas, instalaciones actuales y CPE confirmados vigentes.
- `software`: variantes activas, versión registrada, IDs de hardware donde
  está instalado, CPE confirmados vigentes.
- `applicable_vulnerabilities`: exclusivamente parejas Hardware–CVE cuya
  **aplicabilidad contextual efectiva vigente** es `APPLIES`.
- `conditional_vulnerabilities`: parejas Hardware–CVE vigentes con
  `APPLIES_CONDITIONAL`; se reservan para un apéndice, **no** se suman a
  los hallazgos confirmados.
- `communications`: fase 3, máximo tres firmas de mayor volumen observado
  (`packet_count` sumado solo en ingestas `ACTIVE`). Se recuperan por SQL
  antes de resolver extremos, sin cargar todas las comunicaciones en Python.
  Incluye IP, puerto, transporte, servicio, clasificación, fechas y paquetes.
  La resolución de hardware exige evidencia ARP y asociación vigente; no se
  deduce solo por IP. Si una firma tiene más de 1000 observaciones activas,
  conserva las IP y marca la identidad `NOT_EVALUATED_VOLUME` para limitar
  memoria en la resolución. Se trata de un resumen GLOBAL de tráfico, no una
  lista de flujos necesariamente habituales ni de ataques detectados.

Los conteos de `*_hardware_cve_pairs` **no equivalen** a conteos de CVE
únicos: un CVE puede aplicar a varios equipos. Los campos
`distinct_*_cves` cuentan identificadores CVE distintos.

Cada hallazgo conserva: ID CVE, hardware evaluado, criticidad, severidad,
CVSS base, descripción, fechas/fuentes NVD ya almacenadas, procedencia del
veredicto (`SYSTEM` o `ANALYST`), software relacionado con **esa**
evaluación, prueba técnica automática cuando corresponde y justificaciones
de auditorías humanas **vigentes**. Una justificación no se inventa:
si no existe una auditoría manual actual, `justifications` es `[]`.

## Reglas de seguridad semántica

1. Los CPE solo se incorporan con estado `CONFIRMED`, huella de identidad
   coincidente con el activo actual y producto no obsoleto en la base NVD
   local; un CPE encontrado sin confirmar no demuestra vulnerabilidad.
2. Las relaciones candidatas y las auditorías antiguas/no vigentes no son
   hallazgos. Se utiliza la evaluación contextual del catálogo ya existente,
   sin reimplementar el evaluador de versiones.
3. Un software instalado **no** es automáticamente vulnerable. El software
   incluido en cada hallazgo procede de la evidencia concreta de la pareja
   hardware–CVE.
4. Si el inventario activo tiene faltantes, el recolector devuelve un error
   con sus registros. Primero ejecutar
   `python manage.py audit_inventory_integrity`.
5. No se inventan datos de red, versiones, riesgos, medidas implementadas
   ni recomendaciones de hardening. La fase 3 aporta únicamente evidencia
   observada; la redacción y maquetación corresponde al PDF de la fase 4.

**Limitación:** el corte se calcula con lecturas de la base de datos. En estas
fases no se crea una instantánea persistida ni un documento legalmente sellado.
La evidencia refleja el estado disponible al ejecutar el recolector.
