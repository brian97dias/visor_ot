# VISOR OT — Estados recuperables para la sustentacion

Estos scripts se diseñaron para \`fix/general\` y PostgreSQL local. NO han
sido ejecutados contra el equipo del autor desde GitHub. Haz la primera
ejecucion con el worker detenido y lee todas las vistas previas.

## Qué se conserva

- **Integral:** la base PostgreSQL completa que ya tienes y una copia de
  \`passive_analyzer/output/\`. El script **no restaura ni borra** esa base.
- **Inicio del demo:** otra base PostgreSQL, terminada en \`_demo\`, con
  el PLC-MEZ-01 aun sin registrar y solo la ingesta del dia 1. Tambien tiene
  una salida aislada del analizador, sin el resultado JSON del dia 2.
- **Ensayo:** cambia exclusivamente la base \`_demo\` y la salida aislada.
  \`restaurar-inicio-demo\` permite regresar a la misma situacion inicial.

Los PCAP originales no se borran, no se mueven ni se modifican.
Las capturas se descubren desde \`passive_analyzer/pcaps/\`, o desde
\`PASSIVE_ANALYZER_PCAP_DIR\` si lo configuraste.

ATENCION: los dumps contienen datos y hashes de cuentas. Se almacenan fuera
del repositorio, en \`~/visor_ot_resguardos_demo/\`; no subirlos a GitHub.

## 0. Antes de empezar

Cierra el servidor Django, worker NVD, frontend y FastAPI. En la raiz:

\`\`\`bash
cd ~/Desktop/Tesis/visor_ot
git switch fix/general
git pull
source web_app/backend/.venv/bin/activate
python visor_ot_simulacion_pcap/demo_entornos.py estado
\`\`\`

Se necesitan \`psql\`, \`pg_dump\`, \`pg_restore\` y \`createdb\`
(instala \`postgresql-client\` si no existen). El script obtiene las
credenciales de \`web_app/backend/.env\`, sin imprimir la contraseña.
El usuario de PostgreSQL debe poder conectarse y crear una segunda base;
si no dispone del privilegio \`CREATEDB\`, el administrador de PostgreSQL
debe crear esa base con el mismo propietario.

**No usar** \`reset_lab_data\`: ese comando vacia todas las tablas OT.

## 1. Respaldo integral, SIN borrado (primera operacion recomendada)

\`\`\`bash
python visor_ot_simulacion_pcap/demo_entornos.py resguardar-integral
\`\`\`

Guarda el dump y el directorio de salida original en
\`~/visor_ot_resguardos_demo/integral/\`, junto a un manifiesto
\`manifest.json\` con SHA-256. Nunca lo sobrescribe sin intervencion
manual. Si usas una salida distinta a \`passive_analyzer/output/\`,
puedes dar \`--output-origen /ruta/de/output\`.

## 2. Crear la base de ensayo y la salida separada

\`\`\`bash
python visor_ot_simulacion_pcap/demo_entornos.py crear-demo
source ~/visor_ot_resguardos_demo/activar_demo.sh
echo "$DB_NAME"
echo "$PASSIVE_ANALYZER_OUTPUT_DIR"
\`\`\`

Esperado: el nombre termina en \`_demo\` y el output apunta a
\`~/visor_ot_resguardos_demo/output_activo\`.

Este paso clona el estado INTEGRO: aun contiene ambos dias, 12 hardware
y todas las evaluaciones. No borra la base original.

## 3. Vista previa del recorte (NO modifica datos)

\`\`\`bash
cd ~/Desktop/Tesis/visor_ot/web_app/backend
source .venv/bin/activate
source ~/visor_ot_resguardos_demo/activar_demo.sh
python manage.py preparar_demo_plc_mez --json
\`\`\`

Antes de ejecutar hay que confirmar que la vista previa muestra el
hardware **PLC-MEZ-01**, exactamente las ingestas del dia 1 y del dia 2,
12 y 16 comunicaciones respectivamente, 12 interfaces por dia y cuatro
comunicaciones exclusivas del segundo dia. Si no coincide, DETENTE.

Anota \`day2_pcap_id\`. Es la identidad EXACTA del JSON de FastAPI. El
estado ANALIZADO depende de ese JSON; IMPORTADO depende de PostgreSQL.

## 4. Preparar la base de ensayo y el output aislado

Primero ejecuta esta operacion solamente si revisaste la vista previa.
No lo hagas mientras corre el worker NVD.

\`\`\`bash
python manage.py preparar_demo_plc_mez --execute --confirm PREPARAR_DEMO_PLC_MEZ_01
\`\`\`

Se eliminan SOLO los historiales/relaciones especificos de ese hardware,
y su activo. Se conservan el firmware inventariado, los demas activos,
los sistemas OT y los catalogos CPE/CVE compartidos. Se desvincula su
interfaz observada (conservando la MAC). Se retiran la ingesta del dia 2
y sus cuatro comunicaciones exclusivas. El comando es transaccional:
ante fallos, PostgreSQL revierte toda la operacion.

Después vuelve a la raiz y prepara la salida de FastAPI. Sustituye
\`XXXXXXXXXXXXXXXX\` por \`day2_pcap_id\` de la vista previa.

\`\`\`bash
cd ~/Desktop/Tesis/visor_ot
python visor_ot_simulacion_pcap/preparar_output_demo.py --pcap-id XXXXXXXXXXXXXXXX
python visor_ot_simulacion_pcap/preparar_output_demo.py \
  --pcap-id XXXXXXXXXXXXXXXX --execute --confirm QUITAR_RESULTADO_DIA2
\`\`\`

El script NO toca los PCAP, ni \`passive_analyzer/output/\` original.
Solo retira el JSON y su metadato del dia 2 en \`output_activo\`.
El dia 1 conserva su resultado ANALIZADO y su ingesta IMPORTADA.

## 5. Congelar el estado inicial de la demo

Con los servidores detenidos, ejecuta:

\`\`\`bash
python visor_ot_simulacion_pcap/demo_entornos.py guardar-inicio-demo
\`\`\`

Crea \`~/visor_ot_resguardos_demo/inicio_demo/\` con un nuevo dump y su
output. No permite sobrescribirlo accidentalmente.

Para usar el laboratorio, activa el entorno demo en **cada terminal**
antes de iniciar los procesos correspondientes:

\`\`\`bash
source ~/visor_ot_resguardos_demo/activar_demo.sh
\`\`\`

Luego inicia Django, worker NVD, FastAPI y frontend de la forma habitual.
El frontend no usa PostgreSQL directamente: consulta Django. El worker
SI usa la misma base que Django, por eso debe recibir el mismo \`DB_NAME\`.
FastAPI debe recibir \`PASSIVE_ANALYZER_OUTPUT_DIR\` para leer/escribir
exclusivamente la salida aislada.

## 6. Volver a ensayar desde cero

Cierra Django, worker NVD y FastAPI antes de restaurar.

\`\`\`bash
cd ~/Desktop/Tesis/visor_ot
source web_app/backend/.venv/bin/activate
python visor_ot_simulacion_pcap/demo_entornos.py restaurar-inicio-demo --confirmar
\`\`\`

Devuelve el dump del estado inicial y su output. Usa siempre la base
\`_demo\`, nunca la original. Después vuelve a activar el entorno demo
en las terminales antes de iniciar los servicios.

## 7. Si algo sale mal: restaurar TODO, pero en la base demo

\`\`\`bash
python visor_ot_simulacion_pcap/demo_entornos.py restaurar-integral-demo --confirmar
\`\`\`

Con esto, **la base demo** vuelve a tener los 12 equipos, sus relaciones,
sus 122 evaluaciones y las dos ingestas (segun el estado integral
respaldado). La base original sigue intacta y se conserva el resguardo
integral. Para recuperar el escenario parcial vuelve a los pasos 3–5
(la snapshot \`inicio_demo\` es mas rapida cuando ya exista).

## 8. Dos detalles importantes del ensayo

**Importacion Excel:** si exportaste el inventario antes de quitar el
PLC, la fila del PLC contiene su ID anterior. Borra SOLO la celda
\`id_visor_ot\` de esa fila en una COPIA del Excel; si la dejas, el
importador mostrara que ese ID ya no existe. No cambies los IDs de
los demas registros. La importacion no reconstruye por si misma
las instalaciones de software, asociaciones de interfaces o
sistemas OT: esas se muestran manualmente con Paula.

**Consultas NVD:** el script conserva CPE y CVE del catalogo compartido.
Una busqueda nueva puede reutilizar caché, tardar, o devolver datos
actualizados. Que se confirme de nuevo el CPE y se evalúen todas las CVE
del PLC requiere ensayar con el worker activo. No prometas recuperar
automaticamente el mismo diagnostico sin esa comprobacion.

## Si un comando falla

Detente y copia el error completo de la terminal. No uses SQL \`CASCADE\`
manualmente ni modifiques \`.env\` para apuntar la base original a la demo.
Los scripts tienen guardas precisamente para prevenir perdida de datos.
