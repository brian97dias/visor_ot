# VISOR OT — Guía rápida para ensayar la sustentación

> Rama: `fix/general`. Este README explica cómo partir del estado **inicio_demo**, completar el recorrido y regresar al inicio tantas veces como haga falta. La documentación detallada está en [DEMO_ESTADOS_RECUPERABLES.md](visor_ot_simulacion_pcap/DEMO_ESTADOS_RECUPERABLES.md).

## 1. Estados y seguridad

| Estado | Ubicación | Propósito |
|---|---|---|
| **Original** | PostgreSQL `visor-ot_db` | Laboratorio íntegro; **no modificar durante la demo**. |
| **Respaldo integral** | `~/visor_ot_resguardos_demo/integral/` | `database.dump` y copia de los JSON originales. |
| **Inicio del demo** | `~/visor_ot_resguardos_demo/inicio_demo/` | Punto de partida restaurable para repetir ensayos; se crea una sola vez después de verificar la preparación. |
| **Trabajo del demo** | PostgreSQL `visor-ot_db_demo` y `~/visor_ot_resguardos_demo/output_activo/` | Aquí se ejecutan las operaciones de prueba. |

**Importante:** `passive_analyzer/output/` es el directorio habitual del repositorio, **no** el output aislado que debe usar FastAPI durante la demostración. Algunos resultados JSON y `.meta.json` históricos están versionados en Git pese al `.gitignore`. No uses `git add -A`, `git restore .`, `git clean` ni hagas commit de esos artefactos sin revisar `git status --short`.

El respaldo integral no incluye los PCAP de `passive_analyzer/pcaps/`. No borres esos archivos: el análisis los necesita.

## 2. Verificar el estado inicial antes de guardarlo

Desde la raíz del repositorio:

```bash
cd ~/Desktop/Tesis/visor_ot
git status --short
source web_app/backend/.venv/bin/activate
source ~/visor_ot_resguardos_demo/activar_demo.sh
echo "$DB_NAME"
echo "$PASSIVE_ANALYZER_OUTPUT_DIR"
```

Esperado: `visor-ot_db_demo` y `~/visor_ot_resguardos_demo/output_activo`.

En la misma terminal:

```bash
cd web_app/backend
python manage.py shell -c '
from django.conf import settings
from assets.models import Asset, Hardware
from ingestion.models import Ingestion
from network.models import Communication
print("Base:", settings.DATABASES["default"]["NAME"])
print("Hardware:", Hardware.objects.count())
print("Activos:", Asset.objects.count())
print("Ingestas:", Ingestion.objects.count())
print("Comunicaciones:", Communication.objects.count())
print("PLC-MEZ-01 registrado:", Asset.objects.filter(name="PLC-MEZ-01").exists())
'
```

**Resultado esperado:** `visor-ot_db_demo`, 11 hardware, 26 activos, 1 ingesta, 12 comunicaciones, `False` para PLC-MEZ-01.

Confirmar el estado de los archivos **aislados**:

```bash
test -f "$PASSIVE_ANALYZER_OUTPUT_DIR/dfa988520c22f876.json" && echo 'Día 1: ANALIZADO'
test ! -f "$PASSIVE_ANALYZER_OUTPUT_DIR/79a181a6fcbbf5ae.json" && echo 'Día 2: PENDIENTE'
```

El PCAP del día 2 continúa presente en `passive_analyzer/pcaps/Simulados/`; su JSON se regenerará en vivo. Si falta el JSON del día 1, **no guardes aún el inicio del demo**: revisa la copia integral.

## 3. Guardar el punto de partida (hacer una sola vez)

Detén Django, worker NVD y FastAPI. Para evitar guardar archivos mientras se escriben, ejecuta el respaldo con los servicios detenidos:

```bash
cd ~/Desktop/Tesis/visor_ot
bash visor_ot_simulacion_pcap/demo.sh guardar-inicio-demo
bash visor_ot_simulacion_pcap/demo.sh estado
```

Debe aparecer `inicio_demo: Guardado`. Este comando no sobrescribe el resguardo previo. Antes de invocarlo, utiliza la versión de `fix/general` que reconoce una terminal con `DB_NAME` terminado en `_demo`.

## 4. Iniciar todos los procesos apuntando al demo

Ejecuta los servicios en **terminales separadas**. Activa las variables **antes** de iniciar cada proceso. Si ya estaba corriendo un servidor con las variables antiguas, detenlo y reinícialo.

**Terminal A — FastAPI (puerto 8001)**

```bash
cd ~/Desktop/Tesis/visor_ot/passive_analyzer
source .venv/bin/activate
source ~/visor_ot_resguardos_demo/activar_demo.sh
python -m uvicorn api:app --host 127.0.0.1 --port 8001
```

**Terminal B — Backend Django (puerto 8000)**

```bash
cd ~/Desktop/Tesis/visor_ot/web_app/backend
source .venv/bin/activate
source ~/visor_ot_resguardos_demo/activar_demo.sh
python manage.py runserver 127.0.0.1:8000
```

**Terminal C — Worker NVD**

```bash
cd ~/Desktop/Tesis/visor_ot/web_app/backend
source .venv/bin/activate
source ~/visor_ot_resguardos_demo/activar_demo.sh
python manage.py run_cpe_worker
```

**Terminal D — Frontend React (puerto 5173)**

```bash
cd ~/Desktop/Tesis/visor_ot/web_app/frontend
npm run dev
```

La interfaz queda en `http://localhost:5173`. Para verificar los PCAP en FastAPI: `http://127.0.0.1:8001/api/v1/pcaps/`. Debe aparecer el día 1 `ANALYZED` y el día 2 `PENDING`.

## 5. Recorrido de ensayo

1. **Operadora Paula:** abrir Inventario e importar una **copia** de `datos_sinteticos.xlsx`, con la celda `id_visor_ot` del hardware PLC-MEZ-01 vacía. Revisar la vista previa y confirmar solamente ese registro. Las otras filas deben coincidir con el inventario o quedar omitidas, según sus datos.
2. **Operadora Paula:** registrar los vínculos manuales del nuevo PLC: firmware `FW-S7-1200-V4.4.0`, interfaz con MAC `00:1c:06:01:d4:23` y sistema OT de preparación y mezcla. El Excel **no** reconstruye automáticamente esas relaciones.
3. **Analista:** en Análisis pasivo, pulsar **Analizar** para el PCAP del día 2 y luego **Importar** la evidencia. Comprobar el cambio de 12 a 16 comunicaciones consolidadas.
4. **Analista:** filtrar por `PLC-MEZ-01`, explicar flujos habituales frente a los nuevos, y clasificar por lo menos una comunicación nueva conforme a la política del laboratorio. No confundir `evidencias=2` con autorización automática.
5. **Analista:** buscar y confirmar el CPE del PLC, revisar CVE candidatas y evaluar su aplicabilidad. Las consultas pueden tardar o reutilizar cachés; **no está garantizado** reproducir el mismo total de CVE del respaldo.
6. **Analista:** generar el PDF de diagnóstico de seguridad y mostrar la matriz de priorización y la ficha del PLC. Si NVD tarda, usar una copia integral del informe como evidencia de respaldo, indicándolo expresamente.

Recomendación: dos perfiles de navegador ya iniciados (operadora y analista), con pestañas separadas.

## 6. Volver AL INICIO DEL DEMO para repetir el ensayo

**Detén Django, FastAPI y el worker NVD antes de restaurar**. Desde la raíz:

```bash
cd ~/Desktop/Tesis/visor_ot
bash visor_ot_simulacion_pcap/demo.sh restaurar-inicio-demo --confirmar
```

Esto restaura `visor-ot_db_demo` **y** reemplaza `~/visor_ot_resguardos_demo/output_activo/` con la copia inicial. La base `visor-ot_db` no se modifica. Después vuelve a iniciar los procesos del apartado 4, con `activar_demo.sh` en sus terminales.

## 7. Recuperar el estado íntegro SOLO EN LA COPIA DEMO

Si deseas investigar cómo estaba el laboratorio antes de retirar el PLC y la segunda ingesta:

```bash
cd ~/Desktop/Tesis/visor_ot
bash visor_ot_simulacion_pcap/demo.sh restaurar-integral-demo --confirmar
```

**No restaura ni sobrescribe `visor-ot_db`: únicamente cambia `visor-ot_db_demo` y el output aislado**. Para volver al escenario parcial, utiliza `restaurar-inicio-demo --confirmar`.

## 8. Notas sobre los JSON, las fechas y Git

- La presencia de `<pcap_id>.json` determina el estado `ANALYZED` de FastAPI. La ingesta Django está en PostgreSQL: borrar un JSON **no elimina** una ingesta existente.
- Reanalizar el mismo PCAP normalmente conserva las marcas de primera y última observación registradas en sus paquetes. Las fechas administrativas de la nueva ingesta y los metadatos de los archivos sí pueden cambiar.
- El día 1 debe seguir **analizado e importado**. El día 2 debe estar **pendiente y no importado** al iniciar.
- Si borraste archivos en `passive_analyzer/output/` del repositorio (en vez del output aislado), el snapshot integral conserva una copia, pero el árbol Git local puede mostrar modificaciones (`M`) o eliminaciones (`D`). **No es necesario restaurar esos archivos originales para ejecutar el demo aislado**. Revisa `git status --short` antes de `git pull` y evita versionar cambios accidentales.
- El archivo `inicio_demo/database.dump` y los JSON derivados no se suben al repositorio: son datos locales de ensayo.

## 9. Si aparece un error

Comprueba primero el valor de `DB_NAME` **en la terminal del proceso que falló**. Debe ser `visor-ot_db_demo`. Conserva la salida del error, detén los servicios y restaura el snapshot inicial si es necesario. No uses `reset_lab_data`, SQL `CASCADE` ni comandos de limpieza general.
