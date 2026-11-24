# VISOR OT — Ensayo reproducible de la sustentación

**Guía operativa específica de la demo.** El `README.md` principal del proyecto no se modifica para documentar este procedimiento.

## 1. Dos elementos independientes

- **Django + worker NVD:** utilizan la base clonada `visor-ot_db_demo` mediante `source ~/visor_ot_resguardos_demo/activar_demo.sh`.
- **Analizador FastAPI:** utiliza el directorio **habitual** `passive_analyzer/output/`. **No** ejecutes `activar_demo.sh` en la terminal de FastAPI. Al borrar un análisis se quita su estado `ANALYZED`, pero NO su ingesta histórica en PostgreSQL.
- **Frontend React:** no requiere activar las variables de PostgreSQL; habla con Django.
- **Base íntegra:** `visor-ot_db`, intacta. El backup creado previamente sigue en `~/visor_ot_resguardos_demo/integral/`. No volver a ejecutar `reset_lab_data`.

**Nota:** la herramienta histórica `demo_entornos.py` maneja también un `output_activo` aislado; **este recorrido simplificado no utiliza esa salida**. Para repetir la demo, utiliza `demo_bd.py`, que guarda y restaura **solo PostgreSQL**.

## 2. Antes de guardar el punto inicial

Asegúrate de tener la preparación selectiva ya ejecutada, con estos resultados en la **base demo**:

| Dato | Inicio |
|---|---|
| Hardware | 11 |
| Activos | 26 |
| Ingestas | 1 (día 1) |
| Comunicaciones | 12 |
| PLC-MEZ-01 | Sin registrar |
| PCAP día 1 | Analizado e importado |
| PCAP día 2 | Pendiente de analizar |

Para comprobar Django, desde la raíz:

```bash
cd ~/Desktop/Tesis/visor_ot
source web_app/backend/.venv/bin/activate
source ~/visor_ot_resguardos_demo/activar_demo.sh
cd web_app/backend
python manage.py shell -c '
from django.conf import settings
from assets.models import Hardware, Asset
from ingestion.models import Ingestion
from network.models import Communication
print("Base:", settings.DATABASES["default"]["NAME"])
print("Hardware:", Hardware.objects.count())
print("Activos:", Asset.objects.count())
print("Ingestas:", Ingestion.objects.count())
print("Comunicaciones:", Communication.objects.count())
print("PLC-MEZ-01:", Asset.objects.filter(name="PLC-MEZ-01").exists())
'
```

Esperado: `visor-ot_db_demo`, 11, 26, 1, 12, `False`.

En **VS Code**, deja `passive_analyzer/output/dfa988520c22f876.json` (día 1). Para el día 2 elimina solo `79a181a6fcbbf5ae.json` y `79a181a6fcbbf5ae.meta.json`, si existen. No borres los PCAP. El archivo `dfa988520c22f876.meta.json` del día 1 puede conservarse: si falta, el analizador lo recrea al consultar el hash.

## 3. Guardar el inicio de la demo UNA sola vez

Detén Django y el worker NVD para obtener una instantánea consistente. Desde la raíz, con el entorno Python del backend activado y `DB_NAME=visor-ot_db_demo`:

```bash
cd ~/Desktop/Tesis/visor_ot
web_app/backend/.venv/bin/python visor_ot_simulacion_pcap/demo_bd.py estado
web_app/backend/.venv/bin/python visor_ot_simulacion_pcap/demo_bd.py guardar
```

Se crea `~/visor_ot_resguardos_demo/inicio_demo_bd/database.dump` junto con su `manifest.json` SHA-256.

**Qué guardamos:** todo PostgreSQL de la demo (inventario, relaciones, usuarios, ingestas, CPE/CVE, evaluaciones). **Qué NO guardamos aquí:** los JSON de FastAPI, PCAP y archivos de código. Esos se gestionan aparte. El respaldo no se sobrescribe accidentalmente.

## 4. Iniciar los procesos para el ensayo

Inicia cada proceso desde una terminal diferente. Si ya estaba ejecutándose, deténlo y arráncalo de nuevo para aplicar las variables correctas.

**Terminal A — FastAPI en modo habitual**, sin `activar_demo.sh`:

```bash
cd ~/Desktop/Tesis/visor_ot/passive_analyzer
source .venv/bin/activate
unset PASSIVE_ANALYZER_OUTPUT_DIR
python -m uvicorn api:app --host 127.0.0.1 --port 8001
```

**Terminal B — Backend Django (base demo)**:

```bash
cd ~/Desktop/Tesis/visor_ot/web_app/backend
source .venv/bin/activate
source ~/visor_ot_resguardos_demo/activar_demo.sh
python manage.py runserver 127.0.0.1:8000
```

**Terminal C — Worker NVD (misma base demo)**:

```bash
cd ~/Desktop/Tesis/visor_ot/web_app/backend
source .venv/bin/activate
source ~/visor_ot_resguardos_demo/activar_demo.sh
python manage.py run_cpe_worker
```

**Terminal D — React**:

```bash
cd ~/Desktop/Tesis/visor_ot/web_app/frontend
npm run dev
```

Interfaz: http://localhost:5173. Consulta directa de estado FastAPI: http://127.0.0.1:8001/api/v1/pcaps/.

**Precaución:** si abres la terminal de FastAPI desde una terminal que ya tenía `source activar_demo.sh`, `unset PASSIVE_ANALYZER_OUTPUT_DIR` garantiza que vuelva a `passive_analyzer/output/`. FastAPI toma este valor al iniciar el proceso.

## 5. Recorrido previsto

1. **Paula (operadora):** importa **una copia** de `datos_sinteticos.xlsx` con la celda `id_visor_ot` vacía únicamente en la fila de PLC-MEZ-01. Asegúrate de que sea el único hardware nuevo. El firmware del PLC sigue inventariado.
2. **Paula:** vincula manualmente firmware `FW-S7-1200-V4.4.0`, interfaz MAC `00:1c:06:01:d4:23` y Sistema de preparación y mezcla.
3. **Analista:** analiza e importa el PCAP del día 2. El resultado esperado pasa de 12 a 16 comunicaciones consolidadas.
4. **Analista:** filtra las comunicaciones del PLC, distingue las observadas en ambas jornadas de las nuevas y clasifica alguna de ellas. El estado de autorización requiere decisión humana.
5. **Analista:** busca y confirma CPE del PLC; consulta CVE y muestra ejemplos de aplicabilidad automática y revisión del analista. NVD puede tardar, cambiar resultados o utilizar caché.
6. **Analista:** genera y revisa el diagnóstico de seguridad. El informe original íntegro puede utilizarse como respaldo si NVD no responde.

## 6. Repetir el ensayo: volver al inicio

**Detén Django y worker NVD antes de restaurar** (por precaución, también FastAPI mientras preparas los JSON).

```bash
cd ~/Desktop/Tesis/visor_ot
source web_app/backend/.venv/bin/activate
source ~/visor_ot_resguardos_demo/activar_demo.sh
web_app/backend/.venv/bin/python visor_ot_simulacion_pcap/demo_bd.py restaurar --confirmar
```

**Qué hace:** recupera únicamente el punto guardado en `visor-ot_db_demo`. No cambia la base original, ni los PCAP, ni el directorio `passive_analyzer/output/`.

**Después, en VS Code:** elimina `79a181a6fcbbf5ae.json` y `79a181a6fcbbf5ae.meta.json` del analizador para que el día 2 vuelva a aparecer **Pendiente**. Conserva el JSON del día 1. Vuelve a iniciar los procesos del apartado 4.

## 7. Git y los JSON

`.gitignore` ya contiene `/passive_analyzer/output/`. Los antiguos JSON permanecían seguidos porque estaban añadidos al índice antes de introducir esa regla. El commit de limpieza los retira **del repositorio**, no representa una orden para borrarlos de tu entorno. Sin embargo, **un `git pull` puede borrar o entrar en conflicto con archivos que antes eran seguidos**, por lo que conviene respaldarlos antes de actualizar:

```bash
cd ~/Desktop/Tesis/visor_ot
mkdir -p ~/visor_ot_resguardos_demo/output_local_pre_git
cp -a passive_analyzer/output/. ~/visor_ot_resguardos_demo/output_local_pre_git/
git status --short
```

Si hay cambios en `output/` y no puedes hacer `git pull`, guarda temporalmente los cambios seguidos con `git stash push -m "salida local analizador" -- passive_analyzer/output`, actualiza la rama y **recupera los archivos desde la copia `output_local_pre_git`**, no mediante `git stash pop` (los archivos ya no estarán seguidos). Inspecciona los otros cambios antes de cualquier actualización; no utilices `git reset --hard`.

Comprobación posterior: `git ls-files passive_analyzer/output` debe mostrar **cero archivos**. A partir de entonces crear o borrar JSON no debería producir marcas `M` o `D`.

**Nunca subas a GitHub los dumps de PostgreSQL.** Tampoco uses `reset_lab_data` o `DELETE CASCADE` para preparar ensayos.
