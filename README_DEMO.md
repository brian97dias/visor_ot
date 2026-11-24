# VISOR OT — Comandos rápidos para el demo

**Bases:** `visor-ot_db` = original (intacta); `visor-ot_db_demo` = ensayos.  
**Análisis:** FastAPI usa `passive_analyzer/output/` normal. Restaurar PostgreSQL **no** restaura los JSON.

## 1. Preparar una terminal para administrar la base demo

Desde la raíz del repositorio:

```bash
cd ~/Desktop/Tesis/visor_ot
source web_app/backend/.venv/bin/activate
source ~/visor_ot_resguardos_demo/activar_demo.sh
python visor_ot_simulacion_pcap/demo_bd.py estado
```

**El punto de inicio ya fue guardado** en `~/visor_ot_resguardos_demo/inicio_demo_bd/`. No necesitas ejecutar `guardar` otra vez.

## 2. Restaurar (detén Django y worker NVD antes)

**A. Volver al inicio del demo:** PLC-MEZ-01 sin registrar; 11 hardware, 1 ingesta, 12 comunicaciones.

```bash
cd ~/Desktop/Tesis/visor_ot
source web_app/backend/.venv/bin/activate
source ~/visor_ot_resguardos_demo/activar_demo.sh
python visor_ot_simulacion_pcap/demo_bd.py restaurar --confirmar
```

**B. Recuperar el estado íntegro en la base demo:** 12 hardware, 2 ingestas y 16 comunicaciones.

```bash
cd ~/Desktop/Tesis/visor_ot
source web_app/backend/.venv/bin/activate
source ~/visor_ot_resguardos_demo/activar_demo.sh
python visor_ot_simulacion_pcap/demo_bd.py restaurar-integral --confirmar
```

**Ambos comandos modifican únicamente `visor-ot_db_demo`, NUNCA `visor-ot_db`.** Se restauran desde los respaldos locales; no modifican los JSON de FastAPI. Para regresar del estado íntegro al inicio del demo, ejecuta el comando **A**.

Tras restaurar al inicio, elimina manualmente **solo** los resultados del segundo día en `passive_analyzer/output/`:
- `79a181a6fcbbf5ae.json`
- `79a181a6fcbbf5ae.meta.json`

Conserva `dfa988520c22f876.json` del día 1 y ambos archivos `.pcap` originales.

## 3. Iniciar los servicios (cuatro terminales)

**Terminal 1 — Analizador FastAPI, output normal** (sin activar demo):

```bash
cd ~/Desktop/Tesis/visor_ot/passive_analyzer
source .venv/bin/activate
unset PASSIVE_ANALYZER_OUTPUT_DIR
python -m uvicorn api:app --host 127.0.0.1 --port 8001
```

**Terminal 2 — Django, base demo:**

```bash
cd ~/Desktop/Tesis/visor_ot/web_app/backend
source .venv/bin/activate
source ~/visor_ot_resguardos_demo/activar_demo.sh
python manage.py runserver 127.0.0.1:8000
```

**Terminal 3 — Worker NVD, base demo:**

```bash
cd ~/Desktop/Tesis/visor_ot/web_app/backend
source .venv/bin/activate
source ~/visor_ot_resguardos_demo/activar_demo.sh
python manage.py run_cpe_worker
```

**Terminal 4 — Interfaz React:**

```bash
cd ~/Desktop/Tesis/visor_ot/web_app/frontend
npm run dev
```

Abrir: http://localhost:5173

## 4. Primer ensayo (resumen)

1. **Operadora Paula:** importar una **copia** de `datos_sinteticos.xlsx` con `id_visor_ot` vacío **solo para PLC-MEZ-01**; verificar que sea el único hardware nuevo.
2. Vincular manualmente al PLC su firmware, interfaz MAC `00:1c:06:01:d4:23` y sistema OT.
3. **Analista:** analizar e importar PCAP día 2; comprobar 16 comunicaciones, revisar y clasificar las nuevas.
4. Buscar y confirmar CPE, consultar CVE, revisar aplicabilidad y generar diagnóstico.

**Nota Git:** `passive_analyzer/output/` ya está ignorado; para incorporar el commit que dejó de rastrear los antiguos JSON, haz una copia local de `output/` **antes** del próximo `git pull`. No subas los `database.dump` a GitHub.
