# Laboratorio sintético de comunicaciones OT

Este directorio permite reproducir un ejercicio controlado de VISOR OT para dos sistemas simulados: **preparación y mezcla** y **transferencia y envasado**.

## Archivos

- `generar_pcaps_visor_ot.py`: construye offline dos capturas PCAP Ethernet con ARP, TCP y PROFINET RT representativo. Utiliza la biblioteca estándar; **no transmite paquetes ni hace escaneos**.
- `visor_ot_asociaciones_interfaces.tsv`: inventario técnico de 12 hardware con IPv4 y MAC de una interfaz por equipo y relaciones de software/sistemas.
- `visor_ot_baseline_comunicaciones.tsv`: matriz de flujos TCP y clasificación **propuesta por el analista**.

## Generar las capturas

Desde la raíz del repositorio:

```bash
python3 visor_ot_simulacion_pcap/generar_pcaps_visor_ot.py --output passive_analyzer/pcaps/demo
```

Crea:

- `visor_ot_demo_dia1_operacion.pcap`: tráfico de operación base.
- `visor_ot_demo_dia2_operacion_y_nuevos_flujos.pcap`: tráfico base y conexiones nuevas, entre ellas origen externo a OT.

Los PCAP se ignoran por Git en el flujo habitual; pueden regenerarse con el script. Los mismos nombres se mantienen entre días para que VISOR OT pueda consolidar varias ingestas.

## Validación e interpretación

Con FastAPI iniciado, analizar ambos archivos y confirmar el resultado en «Análisis pasivo». Esperados según el diseño: **12 interfaces por día**, **12 comunicaciones el día 1** (10 TCP + 2 PROFINET RT) y **16 el día 2** (14 TCP + 2 PROFINET RT). Las cantidades son una expectativa de laboratorio y requieren verificación efectiva sobre la instalación utilizada.

1. Registrar el inventario de activos y los dos sistemas OT.
2. Importar el PCAP del día 1 y relacionar cada interfaz MAC con el hardware indicado en el TSV.
3. Clasificar las comunicaciones conforme a la política simulada.
4. Importar el día 2, verificar las comunicaciones que reaparecen y las nuevas, y completar la clasificación de estas últimas.

El analizador **no autoriza ni desautoriza automáticamente** una conexión. Las IP/MAC son datos de simulación reutilizados como contexto, no evidencia de identidad de una planta real.

Las limitaciones detalladas de PROFINET, su representación `ETHERNET/0` y las comprobaciones se documentan en [PROFINET_SYNTHETIC_DEMO.md](../passive_analyzer/PROFINET_SYNTHETIC_DEMO.md).

## Evaluación cuantitativa reproducible del analizador pasivo

La evidencia correspondiente al **11 de noviembre de 2026** se organiza junto al generador para conservar la relación entre el conjunto de referencia, el procesamiento y los resultados:

- [`validar_precision_visor_ot.py`](validar_precision_visor_ot.py): compara los resultados del analizador con las IP/MAC y relaciones esperadas de los dos PCAP; identifica VP, FP y FN, precisión, exhaustividad y F1.
- [`evidencias/resultados_precision_2026-11-11.json`](evidencias/resultados_precision_2026-11-11.json): resumen estructurado de la salida de terminal compartida por el autor (revisión `ced47e4608933056fae986f2f9a0a44b853f1c30`). **No es el volcado completo de la opción `--json`**; los campos que no constaban en esa salida no se han inventado.

### Repetir la evaluación

Desde la raíz del repositorio, con el entorno virtual de `passive_analyzer` y Scapy instalado:

```bash
source passive_analyzer/.venv/bin/activate
python visor_ot_simulacion_pcap/validar_precision_visor_ot.py --repo . --json visor_ot_simulacion_pcap/evidencias/validacion_detallada_local.json
```

El script crea los dos PCAP **en un directorio temporal**, ejecuta el analizador pasivo sin enviar tráfico, compara las observaciones y guarda el JSON detallado solicitado. El archivo `validacion_detallada_local.json` es opcional y no necesita versionarse: su `revision_git` reflejará el commit local desde el que se haya ejecutado. Para reproducir exactamente el corte informado en el resumen, comprobar primero la revisión Git indicada allí.

### Resultados del corte documentado

| Indicador | Día 1 | Día 2 |
| --- | ---: | ---: |
| Paquetes generados | 324 | 348 |
| Interfaces esperadas / observadas | 12 / 12 | 12 / 12 |
| Asociaciones ARP correctas | 12 / 12 | 12 / 12 |
| Comunicaciones esperadas / observadas | 12 / 12 | 16 / 16 |
| VP / FP / FN | 12 / 0 / 0 | 16 / 0 / 0 |
| Precisión / exhaustividad / F1 | 100 % / 100 % / 100 % | 100 % / 100 % / 100 % |

Se evaluaron **28 relaciones por jornada agregada**, que incluyen 12 repetidas: el universo combinado tiene **16 relaciones diferentes**. Las etiquetas de servicio y la orientación SYN se comprueban por separado y generan advertencias si difieren de la referencia. Estos resultados corresponden a **un escenario sintético controlado**, no a una muestra independiente de tráfico industrial real, y no acreditan la detección de ataques, vulnerabilidades ni la integridad de una red industrial.

La tesis describe este procedimiento en 3.4 y sus resultados en 4.1; la localización de las evidencias debe referenciarse desde el **Anexo D**.

