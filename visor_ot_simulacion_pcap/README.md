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
