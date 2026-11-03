# VISOR OT — captura sintética PROFINET RT, S7 y TCP

## Alcance

Se mantiene el contrato de importación existente, `schema_version: 0.2`.
No es necesario modificar tablas, reimportar inventario ni regenerar los PCAP
que entregó el usuario. La clasificación AUTORIZADA/NO_AUTORIZADA no se
infirió del paquete y sigue correspondiendo al analista.

La lectura nueva reconoce tramas Ethernet `0x8892` con FrameID RT clase 1
en `0x8000..0xBBFF`. Es una **identificación representativa de tramas
PROFINET RT**, no decodificación completa de PROFINET ni verificación de
un controlador real. DCP, PTCP, multicast y otras modalidades no quedan
automáticamente normalizadas en el alcance actual.

### ¿Cómo entra PROFINET a la base de datos IP?

PROFINET RT no contiene IP ni puerto TCP/UDP en estas tramas. VISOR OT
solamente registra la comunicación cuando existe una correspondencia
**única** de MAC→IPv4 *en la misma captura* por ARP y la inversa
IPv4→MAC tampoco es ambigua. Si falta evidencia ARP o hay colisión,
la interfaz Ethernet puede seguir observándose, pero **no se inventa una
comunicación IP ni una identidad del activo**.

- `transport_protocol = "ETHERNET"`
- `service_port = 0` como **sentinela interno: no existe puerto**
- `service = "PROFINET RT"`
- `role_source = "ethernet_first_observed"`
- `client_ip/server_ip` mantienen el orden de la primera trama observada;
  **no indican roles reales cliente/servidor/PLC/dispositivo**.
- Se agregan ambos sentidos de la misma pareja de MAC en una comunicación
  por captura, con contador de paquetes conjunto.
- La resolución del nombre del hardware **sigue exigiendo** una asociación
  manual de la interfaz observada en el inventario, no se deduce del PCAP.

El sistema existente puede importar `ETHERNET/0` y consolidar
independientemente de `TCP/102`, `TCP/502`, etc. En React se muestra
«ETHERNET (sin puerto)», y «No aplica (Ethernet)» en el detalle.

En TCP se etiquetan puertos 22, 23, 80 y 443 como SSH, Telnet, HTTP,
HTTPS. Son etiquetas **inferidas a partir del puerto**, no una
afirmación de descifrado TLS, inicio de sesión ni protocolo completo.
No se asigna autorización automáticamente. S7/102 y Modbus/TCP/502
continúan sin cambios.

## Validación independiente de los PCAP adjuntos

Se leyó la estructura PCAP y el encabezado Ethernet con biblioteca
estándar (no con Scapy/Django). La aplicación completa requiere ejecutar
las pruebas en el equipo del operador.

| Evidencia | Día 1 | Día 2 |
| --- | ---: | ---: |
| Paquetes PCAP | 324 | 348 |
| ARP | 24 | 24 |
| PROFINET RT clase 1 | 64 | 64 |
| Flujos TCP distintos (SYN) | 10 | 14 |
| Pares PROFINET bidireccionales | 2 | 2 |
| **Comunicaciones totales esperadas** | **12** | **16** |
| Interfaces ARP únicas | 12 | 12 |

Pares PROFINET (ambos PCAP), cada uno con 32 paquetes:

- `192.168.88.30 ↔ 192.168.88.20` → PLC-MEZ-01 ↔ IO-MEZ-01
- `192.168.88.85 ↔ 192.168.88.105` → PLC-ENV-01 ↔ IO-ENV-01

Los nombres anteriores proceden de
`visor_ot_asociaciones_interfaces.tsv`, **no de inferencia del PCAP**.

Día 1: diez TCP regulares, más dos pares PROFINET.
Día 2: catorce TCP (once autorizables por política, tres conexiones
nuevas desde 192.168.2.64 con estado propuesto NO_AUTORIZADA), más dos
pares PROFINET. Al importar dos PCAP la consolidación combina las
observaciones del mismo servicio a través de ingestas activas. No
confundir 12+16 observaciones por día con 28 comunicaciones únicas
del inventario: 12 son repetidas, cuatro son nuevas en el segundo día.

**La política TSV no incluye las dos parejas PROFINET**: deben
clasificarse manualmente, si la política real de la simulación
las autoriza, y no asumir autorización por el protocolo.

## Comprobación antes de importar

Con el entorno donde está instalado Scapy:

```bash
cd ~/Desktop/Tesis/visor_ot/passive_analyzer
python -m unittest tests_profinet -v
```

Si tus archivos ya están bajo `pcaps/demo/`:

```bash
python pcap_read.py pcaps/demo/visor_ot_demo_dia1_operacion.pcap
python pcap_read.py pcaps/demo/visor_ot_demo_dia2_operacion_y_nuevos_flujos.pcap
```

Los PCAP pueden conservar los nombres y rutas de tu directorio actual;
adapta las rutas en el comando. No es necesario ejecutar el generador
de nuevo.

En Django, con el backend virtualenv activado:

```bash
cd ~/Desktop/Tesis/visor_ot/web_app/backend
python manage.py test network.tests_profinet_import \
  --settings=config.settings_test_sqlite
python manage.py test network ingestion \
  --settings=config.settings_test_sqlite
```

A continuación, levanta el analizador FastAPI como de costumbre, entra en
**Análisis pasivo** e inspecciona los resultados de los dos PCAP **antes
de importarlos**: deben aparecer 12 interfaces y 12 comunicaciones el
primer día y 12 interfaces y 16 comunicaciones el segundo. Verifica en
la tabla las dos filas PROFINET con servicio y origen/destino resueltos.

Importa primero día 1, asocia MAC↔hardware siguiendo el TSV, clasifica
la política base y luego importa día 2. Las tres conexiones de
`192.168.2.64` se clasifican por el analista; no deben recibir
automáticamente la etiqueta NO_AUTORIZADA.

## Restricciones

- No se generan paquetes, no se transmite tráfico, no se ejecuta
  ningún escaneo en la red.
- No se ha habilitado inferencia para tráfico PROFINET sin ARP inequívoco.
- El identificador `ETHERNET/0` es una adaptación compatible con el
  esquema **actual**, no una representación nativa de puertos de Ethernet.
- PROFINET RT con multicast o sin MAC/IP resolubles queda fuera de esta
  normalización y no debe llevar a una atribución inventada.
- Los paquetes sintéticos no certifican comportamiento completo de un PLC.
- No se ha ejecutado Scapy ni Django sobre la máquina del usuario desde
  este entorno; las pruebas automatizadas se incorporan al repositorio.
