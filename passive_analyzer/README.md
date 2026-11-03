# VISOR OT — Analizador pasivo

Servicio independiente FastAPI que lee archivos PCAP/PCAPNG disponibles localmente y transforma su evidencia en observaciones de interfaces y comunicaciones, consultables por el backend Django.

El analizador **no transmite tráfico de red** cuando procesa un PCAP; trabaja con capturas offline. No identifica automáticamente la identidad física del activo ni determina si una conexión está autorizada.

## Preparación local

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m uvicorn api:app --reload --host 127.0.0.1 --port 8001
```

La carpeta local `pcaps/` se usa por defecto para descubrir capturas; los resultados se generan en `output/`. Puedes configurar `PASSIVE_ANALYZER_PCAP_DIR` y `PASSIVE_ANALYZER_OUTPUT_DIR` si necesitas ubicaciones distintas. Para usar la API de ingestas, conserva los archivos dentro del directorio configurado de capturas.

También puedes analizar una captura sin servidor:

```bash
python pcap_read.py pcaps/demo/visor_ot_demo_dia1_operacion.pcap
```

## Evidencia

- Ethernet y ARP para interfaces MAC y asociaciones IPv4 observadas.
- TCP/UDP con puertos de servicios conocidos y orientación de conexión cuando existe evidencia.
- Tramas PROFINET RT representativas normalizables cuando la asociación MAC/IP es inequívoca, usando el identificador interno `ETHERNET/0`.
- Un mismo servicio entre extremos se consolida por clave de comunicación; el contador de paquetes no equivale a una cantidad de equipos.

Ver [alcance PROFINET](PROFINET_SYNTHETIC_DEMO.md), [guía del laboratorio sintético](../visor_ot_simulacion_pcap/README.md) y [arquitectura](../docs/arquitectura.md).

## Pruebas

```bash
python -m unittest discover -s . -p 'tests_*.py' -v
```

Los test conservan su ubicación para mantener la ejecución y los imports actuales. La carpeta `output/` es un artefacto generado: algunos archivos antiguos aún están rastreados por Git y no deben confundirse con resultados de la validación final.
