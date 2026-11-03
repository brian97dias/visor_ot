# Arquitectura y alcance de VISOR OT

## Propósito

Prototipo que mantiene un inventario OT contextualizado: sistemas, hardware, software/firmware instalado, interfaces de red, comunicaciones, asociaciones CPE de NVD y evaluaciones CVE con evidencia. Genera un diagnóstico PDF orientativo. No certifica riesgo calculado ni funcionamiento industrial real.

## Procesos locales

1. **Analizador pasivo FastAPI** (`passive_analyzer/`): recibe capturas PCAP/PCAPNG disponibles en su carpeta configurada; observa tramas y guarda resultados estructurados JSON. Puerto local por defecto 8001.
2. **Backend Django y PostgreSQL** (`web_app/backend/`): inventario, ingesta, conciliación de evidencias, gestión de sistemas y revisión CPE/CVE. Puerto local por defecto 8000.
3. **Worker Django** (`python manage.py run_cpe_worker`): procesa búsquedas NVD en segundo proceso y registra resultados; depende de PostgreSQL para sus bloqueos.
4. **Frontend React/Vite** (`web_app/frontend/`): interfaces de usuario, solicitudes al backend y descarga de informes. Puerto local predeterminado 5173.

## Evidencia de comunicaciones

- Para TCP, el analizador orienta cliente/servidor cuando observa SYN; cuando no, intenta inferirlo por puertos conocidos. La etiqueta de servicio basada en un puerto no verifica el protocolo real de aplicación.
- Para UDP, el analizador requiere correspondencia con puertos configurados.
- La evidencia ARP permite asociar IP y MAC; la atribución a un equipo inventariado requiere una asociación verificada de su interfaz.
- Las tramas **PROFINET RT Ethernet 0x8892** representativas pueden normalizarse como `ETHERNET/0` únicamente con asociación IP/MAC inequívoca observada en la misma captura. No equivale a decodificación íntegra de PROFINET.
- Las observaciones de varias ingestas pueden consolidarse, sin equiparar cantidad de paquetes a cantidad de comunicaciones únicas.
- Las etiquetas **AUTORIZADA / NO_AUTORIZADA / NO_CLASIFICADA** responden a la política adoptada por el analista, no se infieren de una conexión por sí sola.

## Validación de laboratorio

Los dos sistemas simulados son «Sistema de preparación y mezcla» y «Sistema de transferencia y envasado». El generador PCAP documenta topología, interfaces y flujos en [su carpeta](../visor_ot_simulacion_pcap/). Estos datos son sintéticos, aunque algunas denominaciones industriales y referencias de vulnerabilidad remitan a catálogos reales.

El inventario y las decisiones CPE/CVE deben revisarse como resultados de una simulación contextualizada; la existencia de un CPE no prueba por sí sola la vulnerabilidad de un dispositivo real. Cualquier conclusión de aplicabilidad exige comprobar producto, versión, condiciones del aviso y contexto de exposición.
