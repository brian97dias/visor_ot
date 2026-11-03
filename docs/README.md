# Documentación de VISOR OT

Este directorio separa las instrucciones vigentes para reproducir el prototipo de las notas históricas que registraron su evolución.

## Documentación vigente

- [Arquitectura y límites](arquitectura.md): módulos, responsabilidades y alcance de captura pasiva.
- [Pruebas y verificación](pruebas.md): cómo ejecutar los tests sin reorganizar sus importaciones.
- [Revisión previa a publicar](seguridad-publicacion.md): comprobaciones de información sensible, artefactos y ramas.
- [Guía de laboratorio](../visor_ot_simulacion_pcap/README.md): generación de datos PCAP y política de comunicaciones.

## Registro histórico de implementación

La documentación originalmente dispersa en `web_app/backend/vulnerabilities/` se conserva **sin modificar su contenido** en [`desarrollo/vulnerabilidades/`](desarrollo/vulnerabilidades/). Documenta fases de implementación y decisiones tomadas en momentos anteriores; expresiones como «pendiente» o «no implementado» se refieren a *esa fase*, no necesariamente al estado actual.

Las notas de evolución del inventario y reinicio de laboratorio están en [`desarrollo/assets/`](desarrollo/assets/). El comando `reset_lab_data` es **destructivo** y no debe ejecutarse en una base real ni en la base de presentación sin respaldo y comprobación explícita.

Los archivos de tests siguen junto a sus aplicaciones para no romper el descubrimiento y las referencias existentes.
