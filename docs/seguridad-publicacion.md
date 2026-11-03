# Lista de revisión antes de publicar VISOR OT

El repositorio se ha desarrollado inicialmente en privado. **Que la copia actual no contenga un archivo `.env` no demuestra que nunca haya existido una credencial en el historial de Git.** Cambiar la visibilidad de un repositorio hace accesibles también sus commits anteriores a quien pueda consultarlos.

## Revisión obligatoria

1. Enumerar archivos rastreados y excluidos: `git ls-files` y `git status --ignored -sb`.
2. Revisar **todas las ramas y el historial**, no solo la rama de entrega: posibles `.env`, tokens, claves Django/NVD, datos de conexión, dumps SQL, capturas domésticas, informes y material personal.
3. Buscar secretos con un analizador especializado si está disponible (p. ej., Gitleaks), revisar los hallazgos y **rotar inmediatamente cualquier credencial que haya estado expuesta**. `.gitignore` no sanea el historial.
4. Revisar `passive_analyzer/output/`: contiene JSON/metaJSON previamente versionados, incluidos resultados de capturas no pertenecientes al escenario final. **Siguen accesibles mientras estén rastreados en la rama publicada**, aunque se hayan añadido reglas al `.gitignore`.
5. Inspeccionar `web_app/backend/vulnerabilities/visor_ot_hardening_data.json` y posibles datos de laboratorio o personas en reportes.
6. Inspeccionar `datos_sinteticos.xlsx` y sus duplicados; no divulgar datos supuestamente sintéticos que en realidad correspondan a personas u organizaciones reales.
7. Revisar el estado de `main` y `fix/general` antes de elegir la URL de entrega. Preferir una rama de entrega verificada, sin modificar historial ni fusionar automáticamente.

## Decisión sobre artefactos versionados

Se han conservado los archivos rastreados existentes para respetar la preferencia del autor de **no retirar su historial mediante operaciones destructivas**. Las nuevas reglas de `.gitignore` evitan añadir resultados nuevos no rastreados, pero **no ocultan, no desvinculan y no eliminan los resultados que ya estén en Git**. Esta decisión deja una revisión de privacidad pendiente antes de hacer público el repositorio.

Para entregar académicamente sin exposición pública, puede compartirse la URL a una rama concreta y concederse acceso a los evaluadores según la política institucional.

## Configuración local

La plantilla `web_app/backend/.env.example` contiene únicamente marcadores de posición; las credenciales reales deben existir solo en el `.env` local. El backend conserva `DEBUG=True` y configuración de desarrollo; **no exponer el servidor a Internet** sin una revisión y configuración de seguridad separadas.
