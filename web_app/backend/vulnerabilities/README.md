# Módulo de vulnerabilidades de VISOR OT

Este módulo implementa la identificación de candidatos **CPE** para activos OT, el registro de decisiones del analista, la consulta y almacenamiento de **CVE** desde NVD, la evaluación de aplicabilidad contextualizada y la generación de informes de diagnóstico PDF.

## Flujo general

1. El inventario (`assets`) conserva fabricante, modelo, CPU cuando aplica, software, firmware y versiones, así como las asociaciones hardware/software y sistemas OT.
2. Las búsquedas NVD se encolan y procesan mediante `python manage.py run_cpe_worker`. Los CPE candidatos no equivalen a CPE confirmados.
3. El analista confirma o rechaza asociaciones; la identidad del activo puede cambiar, y el estado de evidencia debe reevaluarse cuando corresponda.
4. La evaluación CVE diferencia correspondencias automáticas, condiciones que requieren contexto y decisiones humanas; debe respetar versiones y configuraciones NVD.
5. Los informes presentan hallazgos y prioridades **orientativas**, sin afirmar explotación, riesgo cuantitativo ni cumplimiento certificado.

## Ejecución

Las dependencias, PostgreSQL, entorno de desarrollo, worker y comandos de pruebas se documentan en el [README principal](../../../README.md) y [guía de pruebas](../../../docs/pruebas.md).

## Historial de implementación

Los documentos de fases, regresiones, rendimiento y el antiguo README detallado se han archivado **sin eliminar su contenido**, en [docs/desarrollo/vulnerabilidades](../../../docs/desarrollo/vulnerabilidades/). El documento antiguo representa una fotografía histórica de su fase; no debe usarse para afirmar que CVE o hardening continúan pendientes.

Para las definiciones vigentes prevalecen los modelos, servicios, vistas, migraciones y pruebas del código actual.
