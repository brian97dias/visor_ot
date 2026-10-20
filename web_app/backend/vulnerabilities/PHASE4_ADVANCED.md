# Fase 4 — búsquedas CPE avanzadas (hardware)

El descubrimiento automático SPECIFIC/BROAD y la búsqueda masiva no cambian.
Nuevo endpoint (ADMIN/ANALYST): POST /api/vulnerabilities/assets/{id}/cpe-searches/advanced/

Ejemplo JSON:
{"strategy":"cpeMatchString","parameter":"cpe:2.3:h:rockwellautomation:1783*","start_index":100,"max_pages":2}

Admite keywordSearch o cpeMatchString como estrategia. Las palabras clave
(3–120 caracteres) deben contener el fabricante o un término reconocible.
cpeMatchString debe usar tipo hardware (h) y un alias conocido del fabricante.
URLs, fabricantes ajenos, versiones CPE arbitrarias y software se rechazan.

start_index es múltiplo de 100 (0–10000). max_pages es 1–3. La UI muestra
página inicial 1–101 y entre una y tres páginas por búsqueda, con 100 registros
por página. Un offset positivo siempre representa exploración parcial;
si quedan más resultados, se registra ADVANCED_PAGE_LIMIT.

La petición HTTP solo crea un trabajo CpeSearchRun con trigger ADVANCED y
queries[0] en estado PLANNED. Los trabajos se ejecutan por el mismo worker
PostgreSQL y PublicNvdPacer que las búsquedas automáticas, en cola y con
las mismas medidas de control de frecuencia NVD. No se cambian modelos
ni migraciones. Un trabajo avanzado solo reutiliza otro avanzado idéntico
si sigue QUEUED o RUNNING. Una consulta automática nunca reutiliza la
solicitud avanzada y viceversa.

Los resultados se filtran contra la identidad técnica inventariada;
no se confirma ningún CPE de manera automática. Cada consulta almacena
páginas, cantidad recibida, descartes, coincidencias, errores, offset y límites.
Las búsquedas históricas siguen siendo interpretables.

Se incorporaron 15 pruebas Django con respuestas NVD simuladas y
una prueba adicional de URLs frontend respetando start_index.

Verificaciones desde backend:
python manage.py check
python manage.py makemigrations --check --dry-run
python manage.py test vulnerabilities --settings=config.settings_test_sqlite

Verificaciones desde frontend:
npm run test:unit
npm run build

Prueba funcional: Rockwell, keywordSearch=Rockwell, página 1, 1 página;
después cpeMatchString=cpe:2.3:h:rockwellautomation:1783*, página 2.
Comprueba procedencia ADVANCED, indicadores de parcialidad y vínculos NVD.
El worker debe estar activo para ejecutar lo que se encoló.

La fase 5 (refs oficiales NVD) y la identificación CPE de software
permanecen pendientes.
