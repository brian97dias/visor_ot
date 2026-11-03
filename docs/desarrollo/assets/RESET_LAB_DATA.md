# Reiniciar el laboratorio OT sin borrar los usuarios

Comando: `python manage.py reset_lab_data` (rama `fix/general`).
Usar solamente en la base PostgreSQL de desarrollo/laboratorio,
después de realizar un respaldo recuperable.

## Alcance

Se vacían las tablas de Django de `assets`, `network`, `ingestion`
y `vulnerabilities`: sistemas OT, hardware, software, interfaces,
relaciones, instalaciones, ingestas PCAP, observaciones, comunicaciones,
clasificaciones, CPE, CVE, evaluaciones, búsquedas, cachés NVD locales,
historial de importaciones Excel y correcciones de software.

**Se preservan todas las cuentas**, sus contraseñas cifradas, roles e IDs.
También permanecen `auth`, `sessions`, `admin`, `contenttypes`, migraciones
y la estructura PostgreSQL. No se reinician secuencias de usuarios.

El comando ejecuta TRUNCATE RESTART IDENTITY RESTRICT sobre la lista
completa de tablas OT en una sola transacción. Sin CASCADE, si existe
una dependencia externa no cubierta se aborta la operación completa.
Los identificadores autoincrementales OT vuelven al inicio.

NO se borran archivos en disco: PCAP del analizador FastAPI, Excel
locales, JSON y PDF guardados en `vulnerabilities/output/`. Los PCAP
podrían seguir visibles en el analizador aunque no exista una ingesta
correspondiente en PostgreSQL; limpiarlos sería otra operación distinta.

## Respaldo y ejecución segura

1. Detener las escrituras de la aplicación, trabajadores NVD e ingestas.
   Entrar al entorno virtual en `web_app/backend`.
2. Identificar el nombre EXACTO de la base de datos:

```bash
python manage.py shell -c "from django.db import connection; print(connection.settings_dict['NAME'])"
```

3. Vista previa SIN borrado. Muestra la base, las tablas, sus filas y
   cuántos usuarios se conservarán:

```bash
python manage.py reset_lab_data
```

4. Crear y verificar un respaldo con `pg_dump`. Sustituir HOST,
   USUARIO_POSTGRES y NOMBRE_BD por los valores de tu archivo .env:

```bash
mkdir -p ~/Desktop/Tesis/respaldos
pg_dump -h HOST -p 5432 -U USUARIO_POSTGRES -d NOMBRE_BD \
  --format=custom \
  --file="$HOME/Desktop/Tesis/respaldos/visor_ot_antes_de_reset.dump"
test -s "$HOME/Desktop/Tesis/respaldos/visor_ot_antes_de_reset.dump"
pg_restore -l "$HOME/Desktop/Tesis/respaldos/visor_ot_antes_de_reset.dump" > /dev/null
```

5. Tras comprobar el respaldo, ejecutar con tres confirmaciones:

```bash
python manage.py reset_lab_data \
  --execute \
  --confirm-database NOMBRE_BD \
  --confirm BORRAR_LABORATORIO \
  --backup-confirmed
```

6. Verificar que solo se vaciaron datos del laboratorio:

```bash
python manage.py reset_lab_data
python manage.py shell -c "from django.contrib.auth import get_user_model; print('Usuarios:', get_user_model().objects.count())"
```

El primer comando debe reportar 0 filas de laboratorio. El segundo
debe mostrar las mismas cuentas anteriores.

## Orden recomendado de carga

1. Crear manualmente los dos sistemas OT con criticidad e impacto.
2. Registrar manualmente `PLC-MEZ-01` asociado al primer sistema.
3. Registrar `FW-S7-1200-V4.4.0` como software y vincularlo al PLC.
4. Importar el resto del Excel; marcar como SKIP las dos filas creadas
   manualmente. El Excel no crea sistemas, instalaciones ni interfaces.
5. Asociar los otros hardware a sistemas, sus instalaciones de software
   y las interfaces de red manualmente desde la aplicación.
6. Evaluar CPE/CVE y después cargar comunicaciones sintéticas o PCAP.

**Atención:** el archivo `datos_sinteticos.xlsx` recibido contiene
24 filas hardware (12 equipos repetidos dos veces), y 18 filas software
(15 nombres distintos, tres repetidos). Depurar esas filas duplicadas
antes de importarlo; no iniciar una importación masiva sobre ese archivo
sin revisarlo.

## Pruebas de seguridad del comando

```bash
python manage.py test assets.tests_reset_lab_data --settings=config.settings_test_sqlite
```

Estas pruebas revisan que la vista previa sea no destructiva, que no
se incluyan tablas de usuarios y que SQLite rechace el borrado.
La ejecución de TRUNCATE debe comprobarse manualmente en una base
PostgreSQL desechable antes de emplearla en la base local de la tesis.
