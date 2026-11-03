# VISOR OT — fix/general: inventario sin asociación obligatoria a sistemas

## Decisión de producto

El hardware puede registrarse, importarse, mantenerse activo y restaurarse
sin pertenecer a un sistema OT. Esto refleja falta de contextualización
operacional, no un fallo de integridad. Fabricante, modelo, rol y criticidad
siguen siendo obligatorios para hardware activo nuevo.

## Registro manual

El formulario de creación presenta el campo **Asociar sistema** con
una lista desplegable de sistemas OT activos, sin checkboxes ni modal.
La primera opción es **Sin registrar sistema** (seleccionada inicialmente).
Cuando se elige un sistema, el formulario envía `system_ids: [id]`;
si se mantiene la primera opción, envía `system_ids: []`.
El botón **Registrar activo** guarda directamente el hardware.
El formulario permite una asociación inicial; las asociaciones adicionales
se pueden gestionar después desde el detalle de hardware, manteniendo
las relaciones múltiples del modelo.
Las selecciones inválidas o los sistemas archivados siguen rechazándose.

## Excel: no se importan asociaciones

Las hojas **Hardware** y **Software** siguen con las mismas columnas.
La previsualización/confirmación no solicita sistemas, y la creación
desde Excel jamás establece SystemMembership. La vinculación posterior
es manual y no está automatizada. Una confirmación antigua que contenga
`system_ids` no vacío se rechaza con un error explícito.
Las instalaciones de software en hardware también siguen siendo manuales.

## Ciclo de vida y auditoría

- Se permite desvincular el último sistema OT activo sin borrar el historial.
- Archivar el último sistema de un hardware no bloquea la operación.
- Se puede restaurar hardware sin asociación OT; cualquier asociación
  opcional debe referirse a un sistema activo.
- `audit_inventory_integrity` no reporta como error la ausencia de sistema.
  Sigue comprobando criticidad e identificación técnica de activos.

## Diagnóstico PDF

- El contrato JSON conserva todos los pares Hardware–CVE con `APPLIES`.
- `diagnosis.summary` desglosa hardware y pares CVE con/sin sistema.
- La matriz y los conteos P1/P2/P3 incluyen hardware con sistema activo.
- Hardware con `APPLIES` vigente y sin sistema se muestra íntegro en
  **Apéndice D**, con sus CVE, CPE, instalación de software y observaciones.
- Estos dispositivos no reciben P1/P2/P3 hasta tener sistema asociado.
- CVE condicionados se mantienen en su apéndice habitual (A).
- Activos sin `APPLIES` siguen contabilizándose en la cobertura general:
  ausencia de hallazgos no significa seguridad certificada.

## Validación en Pop!_OS

Desde `web_app/backend`:

```bash
git fetch origin
git switch --track origin/fix/general
python manage.py test assets.tests_inventory_integrity assets.tests_system_memberships assets.tests_excel_import vulnerabilities.tests_hardening_diagnosis vulnerabilities.tests_hardening_pdf_diagnosis vulnerabilities.tests_hardening_report_data --settings=config.settings_test_sqlite
python manage.py test --settings=config.settings_test_sqlite
```

Desde `web_app/frontend`:

```bash
npm run test:unit
npm run lint
npm run build
```

Pruebas manuales: crear hardware sin sistema desde el desplegable,
crear hardware con un sistema seleccionado, añadir un segundo sistema
manualmente desde el detalle, importar Excel sin asociación, quitar el último
vínculo, archivar/restaurar y exportar diagnóstico con un CVE aplicable
del hardware sin sistema. Revisar que el apéndice D lo muestre y que
la matriz principal no lo incluya. No alterar la base real de la tesis
para provocar estados inválidos: usar la base de tests.

Los cambios están en la rama `fix/general`, no en `feature/vulnerability`.
La ejecución de las pruebas Django y el build frontend debe confirmarse
en el entorno local con sus dependencias.
