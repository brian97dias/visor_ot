# VISOR OT — Fase 4 ampliada / subfase C: descarga web

La presentación de **Análisis CVE** permite descargar el diagnóstico PDF
ya aprobado sin salir de la pantalla. El botón **Generar informe** está
junto a **Buscar CVE**. El nuevo endpoint no modifica la lógica del
inventario, las evaluaciones de aplicabilidad ni las referencias NVD.

## Contrato HTTP

- Ruta: `POST /api/vulnerabilities/reports/hardening.pdf`
- Autenticación: JWT del cliente existente; se admite la renovación habitual
  del token de acceso.
- Permisos: administradores y analistas. Operadores: 403, anónimos: 401.
- Solicitud: sin cuerpo ni opciones. No se admite indicar el autor desde el
  navegador; se usa la identidad autenticada.
- Respuesta satisfactoria: `200 application/pdf`, `Content-Disposition:
  attachment`, `Cache-Control: private, no-store` y
  `X-Content-Type-Options: nosniff`.
- Si la integridad de inventario falla, devuelve respuesta JSON `400`,
  que el frontend presenta como error en la pantalla.
- `GET` no está habilitado; iniciar la generación requiere pulsar el botón.

Se recopila el estado vigente mediante
`collect_hardening_report_data()`, y se invoca a
`render_hardening_pdf(..., author=...)` con un `BytesIO`. No se guarda
el PDF en el servidor. El autor se obtiene de
`request.user.get_full_name().strip()` o, si no hay nombre completo,
del nombre de usuario.

La vista es `vulnerabilities/hardening_report_views.py`. La función de
cliente es `downloadHardeningPdf()`, en
`frontend/src/api/vulnerabilities.js`; usa `authenticatedFetch`,
recibe un `Blob` y activa una descarga en el navegador.

## Requisitos

En `web_app/backend` se necesita ReportLab instalado:

```bash
python -m pip install -r requirements-hardening-report.txt
```

Para el frontend se utiliza el proyecto React existente; no hay
dependencias nuevas.

## Pruebas de integración

```bash
# Desde web_app/backend
python manage.py test vulnerabilities.tests_hardening_report_http \
  --settings=config.settings_test_sqlite
python manage.py test vulnerabilities --settings=config.settings_test_sqlite

# Desde web_app/frontend
npm run test:unit
npm run build
npm run lint
```

Prueba manual: iniciar sesión como administrador o analista, abrir
**Análisis CVE**, pulsar **Generar informe** y confirmar que el navegador
descarga un archivo PDF con el usuario real en portada y los hallazgos
actuales del inventario. Repetir con operador: no debe aparecer el botón,
y el backend debe denegar la descarga si se solicita directamente.

La subfase C no cambia `generate_hardening_pdf` ni su opción `--legacy`.
No añade menús laterales, no exporta JSON y no guarda registros de
generación. La regresión final del producto corresponde a la subfase D.
