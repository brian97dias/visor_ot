# VISOR OT — Frontend

Interfaz web React/Vite para consultar y administrar sistemas y activos OT, software instalado, interfaces de red, capturas, comunicaciones, asociaciones CPE, evaluación CVE y diagnósticos PDF.

El frontend **no analiza los PCAP** ni consulta directamente a NVD: se comunica con el backend Django. El análisis pasivo se ejecuta en FastAPI y la cola NVD en un worker independiente.

## Preparar el entorno

Requisitos: Node.js compatible con Vite 8 y npm. Desde este directorio:

```bash
npm ci
cp .env.example .env.local
npm run dev
```

La variable `VITE_API_URL` debe apuntar al servidor Django, normalmente `http://127.0.0.1:8000`. La interfaz de desarrollo se abre normalmente en `http://localhost:5173`. No guardar tokens ni credenciales privadas en variables `VITE_*`: se exponen al navegador.

## Comprobaciones

```bash
npm run test:unit
npm run lint
npm run build
```

Los tests `*.test.js` se conservan junto a los módulos de `src/utils/`; `npm run test:unit` define la lista actual de pruebas. Estas instrucciones no significan que la suite se haya ejecutado en la máquina del autor.

## Más información

- [README del proyecto](../../README.md)
- [Arquitectura](../../docs/arquitectura.md)
- [Pruebas](../../docs/pruebas.md)
