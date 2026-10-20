import { displayNvdReferences } from "../utils/nvdReferences";

/** A direct product URL supplied by NVD, distinct from the official CPE JSON. */
export default function CpeReferences({ references, sourceRunId, showMissing = false }) {
  const products = displayNvdReferences(references);
  if (!products.length && !showMissing) return null;

  return <section className="cpe-references" aria-label="Enlaces de producto incluidos en NVD">
    <div className="cpe-references-heading">
      <strong>Referencia del producto</strong>
      {products.length > 0 && sourceRunId != null && (
        <span>Obtenida en búsqueda #{sourceRunId}</span>
      )}
    </div>
    {products.length > 0 ? (
      <>
        <ul>{products.map(({ url }) => <li key={url}>
          <span className="cpe-reference-group">Producto</span>
          <a href={url} target="_blank" rel="noopener noreferrer"
            aria-label={"Ver producto en " + new URL(url).hostname + " (nueva pestaña)"}>
            Ver producto <span aria-hidden="true">↗</span>
          </a>
          <span className="cpe-reference-type">{new URL(url).hostname}</span>
        </li>)}</ul>
        <p>Enlace incluido en el registro CPE de NVD. Puede ayudar a verificar el
          modelo, pero no constituye una confirmación automática.</p>
      </>
    ) : (
      <p>No hay un enlace de producto conservado para este CPE. Si la búsqueda
        es anterior a esta funcionalidad, ejecuta una nueva búsqueda para recuperar
        las referencias disponibles en NVD.</p>
    )}
  </section>;
}
