import { displayNvdReferences } from "../utils/nvdReferences";

/** NVD catalogue references: external evidence, never an analyst validation. */
export default function CpeReferences({ references, sourceRunId, showMissing = false }) {
  const links = displayNvdReferences(references);
  if (!links.length && !showMissing) return null;
  return <section className="cpe-references" aria-label="Referencias de NVD">
    <div className="cpe-references-heading">
      <strong>Referencias incluidas en NVD</strong>
      {sourceRunId != null && <span>Registradas en búsqueda #{sourceRunId}</span>}
    </div>
    {links.length ? <>
      <ul>{links.map(entry => <li key={entry.url}>
        <span className="cpe-reference-group">{entry.group}</span>
        <span className="cpe-reference-type">{entry.type}</span>
        <a href={entry.url} target="_blank" rel="noopener noreferrer"
          aria-label={"Abrir referencia " + entry.type + " en una pestaña nueva"}>
          {new URL(entry.url).hostname} <span aria-hidden="true">↗</span>
        </a>
      </li>)}</ul>
      <p>Enlaces registrados desde el catálogo NVD. VISOR OT no verifica el contenido
        de estos sitios ni los considera confirmación del CPE.</p>
    </> : <p>Esta identificación no tiene referencias NVD conservadas.
      Puedes consultar el registro oficial mediante el enlace CPE Name.</p>}
  </section>;
}
