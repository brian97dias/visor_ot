import { nvdCpeUrl } from "../utils/nvdLinks";

/** One official NVD link per CPE; identifier is separate, non-clickable evidence. */
export default function CpeEvidence({ cpeName, cpeNameId }) {
  const url = nvdCpeUrl(cpeNameId);
  return <div className="cpe-evidence">
    <div>
      <span className="cpe-evidence-label">CPE Name</span>
      {url ? (
        <a className="cpe-evidence-link" href={url} target="_blank"
          rel="noopener noreferrer" aria-label={"Consultar " + cpeName + " en NVD (nueva pestaña)"}>
          <code>{cpeName}</code><span className="cpe-evidence-external" aria-hidden="true">↗</span>
        </a>
      ) : <code>{cpeName}</code>}
    </div>
    <div><span className="cpe-evidence-label">CPE Name ID (UUID)</span>
      <code>{cpeNameId}</code></div>
  </div>;
}
