import { nvdCpeUrl } from "../utils/nvdLinks";

/** Normalized NVD identity, shared across reviewed and candidate cards. */
export default function CpeEvidence({ cpeName, cpeNameId }) {
  const url = nvdCpeUrl(cpeNameId);
  return <div className="cpe-evidence">
    <div><span className="cpe-evidence-label">CPE Name</span>
      {url ? <a href={url} target="_blank" rel="noopener noreferrer">
        <code>{cpeName}</code> ↗
      </a> : <code>{cpeName}</code>}</div>
    <div><span className="cpe-evidence-label">CPE Name ID (UUID)</span>
      <code>{cpeNameId}</code></div>
    {url && <a href={url} target="_blank" rel="noopener noreferrer">
      Consultar CPE en NVD ↗
    </a>}
  </div>;
}
