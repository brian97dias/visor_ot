import { describeCandidate } from "../utils/cpeDiscoveryPresentation";

/** Automated discovery is not a human decision and never changes an association. */
export default function CpeCandidateExplanation({ candidate }) {
  const info = describeCandidate(candidate);
  return <div className="cpe-match-explanation">
    <div className="cpe-match-heading">
      <span className="cpe-match-category" data-tone={info.tone}>{info.label}</span>
      <small>Clasificación automática, no confirmación</small>
    </div>
    <p>{info.reason}</p>
    {info.levels.length > 0 && <p className="cpe-match-source">
      Niveles: {info.levels.join(", ")}</p>}
    {info.methods.length > 0 && <p className="cpe-match-source">
      Métodos: {info.methods.join(", ")}</p>}
    {info.levels.length === 0 && <p className="cpe-match-source">
      Nivel de descubrimiento no registrado.</p>}
  </div>;
}
