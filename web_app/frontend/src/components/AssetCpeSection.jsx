import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { latestCpeSearch } from "../api/vulnerabilities";

export default function AssetCpeSection({ asset }) {
  const [run, setRun] = useState(null);
  const [ready, setReady] = useState(false);
  const [error, setError] = useState("");
  useEffect(() => {
    let active = true;
    setReady(false);
    latestCpeSearch(asset.id)
      .then(value => { if (active) setRun(value); })
      .catch(err => { if (active) setError(err.message); })
      .finally(() => { if (active) setReady(true); });
    return () => { active = false; };
  }, [asset.id]);
  return <section className="panel assets-detail-section">
    <div className="panel-header"><h2>Identificación CPE</h2>
      {run && <span className="cpe-status" data-status={run.status}>{run.status}</span>}
    </div>
    <p className="cpe-copy">
      {error || (!ready ? "Cargando búsquedas..." :
        !run ? "Todavía no existen búsquedas CPE para este activo." :
        "Última búsqueda: " + new Date(run.created_at).toLocaleString("es-CO") +
        " · " + run.candidate_count + " candidatos.")}
    </p>
    {run && !run.identity_is_current &&
      <div className="cpe-warning">Cambió la identidad del equipo desde esta búsqueda.</div>}
    <div className="cpe-action">
      <Link className="button-secondary" to={"/assets/" + asset.id + "/cpe"}>
        {run ? "Ver candidatos CPE" : "Descubrir candidatos CPE"}
      </Link>
    </div>
  </section>;
}
