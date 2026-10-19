import { useEffect, useState } from "react";
import { Link, useOutletContext, useParams } from "react-router-dom";
import { getAsset } from "../api/assets";
import { latestCpeSearch, readCpeSearch, startCpeSearch } from "../api/vulnerabilities";

const statusText = {
  QUEUED: "Pendiente de ejecución", RUNNING: "Consultando NVD",
  COMPLETED: "Finalizada", FAILED: "Error de consulta",
};
const matchText = {
  SPECIFIC: "Coincidencia específica", FAMILY: "Coincidencia de familia",
  NEEDS_INFO: "Requiere información", POSSIBLE_INCOMPATIBILITY: "Posible incompatibilidad",
};

export default function AssetCpeDiscovery() {
  const { assetId } = useParams();
  const { user } = useOutletContext();
  const [asset, setAsset] = useState(null);
  const [run, setRun] = useState(null);
  const [loading, setLoading] = useState(true);
  const [working, setWorking] = useState(false);
  const [error, setError] = useState("");
  const allowed = ["ADMIN", "ANALYST"].includes(user?.role);
  const pending = ["QUEUED", "RUNNING"].includes(run?.status);

  useEffect(() => {
    let active = true;
    setLoading(true);
    setRun(null);
    setAsset(null);
    setError("");
    Promise.all([getAsset(assetId), latestCpeSearch(assetId)])
      .then(([a, r]) => { if (active) { setAsset(a); setRun(r); } })
      .catch(err => { if (active) setError(err.message); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [assetId]);

  useEffect(() => {
    if (!pending || !run) return;
    let active = true;
    const timer = window.setInterval(() => {
      readCpeSearch(assetId, run.id)
        .then(r => { if (active) { setRun(r); setError(""); } })
        .catch(err => { if (active) setError(err.message); });
    }, 4000);
    return () => { active = false; window.clearInterval(timer); };
  }, [assetId, run?.id, run?.status, pending]);

  async function search(scope) {
    if (working || pending) return;
    setWorking(true);
    setError("");
    try {
      const response = await startCpeSearch(assetId, scope);
      setRun(await readCpeSearch(assetId, response.run_id));
    } catch (err) {
      setError(err.message);
    } finally {
      setWorking(false);
    }
  }
  if (loading) return <section className="page">Cargando identificación CPE...</section>;
  if (!asset) return <section className="page"><p className="error-message">{error}</p>
    <Link to={"/assets/" + assetId}>Volver</Link></section>;

  return <section className="page">
    <div className="breadcrumbs"><span>Activos</span><span>/</span>
      <Link to={"/assets/" + assetId}>{asset.name}</Link><span>/</span><span>CPE</span></div>
    <Link className="button-secondary assets-back-link" to={"/assets/" + assetId}>← Volver al activo</Link>
    <header className="page-header"><span className="page-eyebrow">IDENTIFICACIÓN CPE</span>
      <h1>Descubrimiento de candidatos</h1>
      <p>{asset.hardware?.manufacturer} · {asset.hardware?.model}
        {asset.hardware?.cpu_model ? " · CPU " + asset.hardware.cpu_model : ""}</p>
    </header>

    {error && <div className="error-message" role="alert">{error}</div>}
    {!run?.identity_is_current && run && <p className="cpe-warning">
      La identidad técnica cambió. Los resultados anteriores pueden no corresponder al equipo actual.
    </p>}
    {allowed && asset.asset_type === "HARDWARE" && asset.inventory_status === "ACTIVE" &&
      <div className="cpe-tools">
        <button className="button-primary" type="button" disabled={working || pending}
          onClick={() => search("SPECIFIC")}>{working ? "Solicitando..." : "Buscar candidatos"}</button>
        <button className="button-secondary" type="button" disabled={working || pending}
          onClick={() => search("BROAD")}>Ampliar búsqueda por familia</button>
      </div>}
    {!allowed && <p className="cpe-copy">Tu usuario puede consultar, pero no iniciar búsquedas CPE.</p>}
    {!run ? <section className="panel cpe-copy">Sin búsquedas previas para este hardware.
      Se requieren fabricante y modelo/familia para comenzar.</section> : <>
      <section className="panel">
        <div className="panel-header"><h2>Última búsqueda</h2>
          <span className="cpe-status" data-status={run.status}>{statusText[run.status] || run.status}</span>
        </div>
        <div className="cpe-copy">
          <p>Alcance: {run.scope === "BROAD" ? "Familia" : "Específico"} · Candidatos: {run.candidate_count}.</p>
          <p>Fecha: {new Date(run.created_at).toLocaleString("es-CO")}</p>
          {pending && <p>El procesamiento puede tardar debido al límite público de NVD.
            Si permanece pendiente, verifica que se haya iniciado el comando <code>run_cpe_worker</code>.</p>}
          {run.status === "FAILED" && <p role="alert">{run.error_message}</p>}
          {run.status === "COMPLETED" && run.candidate_count === 0 &&
            <p>Sin coincidencias en las consultas realizadas. Esto no descarta que exista un CPE.</p>}
          {run.result_truncated && <p className="cpe-warning">Resultados limitados; la lista no es exhaustiva.</p>}
          <h3>Consultas NVD</h3>
          <ul>{(run.queries || []).map((query,i) =>
            <li key={i}>{query.strategy}: <code>{query.parameter}</code> ·
              {query.pages} página(s) · {query.retrieved} resultado(s)</li>)}</ul>
        </div>
      </section>
      {run.candidates?.map(c => <article className="cpe-card" key={c.cpe_name_id}>
        <h3>{c.title}</h3><code>{c.cpe_name}</code>
        <div className="cpe-tags">
          <span>{matchText[c.match_level] || c.match_level}</span>
          <span>Tipo: {c.cpe_type}</span>
          <span>Versión: {["*","-",""].includes(c.version) ? "No especificada" : c.version}</span>
          <span>{c.deprecated ? "Deprecado" : "No deprecado"}</span>
          <span>Método: {c.methods.join(" y ")}</span>
        </div>
        <p>{c.match_reason}</p>
      </article>)}
      {run.candidate_count > 0 && <p className="cpe-copy">
        Estos resultados son candidatos, no asociaciones confirmadas.
        La validación del analista se implementará en la fase 2.</p>}
    </>}
  </section>;
}
