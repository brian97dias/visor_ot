import { useEffect, useState } from "react";
import { Link, useLocation, useOutletContext, useParams } from "react-router-dom";
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
  const location = useLocation();
  const query = typeof location.state?.cpeOverviewSearch === "string"
    && location.state.cpeOverviewSearch.startsWith("?")
    ? location.state.cpeOverviewSearch : "";
  const returnTo = "/vulnerabilities/cpe" + query;
  const [asset, setAsset] = useState(null);
  const [run, setRun] = useState(null);
  const [loading, setLoading] = useState(true);
  const [working, setWorking] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [pollingPaused, setPollingPaused] = useState(false);
  const [error, setError] = useState("");
  const allowed = ["ADMIN", "ANALYST"].includes(user?.role);
  const pending = ["QUEUED", "RUNNING"].includes(run?.status);

  useEffect(() => {
    let active = true;
    setLoading(true);
    setRun(null);
    setPollingPaused(false);
    setAsset(null);
    setError("");
    Promise.all([getAsset(assetId), latestCpeSearch(assetId)])
      .then(([a, r]) => { if (active) { setAsset(a); setRun(r); } })
      .catch(err => { if (active) setError(err.message); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [assetId]);

  useEffect(() => {
    if (!pending || !run || pollingPaused) return;
    let active = true;
    // Requests update only the state in PostgreSQL; they never start NVD calls.
    // Stop continuous polling after five minutes and offer a manual refresh.
    const timer = window.setInterval(() => {
      if (Date.now() - Date.parse(run.created_at) >= 5 * 60 * 1000) {
        setPollingPaused(true);
        return;
      }
      readCpeSearch(assetId, run.id)
        .then(r => { if (active) { setRun(r); setError(""); } })
        .catch(err => { if (active) setError(err.message); });
    }, 5000);
    return () => { active = false; window.clearInterval(timer); };
  }, [assetId, run?.id, run?.status, pending, pollingPaused]);

  async function refresh() {
    if (!run || refreshing) return;
    setRefreshing(true);
    try {
      const latest = await readCpeSearch(assetId, run.id);
      setRun(latest);
      setError("");
    } catch (err) {
      setError(err.message);
    } finally {
      setRefreshing(false);
    }
  }

  async function search(scope) {
    if (working || pending) return;
    setWorking(true);
    setPollingPaused(false);
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
    <nav className="breadcrumbs" aria-label="Ruta de navegación">
      <span>Vulnerabilidades</span><span>/</span>
      <Link to={returnTo}>Identificación CPE</Link><span>/</span>
      <span>{asset.name}</span>
    </nav>
    <Link className="button-secondary assets-back-link" to={returnTo}>
      ← Volver a Identificación CPE
    </Link>
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
    {run && pending && (pollingPaused || Boolean(error)) && (
      <div className="cpe-tools">
        <button className="button-secondary" type="button" disabled={refreshing}
          onClick={refresh}>
          {refreshing ? "Consultando estado..." : "Consultar estado ahora"}
        </button>
      </div>
    )}
    {!run ? <section className="panel cpe-copy">Sin búsquedas previas para este hardware.
      Se requieren fabricante y modelo/familia para comenzar.</section> : <>
      <section className="panel">
        <div className="panel-header"><h2>Última búsqueda</h2>
          <span className="cpe-status" data-status={run.status}>{statusText[run.status] || run.status}</span>
        </div>
        <div className="cpe-copy">
          <p>Alcance: {run.scope === "BROAD" ? "Familia" : "Específico"} · Candidatos: {run.candidate_count}.</p>
          <p>Fecha: {new Date(run.created_at).toLocaleString("es-CO")}</p>
          {pending && <>
            <p>La búsqueda permanece guardada en PostgreSQL aunque abandones esta página.</p>
            {run.worker_active === false && <p className="cpe-warning" role="status">
              No se detecta el trabajador NVD en PostgreSQL. Abre otra terminal
              del backend y ejecuta <code>python manage.py run_cpe_worker</code>.
              Las solicitudes HTTP 200 solamente consultan el estado: no ejecutan la búsqueda.
            </p>}
            {run.worker_active === true && run.status === "QUEUED" &&
              <p className="cpe-hint">Trabajador detectado. Este trabajo está esperando su turno;
                puede haber otras búsquedas anteriores en ejecución.</p>}
            {run.worker_active === true && run.status === "RUNNING" &&
              <p className="cpe-hint">Trabajador detectado y búsqueda iniciada.
                NVD puede demorar por los límites de frecuencia y los reintentos.</p>}
            {run.worker_active == null && <p className="cpe-hint">
              No fue posible consultar la disponibilidad del trabajador.</p>}
            {pollingPaused && <p className="cpe-warning" role="status">
              La consulta automática se pausó tras cinco minutos para evitar
              solicitudes indefinidas. Puedes utilizar «Consultar estado ahora»
              para verificar el resultado sin iniciar otra búsqueda.
              Si el trabajador está detenido, reinícialo en otra terminal.
            </p>}
            {!pollingPaused && <p className="cpe-hint">
              Actualizando el estado aproximadamente cada cinco segundos.</p>}
          </>}
          {run.status === "FAILED" && <p role="alert">{run.error_message}</p>}
          {run.status === "COMPLETED" && run.candidate_count === 0 &&
            <p>Sin candidatos de hardware (tipo h) en las consultas realizadas.
              Esto no descarta que exista un CPE en NVD.</p>}
          {run.result_truncated && <p className="cpe-warning">Resultados limitados; la lista no es exhaustiva.</p>}
          <h3>Consultas NVD</h3>
          <ul>{(run.queries || []).map((query,i) =>
            <li key={i}>{query.strategy}: <code>{query.parameter}</code> ·
              {query.pages} página(s) · {query.retrieved} registro(s) NVD sin filtrar</li>)}</ul>
        </div>
      </section>
      {run.candidates?.map(c => <article className="cpe-card" key={c.cpe_name_id}>
        <h3>{c.title}</h3><code>{c.cpe_name}</code>
        <div className="cpe-tags">
          <span>{matchText[c.match_level] || c.match_level}</span>
          <span>Tipo: {c.cpe_type}</span>
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
