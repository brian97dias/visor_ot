import { useEffect, useState } from "react";
import { Link, useLocation, useOutletContext, useParams } from "react-router-dom";
import { getAsset } from "../api/assets";
import {
  latestCpeSearch, readCpeSearch, startCpeSearch, getAssetCpeAssociations,
} from "../api/vulnerabilities";
import CandidateCpeReview from "../components/CandidateCpeReview";
import CpeEvidence from "../components/CpeEvidence";
import CpeDiscoveryTrace from "../components/CpeDiscoveryTrace";
import CpeCandidateExplanation from "../components/CpeCandidateExplanation";
import CpeReferences from "../components/CpeReferences";
import {
  unreviewedCpeCandidates, reopenedWithoutCurrentCandidate, reviewedCpeAssociations,
} from "../utils/cpeReview";

const statusText = {
  QUEUED: "Pendiente de ejecución", RUNNING: "Consultando NVD",
  COMPLETED: "Finalizada", FAILED: "Error de consulta",
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
  const [associations, setAssociations] = useState([]);
  const [associationError, setAssociationError] = useState("");
  const allowed = ["ADMIN", "ANALYST"].includes(user?.role);
  const isSoftware = asset?.asset_type === "SOFTWARE";
  const assetTypeLabel = isSoftware ? "software" : "hardware";
  const cpeTypeLabel = type => type === "h" ? "hardware" :
    type === "o" ? "sistema operativo" : type === "a" ? "aplicación" : "desconocido";
  const pending = ["QUEUED", "RUNNING"].includes(run?.status);
  const candidatesToReview = unreviewedCpeCandidates(run?.candidates, associations);
  const exploratoryCount = candidatesToReview.filter(c => c.match_level === "EXPLORATORY").length;
  const pendingReviewCount = candidatesToReview.length - exploratoryCount;
  const reviewed = reviewedCpeAssociations(associations);
  const reopenedMissing = reopenedWithoutCurrentCandidate(run?.candidates, associations);
  const findAssociation = id => associations.find(
    item => item.cpe_name_id.toLowerCase() === String(id).toLowerCase()
  );

  useEffect(() => {
    let active = true;
    setLoading(true);
    setRun(null);
    setPollingPaused(false);
    setAsset(null);
    setError("");
    setAssociationError("");
    Promise.all([getAsset(assetId), latestCpeSearch(assetId), getAssetCpeAssociations(assetId)])
      .then(([a, r, matches]) => {
        if (active) { setAsset(a); setRun(r); setAssociations(matches); }
      })
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

  async function refreshAssociations() {
    try {
      const updated = await getAssetCpeAssociations(assetId);
      setAssociations(updated);
      setAssociationError("");
    } catch (err) {
      setAssociationError(err.message);
    }
  }

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
      <p>{isSoftware
        ? [asset.software?.manufacturer, asset.software?.product,
           asset.software?.version ? "Versión " + asset.software.version : "Versión no registrada"]
            .filter(Boolean).join(" · ")
        : <>{asset.hardware?.manufacturer} · {asset.hardware?.model}
            {asset.hardware?.cpu_model ? " · CPU " + asset.hardware.cpu_model : ""}</>}</p>
    </header>

    {error && <div className="error-message" role="alert">{error}</div>}
    {!run?.identity_is_current && run && <p className="cpe-warning">
      La identidad técnica cambió. Los resultados anteriores pueden no corresponder al equipo actual.
    </p>}
    {allowed && asset.inventory_status === "ACTIVE" &&
      <div className="cpe-tools">
        <button className="button-primary" type="button" disabled={working || pending}
          onClick={() => search("SPECIFIC")}>{working ? "Solicitando..." : "Buscar candidatos"}</button>
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
    {!run ? <section className="panel cpe-copy">Sin búsquedas previas para este {assetTypeLabel}.
      Se requiere fabricante y {isSoftware ? "producto" : "modelo/familia"} para comenzar.
      {isSoftware && " La versión registrada determina el nivel de precisión de las sugerencias."}
    </section> : <>
      <section className="panel">
        <div className="panel-header"><h2>Última búsqueda</h2>
          <span className="cpe-status" data-status={run.status}>{statusText[run.status] || run.status}</span>
        </div>
        <div className="cpe-copy">
          <p>Alcance: {run.trigger === "CATALOGUE" ? "Selección desde catálogo NVD" :
            run.trigger === "ADVANCED" ? "Avanzada · consulta controlada" :
            run.scope === "BROAD" ? "Familia" : "Específico"} ·
            {" "}{run.candidate_count} candidatos de {assetTypeLabel} encontrados.</p>
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
            <p>Sin candidatos de {assetTypeLabel} en las consultas realizadas.
              Esto no descarta que exista un CPE en NVD.</p>}
          {run.result_truncated && <p className="cpe-warning">Resultados limitados; la lista no es exhaustiva.</p>}
          <CpeDiscoveryTrace queries={run.queries} truncated={run.result_truncated} />
        </div>
      </section>
      <section className="panel cpe-review-summary">
        <div className="panel-header"><div>
          <h2>CPE revisados</h2>
          <p>Identificaciones con una decisión registrada por un analista.</p>
        </div>
          <span className="record-count">{reviewed.length} asociaciones revisadas</span>
        </div>
        <div className="cpe-copy">
          {associationError && <p className="cpe-warning" role="alert">{associationError}</p>}
          {reviewed.length === 0
            ? <p>Aún no hay asociaciones CPE registradas por un analista.</p>
            : <div className="cpe-association-list">
                {reviewed.map(item => (
                  <div className="cpe-association" key={item.id}>
                    <div className="cpe-review-row">
                      <strong>{item.title}</strong>
                      <span className="cpe-review-status" data-validation={item.validation_status}>
                        {item.validation_status === "CONFIRMED" ? "Confirmado" :
                         item.validation_status === "REJECTED" ? "Rechazado" : "Pendiente anterior"}
                      </span>
                    </div>
                    <CpeEvidence cpeName={item.cpe_name} cpeNameId={item.cpe_name_id} />
                    <CpeReferences references={item.nvd_references}
                      sourceRunId={item.references_source_run_id} showMissing />
                    {run.candidates?.some(c =>
                      c.cpe_name_id?.toLowerCase() === item.cpe_name_id?.toLowerCase()) &&
                      <CpeCandidateExplanation candidate={run.candidates.find(c =>
                        c.cpe_name_id?.toLowerCase() === item.cpe_name_id?.toLowerCase())}/>}
                    <p><strong>Justificación:</strong> {item.justification || "No registrada (opcional)"}</p>
                    <p>Revisado por {item.validated_by || "Usuario retirado"} ·
                      {" "}{new Date(item.validated_at).toLocaleString("es-CO")}</p>
                    {item.needs_review && <p className="cpe-warning">
                      La identidad técnica del activo cambió: esta asociación necesita nueva revisión.
                    </p>}
                    <details className="cpe-audit">
                      <summary>Historial de decisiones ({item.history.length})</summary>
                      <ul>{item.history.map(history => <li key={history.id}>
                        {new Date(history.created_at).toLocaleString("es-CO")} —
                        {" "}{history.actor || "Usuario retirado"}: {history.new_status}
                        {history.previous_status ? " (antes " + history.previous_status + ")" : ""}
                        {history.justification ? " — " + history.justification : ""}
                      </li>)}</ul>
                    </details>
                    <CandidateCpeReview
                      candidate={run.candidates?.find(c =>
                        c.cpe_name_id.toLowerCase() === item.cpe_name_id.toLowerCase())}
                      assetId={assetId} run={run} association={item}
                      allowed={allowed && asset.inventory_status === "ACTIVE"}
                      onReviewed={refreshAssociations}
                    />
                  </div>
                ))}
              </div>}
        </div>
      </section>
      <section className="cpe-candidate-section" aria-labelledby="cpe-candidate-title">
        <div className="cpe-candidate-heading">
          <div>
            <h2 id="cpe-candidate-title">CPE candidatos</h2>
            <p>Resultados de NVD aún sin decisión y decisiones deshechas.
              Las correspondencias débiles son opcionales, no identificaciones técnicas.</p>
          </div>
          <span className="record-count">{pendingReviewCount + reopenedMissing.length} por revisar
            {exploratoryCount > 0 ? " · " + exploratoryCount + " exploratorios" : ""}</span>
        </div>
        {candidatesToReview.length === 0 && reopenedMissing.length === 0 ? (
          <div className="panel cpe-copy">
            {run.status === "COMPLETED" && run.candidate_count > 0
              ? "Todos los candidatos de esta búsqueda tienen una decisión. Consulta «CPE revisados»."
              : "No hay candidatos pendientes de revisión en esta búsqueda."}
          </div>
        ) : <>
          {candidatesToReview.map(c => (
            <article className="cpe-card" key={c.cpe_name_id}>
              <h3>{c.title}</h3>
              <CpeEvidence cpeName={c.cpe_name} cpeNameId={c.cpe_name_id}/>
              <CpeReferences references={c.nvd_references} sourceRunId={run.id} showMissing />
              <CpeCandidateExplanation candidate={c}/>
              <div className="cpe-tags">
                <span>Tipo: {cpeTypeLabel(c.cpe_type)} ({c.cpe_type})</span>
                <span>{c.deprecated ? "Deprecado en NVD" : "No deprecado en NVD"}</span>
                <span>Encontrado por: {(c.methods || []).join(" y ")}</span>
              </div>
              <CandidateCpeReview
                candidate={c} assetId={assetId} run={run}
                association={findAssociation(c.cpe_name_id)}
                allowed={allowed && asset.inventory_status === "ACTIVE"}
                onReviewed={refreshAssociations}
              />
            </article>
          ))}
          {reopenedMissing.map(item => (
            <article className="cpe-card" key={"reopened-" + item.id}>
              <h3>{item.title}</h3>
              <CpeEvidence cpeName={item.cpe_name} cpeNameId={item.cpe_name_id}/>
              <CpeReferences references={item.nvd_references}
                sourceRunId={item.references_source_run_id} showMissing />
              <span className="cpe-review-status" data-validation="REOPENED">Decisión deshecha</span>
              <p>Este CPE no figura en la última búsqueda. Ejecuta otra búsqueda
                para volver a evaluar su aplicabilidad. Su historial permanece guardado.</p>
            </article>
          ))}
        </>}
        {run.candidate_count > 0 && <p className="cpe-hint">
          NVD propone coincidencias, pero solo una decisión expresa del analista
          registra su asociación con el activo.
        </p>}
      </section>
    </>}
  </section>;
}
