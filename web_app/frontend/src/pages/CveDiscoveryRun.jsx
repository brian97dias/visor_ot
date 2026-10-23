import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  listCveDiscoveryFindings, readCveDiscoveryRun,
} from "../api/vulnerabilities";
import {
  CVE_DISCOVERY_STATE, cvePageCount, isCveDiscoveryActive,
} from "../utils/cveCataloguePresentation";

const PAGE_SIZE = 20;

export default function CveDiscoveryRun() {
  const { runId } = useParams();
  const [run, setRun] = useState(null);
  const [findings, setFindings] = useState({ count: 0, results: [] });
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [refresh, setRefresh] = useState(0);

  useEffect(() => {
    let active = true;
    setLoading(true);
    Promise.all([
      readCveDiscoveryRun(runId),
      listCveDiscoveryFindings(runId, page, PAGE_SIZE),
    ]).then(([info, rows]) => {
      if (!active) return;
      setRun(info);
      setFindings(rows);
    }).catch(err => { if (active) setError(err.message); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [runId, page, refresh]);

  useEffect(() => {
    if (!run || !isCveDiscoveryActive(run.status)) return undefined;
    const timer = window.setInterval(() => setRefresh(value => value + 1), 10000);
    return () => window.clearInterval(timer);
  }, [run?.status]);

  const pages = cvePageCount(findings.count, PAGE_SIZE);
  return <section className="page cve-catalogue-page">
    <nav className="breadcrumbs" aria-label="Ruta de navegación">
      <Link to="/vulnerabilities/cve">Análisis CVE</Link><span>/</span>
      <span>Búsqueda #{runId}</span>
    </nav>
    <header className="page-header cve-catalogue-heading">
      <div><span className="page-eyebrow">DESCUBRIMIENTO NVD</span>
        <h1>Búsqueda CVE #{runId}</h1>
        <p>Estado de ejecución y hallazgos candidatos recuperados.</p></div>
      <button type="button" className="button-secondary"
        onClick={() => setRefresh(value => value + 1)}>Actualizar</button>
    </header>
    {error && <p className="error-message" role="alert">{error}</p>}
    {loading && !run ? <p>Consultando búsqueda...</p> : run && <>
      <div className="cve-catalogue-stats">
        <div className="cpe-overview-stat"><strong>
          {CVE_DISCOVERY_STATE[run.status] || run.status}</strong>
          <span>Estado</span></div>
        <div className="cpe-overview-stat"><strong>
          {run.completed_queries} / {run.query_count}</strong>
          <span>CPE procesados</span></div>
        <div className="cpe-overview-stat"><strong>
          {run.retrieved_occurrences}</strong>
          <span>Coincidencias recuperadas</span></div>
        <div className="cpe-overview-stat"><strong>
          {run.pages_fetched}</strong><span>Páginas consultadas</span></div>
      </div>
      {run.error_message && <p role="alert" className="error-message">
        {run.error_code}: {run.error_message}</p>}
      {isCveDiscoveryActive(run.status) && <p className="cve-overview-disclaimer">
        Esta búsqueda se procesa mediante el worker NVD. Si permanece en cola,
        verifica que <code>run_cpe_worker</code> esté ejecutándose.
      </p>}
      <section className="panel cve-catalogue-panel">
        <div className="panel-header"><h2>Progreso por CPE</h2></div>
        <div className="table-container">
          <table className="data-table">
            <thead><tr><th>CPE consultado</th><th>Hardware</th><th>Estado</th>
              <th>Progreso</th></tr></thead>
            <tbody>{run.queries.map((query, index) => <tr key={query.cpe_name + index}>
              <td><code className="cve-catalogue-query">{query.cpe_name}</code></td>
              <td>{query.hardware_ids.map(id => "#" + id).join(", ")}</td>
              <td>{CVE_DISCOVERY_STATE[query.status] || query.status}</td>
              <td>{query.retrieved_count} de {query.expected_total ?? "?"}
                <small className="cve-catalogue-secondary">
                  Próximo índice: {query.next_start_index}</small></td>
            </tr>)}</tbody>
          </table>
        </div>
      </section>
      <section className="panel cve-catalogue-jobs">
        <div className="panel-header">
          <div><h2>Hallazgos relacionados</h2>
            <p>Esta tabla refleja los hallazgos materializados cuya última búsqueda es #{runId}.</p>
          </div>
          <span className="record-count">{findings.count} candidatos</span>
        </div>
        <div className="table-container">
          <table className="data-table">
            <thead><tr><th>CVE</th><th>Hardware</th><th>Evidencia</th><th>Acción</th></tr></thead>
            <tbody>{findings.results.length === 0
              ? <tr><td colSpan="4">Aún no hay hallazgos asociados a esta ejecución.</td></tr>
              : findings.results.map(row => <tr key={row.finding_id}>
                <td><strong>{row.cve_id}</strong></td>
                <td><Link to={"/assets/" + row.hardware_id}>
                  {row.hardware_name}</Link></td>
                <td>{row.evidence_status === "CURRENT" ?
                  "Candidato vigente" : "Evidencia desactualizada"}</td>
                <td><Link className="button-secondary"
                  to={"/vulnerabilities/cve/" + encodeURIComponent(row.cve_id)}>
                    Ver CVE</Link></td>
              </tr>)}</tbody>
          </table>
        </div>
        <div className="pagination">
          <span>Página {Math.min(page, pages)} de {pages}</span>
          <div className="pagination-actions">
            <button type="button" disabled={page === 1}
              onClick={() => setPage(p => p - 1)}>Anterior</button>
            <button type="button" disabled={page >= pages}
              onClick={() => setPage(p => p + 1)}>Siguiente</button>
          </div>
        </div>
      </section>
      <p className="cve-overview-disclaimer">
        La ausencia de coincidencias no equivale a «No aplica». Los estados de
        esta pantalla indican progreso de descubrimiento, no decisiones del analista.
      </p>
    </>}
  </section>;
}
