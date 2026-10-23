import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";

import {
  listCveHardware, readCveCatalogue,
} from "../api/vulnerabilities";
import { CVE_SEVERITY, cvePageCount } from "../utils/cveCataloguePresentation";

const PAGE_SIZE = 15;

export default function CveDetail() {
  const { cveId } = useParams();
  const [cve, setCve] = useState(null);
  const [hardware, setHardware] = useState({ count: 0, results: [] });
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [hardwareLoading, setHardwareLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError("");
    readCveCatalogue(cveId)
      .then(data => { if (active) setCve(data); })
      .catch(err => { if (active) setError(err.message); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [cveId]);

  useEffect(() => {
    let active = true;
    setHardwareLoading(true);
    listCveHardware(cveId, page, PAGE_SIZE)
      .then(data => { if (active) setHardware(data); })
      .catch(err => { if (active) setError(err.message); })
      .finally(() => { if (active) setHardwareLoading(false); });
    return () => { active = false; };
  }, [cveId, page]);

  const pages = cvePageCount(hardware.count, PAGE_SIZE);
  const nvdUrl = "https://nvd.nist.gov/vuln/detail/" + encodeURIComponent(cveId);
  return <section className="page cve-catalogue-page cve-general-detail">
    <nav className="breadcrumbs" aria-label="Ruta de navegación">
      <Link to="/vulnerabilities/cve">Análisis CVE</Link><span>/</span>
      <span>{cveId}</span>
    </nav>
    <header className="page-header">
      <span className="page-eyebrow">REGISTRO OFICIAL NVD</span>
      <h1>{cveId}</h1>
      <p>Ficha informativa y hardware con hallazgos candidatos.</p>
    </header>
    {error && <p role="alert" className="error-message">{error}</p>}
    {loading ? <p>Cargando registro NVD...</p> : !cve
      ? <p>No se encontró este CVE recuperado en el catálogo.</p>
      : <>
        <section className="panel cve-catalogue-detail-panel">
          <div className="cve-catalogue-detail-heading">
            <div><h2>Descripción</h2>
              <p>{cve.description || "Sin descripción disponible."}</p></div>
            <span className="cve-catalogue-severity" data-severity={cve.severity}>
              {CVE_SEVERITY[cve.severity] || cve.severity}
              {cve.base_score != null ? " · CVSS " + cve.base_score : ""}
            </span>
          </div>
          <div className="cve-catalogue-detail-meta">
            <div><span>Publicado</span><strong>
              {cve.published ? new Date(cve.published).toLocaleDateString("es-CO") : "No indicado"}
            </strong></div>
            <div><span>Actualización NVD</span><strong>
              {cve.last_modified ? new Date(cve.last_modified).toLocaleDateString("es-CO") : "No indicada"}
            </strong></div>
            <div><span>Hardware relacionados</span>
              <strong>{cve.hardware_count}</strong></div>
            <div><a href={nvdUrl} target="_blank" rel="noreferrer">
              Consultar registro en NVD ↗</a></div>
          </div>
          <details className="cve-catalogue-raw">
            <summary>Ver configuraciones originales NVD ({cve.configurations?.length || 0})</summary>
            <p>Se conserva el árbol AND/OR, los rangos de versión y las negaciones
              tal como los publicó NVD. No representan una confirmación automática.</p>
            <pre>{JSON.stringify(cve.configurations || [], null, 2)}</pre>
          </details>
          <details className="cve-catalogue-raw">
            <summary>Ver métricas CVSS y referencias</summary>
            <pre>{JSON.stringify({
              metrics: cve.metrics, references: cve.references,
            }, null, 2)}</pre>
          </details>
        </section>

        <section className="panel cve-catalogue-jobs">
          <div className="panel-header">
            <div><h2>Hardware relacionado</h2>
              <p>Equipos encontrados mediante CPE del hardware o software instalado.</p>
            </div>
            <span className="record-count">{hardware.count} hallazgos candidatos</span>
          </div>
          <div className="table-container">
            <table className="data-table">
              <thead><tr><th>Hardware</th><th>Estado de evidencia</th>
                <th>Procedencia CPE</th><th>Acción</th></tr></thead>
              <tbody>{hardwareLoading
                ? <tr><td colSpan="4">Cargando hardware...</td></tr>
                : hardware.results.length === 0
                  ? <tr><td colSpan="4">No hay hardware relacionado en los hallazgos actuales.</td></tr>
                  : hardware.results.map(row => <tr key={row.finding_id}>
                    <td><strong>{row.hardware_name}</strong>
                      <small className="cve-catalogue-secondary">#{row.hardware_id}</small>
                    </td>
                    <td><span className="cve-catalogue-evidence" data-status={row.evidence_status}>
                      {row.evidence_status === "CURRENT" ? "Evidencia vigente" : "Revisar identidad/CPE"}
                    </span><small className="cve-catalogue-secondary">Candidato · no evaluado aquí</small></td>
                    <td><div className="cve-catalogue-sources">
                      {row.sources.map((source, index) => <span key={
                        source.asset_cpe_id + "-" + (source.installation_id || "hw") + "-" + index
                      } title={source.cpe_name}>
                        {source.origin === "HARDWARE" ? "Hardware" : "Software instalado"}
                        {" · "}{source.cpe_name}
                      </span>)}
                    </div></td>
                    <td><Link to={"/assets/" + row.hardware_id}
                      className="button-secondary">Ver hardware</Link>
                      {cveId === "CVE-2021-33540" && row.hardware_id === 2 &&
                        <Link className="cve-catalogue-eval-link"
                          to="/vulnerabilities/cve/experimental">Evaluación guiada</Link>}
                    </td>
                  </tr>)}</tbody>
            </table>
          </div>
          <div className="pagination">
            <span>Página {Math.min(page, pages)} de {pages}</span>
            <div className="pagination-actions">
              <button type="button" disabled={page <= 1}
                onClick={() => setPage(x => x - 1)}>Anterior</button>
              <button type="button" disabled={page >= pages}
                onClick={() => setPage(x => x + 1)}>Siguiente</button>
            </div>
          </div>
          {cveId === "CVE-2021-33540" && <p className="cve-catalogue-disclaimer">
            El análisis asistido del hardware #2 sigue disponible en
            {" "}<Link to="/vulnerabilities/cve/experimental">el caso experimental</Link>.
          </p>}
        </section>
        <p className="cve-overview-disclaimer">
          Correlación por CPE ≠ vulnerabilidad confirmada. La evaluación de
          aplicabilidad para hardware y configuraciones genéricas llegará en
          la siguiente etapa del módulo.
        </p>
      </>}
  </section>;
}
