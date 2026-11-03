import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate, useOutletContext, useSearchParams } from "react-router-dom";

import { getCpeOverview } from "../api/vulnerabilities";
import {
  downloadHardeningPdf, enqueueCveDiscovery, listCveCatalogue,
} from "../api/vulnerabilities";
import {
  CVE_EVALUATION_STATE, CVE_CATALOGUE_FILTER_STATES,
  displayCveApplicability,

  CVE_APPLICABILITY_SOURCE,

  CVE_SEVERITY, cveHardwareCandidates,
  cveHardwareSelectionValid, cvePageCount,
  preferredCveHardwareId,
  toggleCveHardwareSelection,
} from "../utils/cveCataloguePresentation";
import { readCpePage } from "../utils/cpeOverviewUrlState";

const PAGE_SIZE = 15;
export default function CveOverview() {
  const { user } = useOutletContext();
  const navigate = useNavigate();
  const canSearch = ["ADMIN", "ANALYST"].includes(user?.role);
  const [params, setParams] = useSearchParams();
  const search = params.get("q") || "";
  const severity = params.get("severity") || "ALL";
  const status = params.get("status") || "ALL";
  const requestedPage = readCpePage(params.get("page"));
  const [catalogue, setCatalogue] = useState({
    count: 0, results: [], page: 1,
    summary: {total: 0, applies: 0, not_applicable: 0,
      pending_review: 0, validated: 0, applies_conditional: 0},
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [reload, setReload] = useState(0);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [hardware, setHardware] = useState([]);
  const [hardwareLoading, setHardwareLoading] = useState(false);
  const [hardwareSearch, setHardwareSearch] = useState("");
  const [selected, setSelected] = useState([]);
  const [submitting, setSubmitting] = useState(false);
  const [selectionError, setSelectionError] = useState("");
  const [generatingReport, setGeneratingReport] = useState(false);
  const [reportError, setReportError] = useState("");
  const [reportNotice, setReportNotice] = useState("");
  const modalFocus = useRef(null);

  function changeFilter(name, value) {
    const next = new URLSearchParams(params);
    if (!value || (["severity", "status"].includes(name) && value === "ALL") ||
        (name === "page" && String(value) === "1")) next.delete(name);
    else next.set(name, String(value));
    if (name !== "page") next.delete("page");
    setParams(next, { replace: name === "q" });
  }

  useEffect(() => {
    let alive = true;
    setLoading(true);
    const timer = window.setTimeout(() => {
      listCveCatalogue({ q: search, severity, status, technical: "ALL", page: requestedPage,
                         page_size: PAGE_SIZE })
        .then(data => { if (alive) setCatalogue(data); })
        .catch(err => { if (alive) setError(err.message); })
        .finally(() => { if (alive) setLoading(false); });
    }, search ? 300 : 0);
    return () => { alive = false; window.clearTimeout(timer); };
  }, [search, severity, status, requestedPage, reload]);

  useEffect(() => {
    if (!dialogOpen) return undefined;
    modalFocus.current?.focus();
    function escape(event) {
      if (event.key === "Escape" && !submitting) setDialogOpen(false);
    }
    document.addEventListener("keydown", escape);
    return () => document.removeEventListener("keydown", escape);
  }, [dialogOpen, submitting]);

  async function openDialog() {
    if (!canSearch) return;
    setDialogOpen(true);
    setSelectionError("");
    setHardwareLoading(true);
    try {
      const data = await getCpeOverview();
      setHardware(cveHardwareCandidates(data));
    } catch (err) {
      setSelectionError("No se pudo obtener el inventario CPE: " + err.message);
    } finally {
      setHardwareLoading(false);
    }
  }

  async function generateReport() {
    if (!canSearch || generatingReport) return;
    setGeneratingReport(true);
    setReportError("");
    setReportNotice("");
    try {
      const { blob, filename } = await downloadHardeningPdf();
      const objectUrl = URL.createObjectURL(blob);
      try {
        const anchor = document.createElement("a");
        anchor.href = objectUrl;
        anchor.download = filename;
        document.body.appendChild(anchor);
        try {
          anchor.click();
          setReportNotice("La descarga del informe PDF se ha iniciado.");
        } finally {
          anchor.remove();
        }
      } finally {
        // Give the browser time to start saving before releasing the blob.
        window.setTimeout(() => URL.revokeObjectURL(objectUrl), 30_000);
      }
    } catch (err) {
      setReportError(err.message || "No se pudo descargar el informe.");
    } finally {
      setGeneratingReport(false);
    }
  }

  function refreshAll() {
    setError("");
    setReload(prev => prev + 1);
  }

  const displayedHardware = useMemo(() => {
    const q = hardwareSearch.trim().toLowerCase();
    return hardware.filter(row => !q || [
      row.asset_name, row.manufacturer, row.product, row.cpu_model,
      String(row.asset_id),
    ].some(item => String(item || "").toLowerCase().includes(q)));
  }, [hardware, hardwareSearch]);

  async function queue() {
    if (submitting || !cveHardwareSelectionValid(selected)) return;
    setSelectionError("");
    setSubmitting(true);
    try {
      const response = await enqueueCveDiscovery(selected);
      setDialogOpen(false);
      setSelected([]);
      setHardwareSearch("");
      navigate("/vulnerabilities/cve/discoveries/" + response.run_id);
    } catch (err) {
      setSelectionError(err.message);
    } finally {
      setSubmitting(false);
    }
  }

  const pages = cvePageCount(catalogue.count, PAGE_SIZE);
  const currentPage = Math.min(requestedPage, pages);

  return <section className="page cve-catalogue-page">
    <header className="page-header cve-catalogue-heading">
      <div>
        <span className="page-eyebrow">VULNERABILIDADES</span>
        <h1>Análisis CVE</h1>
        <p>Vulnerabilidades oficiales de NVD y hardware relacionado mediante CPE confirmados.</p>
      </div>
      {canSearch && <div className="cve-catalogue-heading-actions">
        <button type="button" className="button-secondary"
          onClick={generateReport} disabled={generatingReport}
          aria-busy={generatingReport}>
          {generatingReport ? "Generando informe..." : "Generar informe"}
        </button>
        <button type="button" className="button-primary"
          onClick={openDialog}>Buscar CVE</button>
      </div>}
    </header>

    {reportError && <p className="error-message" role="alert">{reportError}</p>}
    {reportNotice && <p className="cve-catalogue-report-notice" role="status">{reportNotice}</p>}
    {error && <p className="error-message" role="alert">{error}</p>}

    <div className="cve-catalogue-stats" aria-label="Resumen de aplicabilidad CVE">
      <div className="cpe-overview-stat">
        <strong>{catalogue.summary?.total ?? 0}</strong><span>CVE registrados</span>
      </div>
      <div className="cpe-overview-stat">
        <strong>{catalogue.summary?.pending_review ?? 0}</strong><span>Por validar</span>
      </div>
      <div className="cpe-overview-stat cve-catalogue-validated">
        <strong>{catalogue.summary?.validated ?? 0}</strong><span>CVE validados</span>
        <div className="cve-catalogue-stat-breakdown">
          <span>Aplica: <strong>{catalogue.summary?.applies ?? 0}</strong></span>
          <span>Condicionada: <strong>{catalogue.summary?.applies_conditional ?? 0}</strong></span>
          <span>No aplica: <strong>{catalogue.summary?.not_applicable ?? 0}</strong></span>
        </div>
      </div>
    </div>

    <div className="panel cve-catalogue-panel">
      <div className="panel-header">
        <div><h2>CVE registrados</h2>
          <p>Vulnerabilidades descubiertas y resultados de evaluación del inventario.</p>
        </div>
        <span className="record-count">{catalogue.count} resultados</span>
      </div>
      <div className="cpe-overview-toolbar">
        <label className="cve-catalogue-control">
          <span>Buscar CVE o activo</span>
          <input aria-label="Buscar CVE por identificador, descripción o nombre del activo evaluado"
            type="search" value={search} placeholder="CVE-2021, descripción, PLC-TRA-01..."
            onChange={event => changeFilter("q", event.target.value)}/>
        </label>
        <label className="cve-catalogue-control">
          <span>Severidad</span>
          <select value={severity}
            onChange={event => changeFilter("severity", event.target.value)}>
            <option value="ALL">Todas</option>
            {Object.entries(CVE_SEVERITY).map(([code, label]) =>
              <option key={code} value={code}>{label}</option>)}
          </select>
        </label>
        <label className="cve-catalogue-control">
          <span>Estado del CVE</span>
          <select aria-label="Filtrar CVE por estado" value={status}
            onChange={event => changeFilter("status", event.target.value)}>
            <option value="ALL">Todos</option>
            {Object.entries(CVE_CATALOGUE_FILTER_STATES).map(([code, label]) =>
              <option key={code} value={code}>{label}</option>)}
          </select>
        </label>
        <button type="button" className="button-secondary" onClick={refreshAll}>
          Actualizar
        </button>
      </div>
      <div className="table-container">
        <table className="data-table">
          <thead><tr><th>CVE</th><th>Severidad</th><th>Descripción NVD</th>
            <th>Activos evaluados</th><th>Aplicabilidad</th><th>Acción</th></tr></thead>
          <tbody>
            {loading ? <tr><td colSpan="6">Cargando CVE...</td></tr>
            : catalogue.results.length === 0 ? <tr><td colSpan="6">
              {search || severity !== "ALL" || status !== "ALL"
                ? "No hay CVE que coincidan con estos filtros. Prueba con un identificador CVE, su descripción o el nombre de un activo evaluado."
                : "Todavía no hay CVE recuperados. Inicia una búsqueda con hardware que tenga CPE confirmados."}
            </td></tr>
            : catalogue.results.map(row => <tr key={row.cve_id}>
              <td><strong className="cve-catalogue-id">{row.cve_id}</strong>
                <small className="cve-catalogue-secondary">Registro oficial NVD</small></td>
              <td><span className="cve-catalogue-severity"
                data-severity={row.severity}>{CVE_SEVERITY[row.severity] || row.severity}</span>
                {row.base_score != null && <small className="cve-catalogue-secondary">
                  CVSS {row.base_score}</small>}</td>
              <td><p className="cve-catalogue-description">{row.description || "Sin descripción."}</p></td>
              <td><div className="cve-catalogue-related">
                {(row.related_assets || []).length ? row.related_assets.map(context =>
                  <div className="cve-catalogue-asset-context" key={context.hardware_id}>
                    <div className="cve-catalogue-asset-context-heading">
                      <span>Hardware #{context.hardware_id}</span>

                    </div>
                    {context.assets?.length ? context.assets.map(asset =>
                      <div key={asset.asset_id} className="cve-catalogue-asset-item">
                        <span>{asset.asset_type === "HARDWARE"
                          ? "Hardware · Plataforma"
                          : asset.software_type === "FIRMWARE"
                            ? "Firmware · Vulnerable" : "Software · Vulnerable"}</span>
                        <Link to={"/assets/" + asset.asset_id}
                          title={"Ver ficha técnica de " + asset.name}>
                          {asset.name}
                        </Link>
                        {asset.version && <small>Versión {asset.version}</small>}
                      </div>) : <span className="cve-catalogue-secondary">
                        Hardware #{context.hardware_id}: evidencia desactualizada
                      </span>}
                  </div>
                ) : <span className="cve-catalogue-secondary">
                  Sin activos vinculados en el inventario
                </span>}
              </div></td>
              <td>
                <span className="cve-catalogue-evaluation-status"
                  data-status={displayCveApplicability(row.applicability_status)}>
                  {CVE_EVALUATION_STATE[displayCveApplicability(row.applicability_status)]}
                </span>
                {["SYSTEM", "ANALYST"].includes(row.applicability_source) &&
                  <small className="cve-catalogue-secondary">
                    {CVE_APPLICABILITY_SOURCE[row.applicability_source]}
                  </small>}
                {row.revalidation_required &&
                  <small className="cve-catalogue-secondary">
                    Revisar evidencia anterior
                  </small>}

              </td>
              <td><Link className="button-secondary"
                to={"/vulnerabilities/cve/" + encodeURIComponent(row.cve_id) +
                  (preferredCveHardwareId(row) ?
                    "?hardware=" + preferredCveHardwareId(row) : "")}>Ver</Link></td>
            </tr>)}
          </tbody>
        </table>
      </div>
      <div className="pagination">
        <span>Página {currentPage} de {pages} · {catalogue.count} CVE</span>
        <div className="pagination-actions">
          <button type="button" disabled={currentPage === 1}
            onClick={() => changeFilter("page", currentPage - 1)}>Anterior</button>
          <button type="button" disabled={currentPage >= pages}
            onClick={() => changeFilter("page", currentPage + 1)}>Siguiente</button>
        </div>
      </div>
    </div>

    <p className="cve-overview-disclaimer">
      Una búsqueda por CPE de hardware identifica CVE candidatos.
      VISOR OT evalúa sus configuraciones pertinentes con el inventario vigente:
      puede concluir «Aplica», «No aplica» o dejar la evaluación pendiente.
      «No aplica» automático se limita al alcance NVD del hardware y no demuestra
      ausencia de otro software ni sustituye los avisos del fabricante.
      El analista puede revisar la conclusión con justificación e historial.
      Abre «Ver» para consultar las condiciones y la evidencia.
    </p>

    {dialogOpen && <div className="cpe-bulk-overlay">
      <div className="cpe-bulk-dialog cve-catalogue-dialog" role="dialog"
        aria-modal="true" aria-labelledby="cve-search-dialog-title">
        <div className="cpe-bulk-dialog-heading">
          <div><span className="page-eyebrow">DESCUBRIMIENTO NVD</span>
            <h2 id="cve-search-dialog-title">Buscar CVE por hardware</h2></div>
          <button type="button" className="cpe-bulk-close" aria-label="Cerrar"
            disabled={submitting} onClick={() => setDialogOpen(false)}>×</button>
        </div>
        <p>Selecciona hardware con CPE confirmados. También se consultarán los
          CPE oficiales del software que esté instalado y vigente en cada equipo.</p>
        <input ref={modalFocus} type="search"
          className="cve-catalogue-hardware-search"
          aria-label="Filtrar hardware" placeholder="Filtrar hardware..."
          value={hardwareSearch} onChange={event => setHardwareSearch(event.target.value)}/>
        <div className="cve-catalogue-hardware-list">
          {hardwareLoading ? <p>Cargando hardware...</p>
            : displayedHardware.length === 0 ? <p>
              No hay hardware con CPE confirmados que coincida con la búsqueda.
              Revisa primero el módulo Identificación CPE.
            </p> : displayedHardware.map(row => <label key={row.asset_id}
              className="cve-catalogue-hardware-row">
              <input type="checkbox" checked={selected.includes(row.asset_id)}
                disabled={submitting || (!selected.includes(row.asset_id) && selected.length >= 100)}
                onChange={() => setSelected(current => toggleCveHardwareSelection(
                  current, row.asset_id
                ))}/>
              <span><strong>{row.asset_name}</strong>
                <small>Hardware #{row.asset_id} · {row.manufacturer} {row.product}
                  {" · "}{row.confirmed_count} CPE confirmados</small>
              </span></label>)}
        </div>
        <div className="cve-catalogue-dialog-foot">
          <span>{selected.length} hardware seleccionados · máximo 100</span>
          <button type="button" className="button-secondary"
            disabled={!displayedHardware.length || submitting}
            onClick={() => setSelected(current => {
              const visibleIds = displayedHardware.map(row => row.asset_id);
              const allSelected = visibleIds.every(id => current.includes(id));
              return allSelected ? current.filter(id => !visibleIds.includes(id))
                : [...new Set([...current, ...visibleIds])].slice(0, 100);
            })}>Seleccionar / quitar visibles</button>
        </div>
        {selectionError && <p className="error-message" role="alert">{selectionError}</p>}
        <p className="cve-catalogue-disclaimer">
          El backend validará de nuevo la vigencia de los CPE antes de enviar
          consultas a NVD. Solo se confirmarán automáticamente las correspondencias verificadas.
        </p>
        <div className="cpe-bulk-dialog-actions">
          <button type="button" className="button-secondary"
            disabled={submitting} onClick={() => setDialogOpen(false)}>Cancelar</button>
          <button type="button" className="button-primary"
            disabled={submitting || !cveHardwareSelectionValid(selected)}
            onClick={queue}>{submitting ? "Registrando..." : "Confirmar búsqueda"}</button>
        </div>
      </div>
    </div>}
  </section>;
}
