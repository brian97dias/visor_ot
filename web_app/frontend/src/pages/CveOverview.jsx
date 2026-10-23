import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useOutletContext, useSearchParams } from "react-router-dom";

import { getCpeOverview } from "../api/vulnerabilities";
import {
  enqueueCveDiscovery, listCveCatalogue, listCveDiscoveryRuns,
} from "../api/vulnerabilities";
import SuccessNotice from "../components/SuccessNotice";
import {
  CVE_DISCOVERY_STATE, CVE_EVALUATION_STATE, CVE_EVALUATION_HELP,
  CVE_TECHNICAL_STATE, CVE_TECHNICAL_FILTER,
  CVE_SEVERITY, cveHardwareCandidates,
  cveHardwareSelectionValid, cvePageCount, isCveDiscoveryActive,
  toggleCveHardwareSelection,
} from "../utils/cveCataloguePresentation";
import { readCpePage } from "../utils/cpeOverviewUrlState";

const PAGE_SIZE = 15;
const POLL_MS = 10000;
const POLL_LIMIT_MS = 5 * 60 * 1000;

export default function CveOverview() {
  const { user } = useOutletContext();
  const canSearch = ["ADMIN", "ANALYST"].includes(user?.role);
  const [params, setParams] = useSearchParams();
  const search = params.get("q") || "";
  const severity = params.get("severity") || "ALL";
  const status = params.get("status") || "ALL";
  const technical = params.get("technical") || "ALL";
  const requestedPage = readCpePage(params.get("page"));
  const [catalogue, setCatalogue] = useState({ count: 0, results: [], page: 1 });
  const [runs, setRuns] = useState([]);
  const [loading, setLoading] = useState(true);
  const [runsLoading, setRunsLoading] = useState(true);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [reload, setReload] = useState(0);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [hardware, setHardware] = useState([]);
  const [hardwareLoading, setHardwareLoading] = useState(false);
  const [hardwareSearch, setHardwareSearch] = useState("");
  const [selected, setSelected] = useState([]);
  const [submitting, setSubmitting] = useState(false);
  const [selectionError, setSelectionError] = useState("");
  const [pollingPaused, setPollingPaused] = useState(false);
  const pollStarted = useRef(null);
  const modalFocus = useRef(null);
  const active = runs.some(run => isCveDiscoveryActive(run.status));

  function changeFilter(name, value) {
    const next = new URLSearchParams(params);
    if (!value || (["severity", "status", "technical"].includes(name) && value === "ALL") ||
        (name === "page" && String(value) === "1")) next.delete(name);
    else next.set(name, String(value));
    if (name !== "page") next.delete("page");
    setParams(next, { replace: name === "q" });
  }

  useEffect(() => {
    let alive = true;
    setLoading(true);
    const timer = window.setTimeout(() => {
      listCveCatalogue({ q: search, severity, status, technical, page: requestedPage,
                         page_size: PAGE_SIZE })
        .then(data => { if (alive) setCatalogue(data); })
        .catch(err => { if (alive) setError(err.message); })
        .finally(() => { if (alive) setLoading(false); });
    }, search ? 300 : 0);
    return () => { alive = false; window.clearTimeout(timer); };
  }, [search, severity, status, technical, requestedPage, reload]);

  useEffect(() => {
    let alive = true;
    listCveDiscoveryRuns()
      .then(data => { if (alive) setRuns(data); })
      .catch(err => { if (alive) setError(err.message); })
      .finally(() => { if (alive) setRunsLoading(false); });
    return () => { alive = false; };
  }, []);

  useEffect(() => {
    if (!active || pollingPaused) {
      if (!active) pollStarted.current = null;
      return undefined;
    }
    if (pollStarted.current === null) pollStarted.current = Date.now();
    let alive = true;
    const timer = window.setInterval(async () => {
      if (Date.now() - pollStarted.current > POLL_LIMIT_MS) {
        if (alive) setPollingPaused(true);
        return;
      }
      try {
        const items = await listCveDiscoveryRuns();
        if (alive) {
          setRuns(items);
          // Refresh CVE catalogue as each page may have produced new candidates.
          setReload(prev => prev + 1);
        }
      } catch (err) {
        if (alive) setError(err.message);
      }
    }, POLL_MS);
    return () => { alive = false; window.clearInterval(timer); };
  }, [active, pollingPaused]);

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

  async function refreshAll() {
    setError("");
    setPollingPaused(false);
    pollStarted.current = Date.now();
    try {
      const list = await listCveDiscoveryRuns();
      setRuns(list);
      setReload(prev => prev + 1);
    } catch (err) {
      setError(err.message);
    }
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
      setNotice((response.reused ? "Se reutilizó" : "Se creó") +
        " la búsqueda CVE #" + response.run_id + ". El worker NVD la procesará.");
      setDialogOpen(false);
      setSelected([]);
      setHardwareSearch("");
      await refreshAll();
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
      {canSearch && <button type="button" className="button-primary"
        onClick={openDialog}>Buscar CVE</button>}
    </header>

    <SuccessNotice message={notice} onClose={() => setNotice("")}
      durationMs={30000}/>
    {error && <p className="error-message" role="alert">{error}</p>}

    <div className="cve-catalogue-stats">
      <div className="cpe-overview-stat"><strong>{runs.length}</strong>
        <span>Búsquedas recientes</span></div>
      <div className="cpe-overview-stat"><strong>
        {runs.filter(run => isCveDiscoveryActive(run.status)).length}</strong>
        <span>En cola o proceso</span></div>
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
          <span>Buscar CVE</span>
          <input aria-label="Buscar CVE por identificador o descripción"
            type="search" value={search} placeholder="CVE-2021, componente..."
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
            {Object.entries(CVE_EVALUATION_STATE).map(([code, label]) =>
              <option key={code} value={code}>{label}</option>)}
          </select>
        </label>
        <label className="cve-catalogue-control">
          <span>Resultado técnico</span>
          <select aria-label="Filtrar por evaluación técnica" value={technical}
            onChange={event => changeFilter("technical", event.target.value)}>
            <option value="ALL">Todos</option>
            {Object.entries(CVE_TECHNICAL_FILTER).map(([code, label]) =>
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
            <th>Activos relacionados</th><th>Estado</th><th>Resultado técnico</th><th>Acción</th></tr></thead>
          <tbody>
            {loading ? <tr><td colSpan="7">Cargando CVE...</td></tr>
            : catalogue.results.length === 0 ? <tr><td colSpan="7">
              No hay CVE recuperados para estos filtros. Inicia una búsqueda
              con hardware que tenga CPE confirmados.
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
                    {context.assets?.length ? context.assets.map(asset =>
                      <div key={asset.asset_id} className="cve-catalogue-asset-item">
                        <span>{asset.asset_type === "HARDWARE" ? "Hardware" :
                          asset.software_type === "FIRMWARE" ? "Firmware" : "Software"}</span>
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
                  data-status={row.evaluation_status || "PENDING_REVIEW"}>
                  {CVE_EVALUATION_STATE[row.evaluation_status] ||
                    CVE_EVALUATION_STATE.PENDING_REVIEW}
                </span>
                <small className="cve-catalogue-secondary">
                  {CVE_EVALUATION_HELP[row.evaluation_status] ||
                    CVE_EVALUATION_HELP.PENDING_REVIEW}
                </small>
              </td>
              <td>
                <span className="cve-technical-tag" data-result={row.technical_result}>
                  {CVE_TECHNICAL_STATE[row.technical_result] ||
                    CVE_TECHNICAL_STATE.INDETERMINATE}
                </span>
                <small className="cve-catalogue-secondary">
                  Calculado con CPE, instalación y versión vigentes
                </small>
              </td>
              <td><Link className="button-secondary"
                to={"/vulnerabilities/cve/" + encodeURIComponent(row.cve_id)}>Ver</Link></td>
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

    <section className="panel cve-catalogue-jobs" aria-labelledby="cve-jobs-title">
      <div className="panel-header">
        <div><h2 id="cve-jobs-title">Búsquedas CVE recientes</h2>
          <p>Seguimiento de trabajos enviados al worker NVD.</p></div>
        <button type="button" className="button-secondary" onClick={refreshAll}>
          Actualizar estado
        </button>
      </div>
      {runsLoading ? <p className="cve-catalogue-empty">Cargando trabajos...</p>
        : runs.length === 0 ? <p className="cve-catalogue-empty">
          Todavía no hay búsquedas CVE registradas.</p> : <div className="table-container">
          <table className="data-table">
            <thead><tr><th>Búsqueda</th><th>Estado</th><th>CPE procesados</th>
              <th>CVE encontrados</th><th>Acción</th></tr></thead>
            <tbody>{runs.slice(0, 10).map(run => <tr key={run.run_id}>
              <td><strong>#{run.run_id}</strong><small className="cve-catalogue-secondary">
                {run.selected_hardware_ids.length} hardware seleccionados</small></td>
              <td><span className="cve-catalogue-job-status" data-status={run.status}>
                {CVE_DISCOVERY_STATE[run.status] || run.status}</span>
                {run.error_message && <small className="cve-catalogue-job-error">
                  {run.error_message}</small>}</td>
              <td>{run.completed_queries} / {run.query_count}</td>
              <td>{run.retrieved_occurrences} <small className="cve-catalogue-inline-note">
                coincidencias</small></td>
              <td><Link className="button-secondary"
                to={"/vulnerabilities/cve/discoveries/" + run.run_id}>Ver progreso</Link></td>
            </tr>)}</tbody>
          </table>
        </div>}
      {pollingPaused && active && <p className="cve-catalogue-empty">
        Actualización automática pausada. Puedes consultar el estado manualmente.
      </p>}
    </section>
    <p className="cve-overview-disclaimer">
      Un CVE encontrado por CPE es un hallazgo candidato: no significa que afecte
      automáticamente al hardware. Abre «Ver» para revisar sus condiciones NVD
      y las evidencias del inventario. Las decisiones siempre requieren verificación.
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
          consultas a NVD. Ningún hallazgo se confirmará automáticamente.
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
