import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useOutletContext, useSearchParams } from "react-router-dom";
import { CPE_OVERVIEW_PAGE_SIZE, readCpePage, updateCpeOverviewParams } from "../utils/cpeOverviewUrlState";
import {
  getCpeOverview, startCpeSearch, startBulkCpeSearch,
} from "../api/vulnerabilities";
import { cpeCountDetails } from "../utils/cpeOverviewPresentation";
import { togglePageSelection, toggleRowSelection, countSelectedTypes } from "../utils/cpeBulkSelection";
import ExternalCpeModal from "../components/ExternalCpeModal";

const STATUS = {
  NOT_SEARCHED: "Sin búsqueda",
  QUEUED: "En cola",
  RUNNING: "Consultando NVD",
  TO_REVIEW: "Por revisar",
  IN_REVIEW: "En revisión",
  EVALUATED: "Evaluado",
  PARTIAL_RESULTS: "Resultados parciales",
  NO_RESULTS: "Sin resultados",
  FAILED: "Error de consulta",
  STALE: "Revisión necesaria",
};
const OUTCOME = {
  QUEUED: "En cola",
  REUSED: "Ya estaba en cola",
  SKIPPED: "No procesado",
  NOT_FOUND: "Activo inexistente",
  INVALID_IDENTITY: "Identidad técnica incompleta",
};
const MAX_BULK_ASSETS = 100;
const POLL_MS = 10000;
const POLL_LIMIT_MS = 5 * 60 * 1000;

export default function CpeOverview() {
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [selectedIds, setSelectedIds] = useState([]);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [bulkWorking, setBulkWorking] = useState(false);
  const [bulkResult, setBulkResult] = useState(null);
  const [bulkError, setBulkError] = useState("");
  const [individualWorking, setIndividualWorking] = useState([]);
  const [externalCpeAsset, setExternalCpeAsset] = useState(null);
  const externalTriggerFocus = useRef(null);

  const [pollingPaused, setPollingPaused] = useState(false);
  const pollStartedAt = useRef(null);
  const dialogFocus = useRef(null);
  const [searchParams, setSearchParams] = useSearchParams();
  const { user } = useOutletContext();
  const canSearch = ["ADMIN", "ANALYST"].includes(user?.role);
  const filter = searchParams.get("status") || "ALL";
  const assetType = searchParams.get("type") || "ALL";
  const search = searchParams.get("q") || "";

  function changeFilter(key, value) {
    setSearchParams(updateCpeOverviewParams(searchParams, key, value),
      { replace: key === "q" });
  }

  async function refreshOverview() {
    const items = await getCpeOverview();
    setRows(items);
    setSelectedIds(current => current.filter(id => items.some(row => row.asset_id === id)));
    return items;
  }

  useEffect(() => {
    let active = true;
    setLoading(true);
    getCpeOverview()
      .then(items => { if (active) setRows(items); })
      .catch(err => { if (active) setError(err.message); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, []);

  const visible = useMemo(() => rows.filter(row => {
    if (assetType !== "ALL" && row.asset_type !== assetType) return false;
    if (filter !== "ALL" && filter !== row.identification_status) return false;
    const query = search.trim().toLowerCase();
    return !query || [
      row.asset_name, row.manufacturer, row.product, row.version, row.cpu_model, row.role,
    ].some(value => String(value || "").toLowerCase().includes(query));
  }), [rows, filter, assetType, search]);

  const totalPages = Math.max(1, Math.ceil(visible.length / CPE_OVERVIEW_PAGE_SIZE));
  const currentPage = Math.min(readCpePage(searchParams.get("page")), totalPages);
  const currentRows = visible.slice(
    (currentPage - 1) * CPE_OVERVIEW_PAGE_SIZE, currentPage * CPE_OVERVIEW_PAGE_SIZE
  );
  const pageIds = currentRows.map(row => row.asset_id);
  const selectedRows = useMemo(() => {
    const lookup = new Map(rows.map(row => [row.asset_id, row]));
    return selectedIds.map(id => lookup.get(id)).filter(Boolean);
  }, [rows, selectedIds]);
  const selectedTypeCounts = countSelectedTypes(selectedRows);
  const allPageSelected = pageIds.length > 0 && pageIds.every(id => selectedIds.includes(id));
  const partialPage = !allPageSelected && pageIds.some(id => selectedIds.includes(id));
  const pageCheckboxRef = useRef(null);
  useEffect(() => {
    if (pageCheckboxRef.current) pageCheckboxRef.current.indeterminate = partialPage;
  }, [partialPage, currentPage, visible.length]);

  const count = state => rows.filter(row => row.identification_status === state).length;
  const hardwareCount = rows.filter(row => row.asset_type === "HARDWARE").length;
  const softwareCount = rows.filter(row => row.asset_type === "SOFTWARE").length;
  const processing = count("QUEUED") + count("RUNNING");
  const confirmed = rows.filter(row => row.confirmed_count > 0).length;
  const toReview = count("TO_REVIEW") + count("IN_REVIEW");

  useEffect(() => {
    if (processing === 0) {
      pollStartedAt.current = null;
      return;
    }
    if (pollingPaused) return;
    if (pollStartedAt.current === null) pollStartedAt.current = Date.now();
    let active = true;
    const timer = window.setInterval(async () => {
      if (Date.now() - pollStartedAt.current >= POLL_LIMIT_MS) {
        if (active) setPollingPaused(true);
        return;
      }
      try {
        const items = await getCpeOverview();
        if (active) setRows(items);
      } catch (err) {
        if (active) setError(err.message);
      }
    }, POLL_MS);
    return () => { active = false; window.clearInterval(timer); };
  }, [processing, pollingPaused]);

  useEffect(() => {
    if (!dialogOpen) return;
    dialogFocus.current?.focus();
    function onEscape(event) {
      if (event.key === "Escape" && !bulkWorking) setDialogOpen(false);
    }
    document.addEventListener("keydown", onEscape);
    return () => document.removeEventListener("keydown", onEscape);
  }, [dialogOpen, bulkWorking, bulkResult]);

  function openExternalCpe(row) {
    if (!canSearch || dialogOpen) return;
    externalTriggerFocus.current = document.activeElement;
    setExternalCpeAsset(row);
  }

  function closeExternalCpe() {
    setExternalCpeAsset(null);
    // Restore focus to the button which opened the form.
    window.requestAnimationFrame(() => externalTriggerFocus.current?.focus());
  }

  function openConfirmation() {
    if (!selectedRows.length) return;
    setBulkError("");
    setBulkResult(null);
    setDialogOpen(true);
  }

  async function queueIndividual(row) {
    if (individualWorking.includes(row.asset_id)) return;
    setIndividualWorking(current => [...current, row.asset_id]);
    setNotice("");
    setError("");
    try {
      const result = await startCpeSearch(row.asset_id, "SPECIFIC");
      setNotice("Se registró o reutilizó la búsqueda de " + row.asset_name +
        " (trabajo #" + result.run_id + "). Se procesará en la cola NVD.");
      pollStartedAt.current = Date.now();
      setPollingPaused(false);
      try {
        await refreshOverview();
      } catch (refreshError) {
        setError("La búsqueda ya está registrada, pero no se pudo actualizar la tabla: " +
          refreshError.message);
      }
    } catch (err) {
      setError("No se pudo solicitar la búsqueda de " + row.asset_name + ": " + err.message);
    } finally {
      setIndividualWorking(current => current.filter(id => id !== row.asset_id));
    }
  }

  async function queueBulk() {
    if (!selectedRows.length || selectedRows.length > MAX_BULK_ASSETS || bulkWorking) return;
    setBulkWorking(true);
    setBulkError("");
    setError("");
    setNotice("");
    try {
      const result = await startBulkCpeSearch(selectedRows.map(row => row.asset_id));
      setBulkResult(result);
      setSelectedIds([]);
      setNotice("Solicitud masiva registrada: " + result.summary.queued + " encoladas, " +
        result.summary.reused + " reutilizadas, " + result.summary.skipped +
        " omitidas y " + result.summary.failed + " con error.");
      pollStartedAt.current = Date.now();
      setPollingPaused(false);
      try {
        await refreshOverview();
      } catch (refreshError) {
        setBulkError("Los trabajos ya fueron registrados, pero falló la actualización " +
          "de la tabla: " + refreshError.message);
      }
    } catch (err) {
      setBulkError(err.message);
    } finally {
      setBulkWorking(false);
    }
  }

  return <section className="page">
    <header className="page-header">
      <div><span className="page-eyebrow">VULNERABILIDADES</span>
        <h1>Identificación CPE</h1>
        <p>Supervisión de búsquedas y candidatos de los activos inventariados.</p>
      </div>
    </header>
    <div className="cpe-overview-stats" aria-label="Resumen de búsquedas CPE">
      <div className="cpe-overview-stat">
        <strong>{rows.length}</strong><span>Activos vigentes</span>
        <small>{hardwareCount} hardware · {softwareCount} software</small>
      </div>
      <div className="cpe-overview-stat"><strong>{toReview}</strong><span>Con CPE por revisar</span></div>
      <div className="cpe-overview-stat"><strong>{confirmed}</strong><span>Con algún CPE confirmado</span></div>
      <div className="cpe-overview-stat"><strong>{processing}</strong><span>En cola o consultando</span></div>
    </div>

    <section className="panel">
      <div className="panel-header">
        <div><h2>Identificaciones del inventario</h2>
          <p>Un candidato descubierto todavía no constituye una asociación CPE confirmada.</p></div>
        <span className="record-count">{visible.length} resultados</span>
      </div>
      <div className="cpe-overview-toolbar">
        <input type="search" aria-label="Buscar activos para identificar CPE"
          placeholder="Buscar activo, fabricante, producto, versión o CPU..."
          value={search} onChange={event => changeFilter("q", event.target.value)}/>
        <select aria-label="Filtrar tipo de activo CPE"
          value={assetType} onChange={event => changeFilter("type", event.target.value)}>
          <option value="ALL">Hardware y Software</option>
          <option value="HARDWARE">Solo Hardware</option>
          <option value="SOFTWARE">Solo Software</option>
        </select>
        <select aria-label="Filtrar estado de identificación CPE"
          value={filter} onChange={event => changeFilter("status", event.target.value)}>
          <option value="ALL">Todos los estados</option>
          {Object.entries(STATUS).map(([value, label]) =>
            <option value={value} key={value}>{label}</option>)}
        </select>
      </div>

      {notice && <div className="cpe-bulk-notice" role="status">{notice}</div>}
      {error && <div className="error-message" role="alert">{error}</div>}
      {processing > 0 && <div className="cpe-bulk-progress" role="status">
        <span>{processing} búsqueda(s) en cola o procesándose en PostgreSQL.
          {" "}El worker NVD las ejecutará secuencialmente.</span>
        {pollingPaused
          ? <button type="button" className="button-secondary"
              onClick={async () => {
                setError("");
                try {
                  await refreshOverview();
                  pollStartedAt.current = Date.now();
                  setPollingPaused(false);
                } catch (err) { setError(err.message); }
              }}>Consultar estado</button>
          : <span className="cpe-bulk-progress-note">Actualización automática cada 10 s
            (hasta 5 min)</span>}
      </div>}

      {selectedRows.length > 0 && <div className="cpe-bulk-selection-bar" role="region"
          aria-label="Acciones para activos seleccionados">
        <strong>{selectedRows.length} activos seleccionados</strong>
        <span>{selectedTypeCounts.hardware} hardware · {selectedTypeCounts.software} software</span>
        <button className="button-primary" type="button" disabled={!canSearch}
          title={!canSearch ? "Solo analistas y administradores pueden solicitar búsquedas" : undefined}
          onClick={openConfirmation}>
          Buscar CPE
        </button>
        <button type="button" className="button-secondary" onClick={() => setSelectedIds([])}>
          Limpiar selección
        </button>
      </div>}

      {loading ? <div className="empty-state">Cargando estados CPE...</div>
        : !error && visible.length === 0
          ? <div className="empty-state">No hay activos que coincidan con estos filtros.</div>
          : <div className="table-container">
            <table className="data-table cpe-bulk-table">
              <thead><tr>
                <th className="cpe-select-cell">
                  <input type="checkbox" ref={pageCheckboxRef}
                    aria-label="Seleccionar activos de esta página" checked={allPageSelected}
                    disabled={pageIds.length === 0}
                    onChange={event => setSelectedIds(current =>
                      togglePageSelection(current, pageIds, event.target.checked))}/>
                </th>
                <th>Activo</th><th>Identidad técnica</th>
                <th>Estado</th><th>CPE</th><th>Acciones</th>
              </tr></thead>
              <tbody>{currentRows.map(row => <tr key={row.asset_id}
                  className={selectedIds.includes(row.asset_id) ? "cpe-row-selected" : ""}>
                <td className="cpe-select-cell">
                  <input type="checkbox" checked={selectedIds.includes(row.asset_id)}
                    aria-label={"Seleccionar " + row.asset_name}
                    onChange={event => setSelectedIds(current =>
                      toggleRowSelection(current, row.asset_id, event.target.checked))}/>
                </td>
                <td><Link className="cpe-overview-asset-link" to={"/assets/" + row.asset_id}
                    title={"Ver detalle de " + row.asset_name}>
                    {row.asset_name}
                  </Link>
                  <div className="cpe-overview-subtitle">
                    #{row.asset_id} · {row.asset_type === "HARDWARE" ? "Hardware" : "Software"}
                  </div>
                </td>
                <td>{row.manufacturer || "Fabricante desconocido"}
                  <div className="cpe-overview-subtitle">
                    {row.product || "Producto sin registrar"}
                    {row.cpu_model && " · CPU " + row.cpu_model}
                    {row.version && " · " + row.version}
                  </div>
                </td>
                <td><span className="cpe-overview-status" data-status={row.identification_status}>
                    {row.identification_status === "TO_REVIEW"
                      && row.exploratory_count > 0 && row.unreviewed_count === 0
                      ? "Revisión exploratoria" : (STATUS[row.identification_status] || row.identification_status)}
                  </span>
                  {row.last_search_at && <div className="cpe-overview-subtitle">
                    {new Date(row.last_search_at).toLocaleString("es-CO")}
                  </div>}
                </td>
                <td>{row.run_id
                  ? <div className="cpe-overview-counts">
                      <strong>{row.candidate_count} encontrados</strong>
                      {row.exploratory_count > 0 && <div className="cpe-overview-subtitle">
                        {row.exploratory_count} correspondencia(s) débil(es), no pendientes obligatorios
                      </div>}
                      <div className="cpe-overview-subtitle cpe-breakdown">
                        {cpeCountDetails(row).map((part, index) => (
                          <span key={part.key} className={"cpe-count-" + part.key}>
                            {index > 0 ? " · " : ""}{part.count} {part.label}
                          </span>
                        ))}
                      </div>
                      {row.legacy_pending_count > 0 && <div className="cpe-overview-subtitle">
                        {row.legacy_pending_count} pendiente(s) histórico(s) incluido(s) en por revisar
                      </div>}
                      {row.out_of_scope_count > 0 && <div className="cpe-overview-subtitle">
                        {row.out_of_scope_count} decisión(es) fuera de la búsqueda actual
                      </div>}
                    </div> : "—"}
                </td>
                <td><div className="cpe-row-actions">
                  <button type="button" className="button-primary"
                    disabled={!canSearch || individualWorking.includes(row.asset_id)}
                    onClick={() => queueIndividual(row)}>
                    {individualWorking.includes(row.asset_id) ? "Solicitando..." : "Buscar"}
                  </button>
                  <Link className="button-secondary" to={"/assets/" + row.asset_id + "/cpe"}
                    state={{ fromCpeOverview: true, cpeOverviewSearch: "?" + searchParams.toString() }}>
                    Revisar
                  </Link>
                  {canSearch && <button type="button" className="button-secondary"
                    aria-label={"Agregar CPE por ID a " + row.asset_name}
                    onClick={() => openExternalCpe(row)}>
                    Agregar CPE por ID
                  </button>}
                </div></td>
              </tr>)}</tbody>
            </table>
          </div>}
      {!loading && visible.length > 0 && totalPages > 1 && (
        <div className="pagination">
          <span>Página {currentPage} de {totalPages} · {visible.length} resultados</span>
          <div className="pagination-actions">
            <button type="button" disabled={currentPage <= 1}
              onClick={() => changeFilter("page", currentPage - 1)}>Anterior</button>
            <button type="button" disabled={currentPage >= totalPages}
              onClick={() => changeFilter("page", currentPage + 1)}>Siguiente</button>
          </div>
        </div>
      )}
      <p className="cpe-overview-note">
        La selección admite hardware y software y se conserva al cambiar filtros o página.
        La búsqueda individual y la masiva se inician únicamente cuando el analista
        pulsa Buscar. El motor amplía automáticamente las consultas cuando hace falta.
        Agregar CPE por ID verifica un registro oficial sin confirmarlo automáticamente;
        los contadores de esta tabla reflejan solo el descubrimiento automático.
      </p>
    </section>

    {externalCpeAsset && <ExternalCpeModal key={externalCpeAsset.asset_id}
      asset={externalCpeAsset} allowed={canSearch} onClose={closeExternalCpe}
      onReviewed={async () => {
        try { await refreshOverview(); }
        catch (refreshError) {
          setNotice("La decisión se guardó; no se pudo refrescar el listado: " +
            refreshError.message);
        }
      }}/>}
    {dialogOpen && <div className="cpe-bulk-overlay">
      <div className="cpe-bulk-dialog" role="dialog" aria-modal="true"
        aria-labelledby="cpe-bulk-title" aria-describedby="cpe-bulk-description">
        {!bulkResult ? <>
          <div className="cpe-bulk-dialog-heading">
            <div><span className="page-eyebrow">IDENTIFICACIÓN CPE</span>
              <h2 id="cpe-bulk-title">Confirmar búsqueda CPE</h2></div>
            <button type="button" aria-label="Cerrar confirmación"
              disabled={bulkWorking} className="cpe-bulk-close"
              onClick={() => setDialogOpen(false)}>×</button>
          </div>
          <p id="cpe-bulk-description">
            ¿Iniciar la búsqueda de candidatos para <strong>{selectedRows.length} activos</strong>?
          </p>
          <div className="cpe-bulk-preview">
            {selectedRows.map(row => <div key={row.asset_id} className="cpe-bulk-preview-item">
              <strong>{row.asset_name}</strong>
              <span>{row.asset_type === "HARDWARE" ? "Hardware" : "Software"} · #{row.asset_id}</span>
            </div>)}
          </div>
          <div className="cpe-bulk-metadata">
            <div><span>Alcance</span><strong>Específico (por defecto)</strong></div>
            <div><span>Procesamiento</span><strong>Cola secuencial NVD</strong></div>
            <div><span>Confirmación CPE</span><strong>Manual, posteriormente</strong></div>
          </div>

          {selectedRows.length > MAX_BULK_ASSETS && <p className="cpe-bulk-warning" role="alert">
            Máximo {MAX_BULK_ASSETS} activos por solicitud. Reduce la selección antes de continuar.
          </p>}
          <p className="cpe-bulk-hint">
            Los trabajos se conservarán en PostgreSQL aunque abandones esta página.
            Las búsquedas existentes en cola se reutilizarán y ninguna coincidencia CPE
            se confirmará automáticamente.
          </p>
          {bulkError && <p className="error-message" role="alert">{bulkError}</p>}
          <div className="cpe-bulk-dialog-actions">
            <button type="button" ref={dialogFocus} className="button-secondary"
              disabled={bulkWorking} onClick={() => setDialogOpen(false)}>Cancelar</button>
            <button type="button" className="button-primary" disabled={bulkWorking ||
              selectedRows.length > MAX_BULK_ASSETS} onClick={queueBulk}>
              {bulkWorking ? "Registrando..." : "Confirmar y poner en cola"}
            </button>
          </div>
        </> : <>
          <div className="cpe-bulk-dialog-heading">
            <div><span className="page-eyebrow">IDENTIFICACIÓN CPE</span>
              <h2 id="cpe-bulk-title">Resultado de la solicitud</h2></div>
          </div>
          <p id="cpe-bulk-description">
            {bulkResult.summary.queued} encoladas · {bulkResult.summary.reused} reutilizadas ·
            {" "}{bulkResult.summary.skipped} omitidas · {bulkResult.summary.failed} con error.
          </p>
          <div className="cpe-bulk-preview">
            {bulkResult.results.map(row => <div key={row.asset_id}
                className="cpe-bulk-preview-item">
              <strong>{row.asset_name || "Activo #" + row.asset_id}</strong>
              <span className={"cpe-bulk-result-" + row.outcome.toLowerCase()}>
                {OUTCOME[row.outcome] || row.outcome}
                {row.run_id ? " · Trabajo #" + row.run_id : ""}
              </span>
              {row.message && <small>{row.message}</small>}
            </div>)}
          </div>
          <p className="cpe-bulk-hint">
            La API registró los trabajos, pero el worker NVD deberá procesarlos.
            Para ello debe estar ejecutándose <code>python manage.py run_cpe_worker</code>
            en otra terminal. Consulta sus estados desde esta misma tabla.
          </p>
          {bulkError && <p className="error-message" role="alert">{bulkError}</p>}
          <div className="cpe-bulk-dialog-actions">
            <button className="button-primary" type="button" ref={dialogFocus}
              onClick={() => setDialogOpen(false)}>Volver a Identificación CPE</button>
          </div>
        </>}
      </div>
    </div>}
  </section>;
}
