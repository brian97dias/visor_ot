import { useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { CPE_OVERVIEW_PAGE_SIZE, readCpePage, updateCpeOverviewParams } from "../utils/cpeOverviewUrlState";
import { getCpeOverview } from "../api/vulnerabilities";

const STATUS = {
  NOT_SEARCHED: "Sin búsqueda",
  QUEUED: "En cola",
  RUNNING: "Consultando NVD",
  CANDIDATES: "Candidatos por revisar",
  NO_RESULTS: "Sin resultados",
  FAILED: "Error de consulta",
  STALE: "Identidad modificada",
  NOT_SUPPORTED: "Software: disponible en fase 4",
  CONFIRMED: "CPE confirmado",
  PENDING_VALIDATION: "Validación pendiente",
  REOPENED: "Revisión reabierta",
};

export default function CpeOverview() {
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  // Share the same URL-state pattern as Inventory and Communications.
  const [searchParams, setSearchParams] = useSearchParams();
  const filter = searchParams.get("status") || "ALL";
  const assetType = searchParams.get("type") || "ALL";
  const search = searchParams.get("q") || "";
  function changeFilter(key, value) {
    setSearchParams(updateCpeOverviewParams(searchParams, key, value),
      { replace: key === "q" });
  }

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError("");
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
      row.asset_name, row.manufacturer, row.product, row.cpu_model, row.role,
    ].some(value => String(value || "").toLowerCase().includes(query));
  }), [rows, filter, assetType, search]);

  const totalPages = Math.max(1, Math.ceil(visible.length / CPE_OVERVIEW_PAGE_SIZE));
  const currentPage = Math.min(readCpePage(searchParams.get("page")), totalPages);
  const currentRows = visible.slice(
    (currentPage - 1) * CPE_OVERVIEW_PAGE_SIZE, currentPage * CPE_OVERVIEW_PAGE_SIZE
  );

  const count = state => rows.filter(row => row.identification_status === state).length;
  const hardwareCount = rows.filter(row => row.asset_type === "HARDWARE").length;
  const softwareCount = rows.filter(row => row.asset_type === "SOFTWARE").length;
  const processing = count("QUEUED") + count("RUNNING");
  const confirmed = count("CONFIRMED");

  return <section className="page">
    <header className="page-header">
      <div>
        <span className="page-eyebrow">VULNERABILIDADES</span>
        <h1>Identificación CPE</h1>
        <p>Supervisión de búsquedas y candidatos de los activos inventariados.</p>
      </div>
    </header>
    <div className="cpe-overview-stats" aria-label="Resumen de búsquedas CPE">
      <div className="cpe-overview-stat">
        <strong>{rows.length}</strong><span>Activos vigentes</span>
        <small>{hardwareCount} hardware · {softwareCount} software</small>
      </div>
      <div className="cpe-overview-stat"><strong>{count("CANDIDATES")}</strong><span>Con candidatos para revisar</span></div>
      <div className="cpe-overview-stat"><strong>{confirmed}</strong><span>Con CPE confirmado</span></div>
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
          placeholder="Buscar por activo, fabricante, modelo o CPU..."
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
      {error && <div className="error-message" role="alert">{error}</div>}
      {loading ? <div className="empty-state">Cargando estados CPE...</div>
        : !error && visible.length === 0
          ? <div className="empty-state">No hay activos que coincidan con estos filtros.</div>
          : !error && <div className="table-container">
            <table className="data-table">
              <thead><tr><th>Activo</th><th>Identidad técnica</th>
                <th>Estado</th><th>Candidatos</th><th>Acciones</th></tr></thead>
              <tbody>{currentRows.map(row => <tr key={row.asset_id}>
                <td><strong>{row.asset_name}</strong>
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
                    {STATUS[row.identification_status] || row.identification_status}
                  </span>
                  {row.last_search_at && <div className="cpe-overview-subtitle">
                    {new Date(row.last_search_at).toLocaleString("es-CO")}
                  </div>}
                </td>
                <td>{row.asset_type === "HARDWARE" && row.run_id
                  ? row.candidate_count : "—"}
                  {row.confirmed_count > 0 && <div className="cpe-overview-subtitle">
                    {row.confirmed_count} confirmado(s)</div>}
                  {row.pending_validation_count > 0 && <div className="cpe-overview-subtitle">
                    {row.pending_validation_count} validación(es) pendiente(s)</div>}
                  {row.reopened_count > 0 && <div className="cpe-overview-subtitle">
                    {row.reopened_count} revisión(es) reabierta(s)</div>}
                </td>
                <td>{row.asset_type === "HARDWARE"
                  ? <Link className="button-secondary"
                      to={"/assets/" + row.asset_id + "/cpe"}
                      state={{ fromCpeOverview: true, cpeOverviewSearch: "?" + searchParams.toString() }}>
                        Revisar</Link>
                  : <Link className="button-secondary"
                      to={"/assets/" + row.asset_id}>Ver activo</Link>}</td>
              </tr>)}</tbody>
            </table>
          </div>}
      {!loading && !error && visible.length > 0 && totalPages > 1 && (
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
        Actualmente solo se buscan CPE de hardware. Los activos de software se
        muestran para dar visibilidad al inventario, pero su búsqueda llegará en la fase 4.
        La confirmación o el rechazo de candidatos se realiza expresamente
        desde la revisión de cada hardware y queda registrada con su historial.
      </p>
    </section>
  </section>;
}
