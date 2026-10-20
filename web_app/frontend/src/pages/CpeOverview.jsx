import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
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
};

export default function CpeOverview() {
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [filter, setFilter] = useState("ALL");
  const [assetType, setAssetType] = useState("ALL");
  const [search, setSearch] = useState("");
  const [revision, setRevision] = useState(0);

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError("");
    getCpeOverview()
      .then(items => { if (active) setRows(items); })
      .catch(err => { if (active) setError(err.message); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [revision]);

  const visible = useMemo(() => rows.filter(row => {
    if (assetType !== "ALL" && row.asset_type !== assetType) return false;
    if (filter !== "ALL" && filter !== row.identification_status) return false;
    const query = search.trim().toLowerCase();
    return !query || [
      row.asset_name, row.manufacturer, row.product, row.cpu_model, row.role,
    ].some(value => String(value || "").toLowerCase().includes(query));
  }), [rows, filter, assetType, search]);

  const count = state => rows.filter(row => row.identification_status === state).length;
  const hardwareCount = rows.filter(row => row.asset_type === "HARDWARE").length;
  const softwareCount = rows.filter(row => row.asset_type === "SOFTWARE").length;
  const processing = count("QUEUED") + count("RUNNING");

  return <section className="page">
    <header className="page-header">
      <div>
        <span className="page-eyebrow">VULNERABILIDADES</span>
        <h1>Identificación CPE</h1>
        <p>Supervisión de búsquedas y candidatos de los activos inventariados.</p>
      </div>
    </header>
    <div className="cpe-overview-stats" aria-label="Resumen de búsquedas CPE">
      <div className="cpe-overview-stat"><strong>{rows.length}</strong><span>Activos vigentes</span></div>
      <div className="cpe-overview-stat"><strong>{hardwareCount}</strong><span>Hardware</span></div>
      <div className="cpe-overview-stat"><strong>{softwareCount}</strong><span>Software (fase 4)</span></div>
      <div className="cpe-overview-stat"><strong>{count("CANDIDATES")}</strong><span>Con candidatos para revisar</span></div>
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
          value={search} onChange={event => setSearch(event.target.value)}/>
        <select aria-label="Filtrar tipo de activo CPE"
          value={assetType} onChange={event => setAssetType(event.target.value)}>
          <option value="ALL">Hardware y Software</option>
          <option value="HARDWARE">Solo Hardware</option>
          <option value="SOFTWARE">Solo Software</option>
        </select>
        <select aria-label="Filtrar estado de identificación CPE"
          value={filter} onChange={event => setFilter(event.target.value)}>
          <option value="ALL">Todos los estados</option>
          {Object.entries(STATUS).map(([value, label]) =>
            <option value={value} key={value}>{label}</option>)}
        </select>
        <button className="button-secondary" type="button" disabled={loading}
          onClick={() => setRevision(current => current + 1)}>
          {loading ? "Actualizando..." : "Actualizar estados"}
        </button>
      </div>
      {error && <div className="error-message" role="alert">{error}</div>}
      {loading ? <div className="empty-state">Cargando estados CPE...</div>
        : !error && visible.length === 0
          ? <div className="empty-state">No hay activos que coincidan con estos filtros.</div>
          : !error && <div className="table-container">
            <table className="data-table">
              <thead><tr><th>Activo</th><th>Identidad técnica</th>
                <th>Estado</th><th>Candidatos</th><th>Acciones</th></tr></thead>
              <tbody>{visible.map(row => <tr key={row.asset_id}>
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
                  ? row.candidate_count : "—"}</td>
                <td>{row.asset_type === "HARDWARE"
                  ? <Link className="button-secondary"
                      to={"/assets/" + row.asset_id + "/cpe"}
                      state={{ fromCpeOverview: true }}>Revisar</Link>
                  : <Link className="button-secondary"
                      to={"/assets/" + row.asset_id}>Ver activo</Link>}</td>
              </tr>)}</tbody>
            </table>
          </div>}
      <p className="cpe-overview-note">
        Actualmente solo se buscan CPE de hardware. Los activos de software se
        muestran para dar visibilidad al inventario, pero su búsqueda llegará en la fase 4.
        La validación y confirmación de CPE llegará en la fase 2.
        La ficha de cada hardware mantiene su acceso directo al descubrimiento.
      </p>
    </section>
  </section>;
}
