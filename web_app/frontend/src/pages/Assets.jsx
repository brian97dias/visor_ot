import { useEffect, useMemo, useState } from "react";
import { Link, useOutletContext } from "react-router-dom";

import { getAssets } from "../api/assets";
import {
  canCreateAssets,
  CRITICALITY_LABELS,
  displayCost,
  ROLE_LABELS,
} from "../utils/assetPermissions";

const PAGE_SIZE = 15;

function Assets({ hardwareOnly = false }) {
  const { user } = useOutletContext();
  const [assets, setAssets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [criticality, setCriticality] = useState("ALL");
  const [currentPage, setCurrentPage] = useState(1);

  useEffect(() => {
    let active = true;
    getAssets()
      .then((data) => { if (active) setAssets(data); })
      .catch((err) => { if (active) setError(err.message); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, []);

  useEffect(() => {
    setCurrentPage(1);
  }, [search, criticality, hardwareOnly]);

  const filtered = useMemo(() => {
    const query = search.trim().toLowerCase();
    return assets.filter((asset) => {
      if (hardwareOnly && asset.asset_type !== "HARDWARE") return false;
      if (criticality !== "ALL" && asset.criticality !== criticality) return false;
      const searchable = [
        asset.id, asset.name, asset.description,
        asset.hardware?.manufacturer, asset.hardware?.model,
        asset.hardware?.role, asset.asset_type,
      ].filter((value) => value !== null && value !== undefined)
        .join(" ").toLowerCase();
      return !query || searchable.includes(query);
    });
  }, [assets, search, criticality, hardwareOnly]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const visible = filtered.slice(
    (currentPage - 1) * PAGE_SIZE,
    currentPage * PAGE_SIZE
  );

  return (
    <section className="page">
      <header className="page-header assets-page-heading">
        <div>
          <span className="page-eyebrow">ACTIVOS</span>
          <h1>{hardwareOnly ? "Hardware" : "Inventario"}</h1>
          <p>Registro de activos OT y su información técnica y operacional.</p>
        </div>
        {canCreateAssets(user) && (
          <Link className="button-primary assets-primary-link" to="/assets/new">
            Registrar activo
          </Link>
        )}
      </header>

      {error && <div className="error-message">{error}</div>}

      <div className="panel">
        <div className="panel-header">
          <div>
            <h2>{hardwareOnly ? "Dispositivos físicos" : "Activos registrados"}</h2>
            <p>Consulta los activos inventariados y sus datos disponibles.</p>
          </div>
          <span className="record-count">{assets.length} activos en total</span>
        </div>

        <div className="table-toolbar assets-toolbar">
          <div className="search-box">
            <input
              type="search"
              aria-label="Buscar activos"
              placeholder="Buscar por nombre, fabricante, modelo o rol..."
              value={search}
              onChange={(event) => setSearch(event.target.value)}
            />
          </div>
          <select
            className="table-filter-select"
            aria-label="Filtrar por criticidad"
            value={criticality}
            onChange={(event) => setCriticality(event.target.value)}
          >
            <option value="ALL">Todas las criticidades</option>
            {Object.entries(CRITICALITY_LABELS).map(([value, label]) => (
              <option key={value} value={value}>{label}</option>
            ))}
          </select>
          <span className="filtered-count">{filtered.length} resultados</span>
        </div>

        {loading ? (
          <div className="empty-state">Cargando activos...</div>
        ) : !error && filtered.length === 0 ? (
          <div className="empty-state observations-empty">
            <strong>No se encontraron activos.</strong>
            <p>
              {assets.length === 0
                ? "El inventario aparecerá cuando se registre el primer activo."
                : "Prueba con otros términos de búsqueda o filtros."}
            </p>
          </div>
        ) : !error && (
          <>
            <div className="table-container">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Activo</th>
                    <th>Tipo / Rol</th>
                    <th>Fabricante / Modelo</th>
                    <th>Criticidad</th>
                    <th>Costo de reposición</th>
                    <th>Acciones</th>
                  </tr>
                </thead>
                <tbody>
                  {visible.map((asset) => (
                    <tr key={asset.id}>
                      <td>
                        <strong className="pcap-name">{asset.name}</strong>
                        <div className="pcap-path">ID #{asset.id}</div>
                      </td>
                      <td>
                        <span>Hardware</span>
                        <div className="pcap-path">
                          {ROLE_LABELS[asset.hardware?.role] || "Sin clasificar"}
                        </div>
                      </td>
                      <td>
                        {asset.hardware?.manufacturer || "Sin registrar"}
                        <div className="pcap-path">
                          {asset.hardware?.model || "Modelo sin registrar"}
                        </div>
                      </td>
                      <td>
                        {CRITICALITY_LABELS[asset.criticality] || asset.criticality}
                      </td>
                      <td>{displayCost(asset)}</td>
                      <td>
                        <Link className="button-link" to={"/assets/" + asset.id}>
                          Ver detalle
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {totalPages > 1 && (
              <div className="pagination">
                <span>Página {currentPage} de {totalPages}</span>
                <div className="pagination-actions">
                  <button disabled={currentPage === 1}
                    onClick={() => setCurrentPage((page) => page - 1)}>Anterior</button>
                  <button disabled={currentPage === totalPages}
                    onClick={() => setCurrentPage((page) => page + 1)}>Siguiente</button>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </section>
  );
}

export default Assets;
