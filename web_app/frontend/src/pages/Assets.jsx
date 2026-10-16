import { Fragment, useEffect, useMemo, useState } from "react";
import { Link, useLocation, useOutletContext, useSearchParams } from "react-router-dom";

import { archiveAsset, exportAssetsExcel, getAssets, restoreAsset } from "../api/assets";
import SuccessNotice from "../components/SuccessNotice";
import ConfirmAssetStatusModal from "../components/ConfirmAssetStatusModal";
import AssetRelationsRow from "../components/AssetRelationsRow";
import { filterInventoryAssets, RELATIONSHIP_FILTERS } from "../utils/inventoryFilters";
import { readPositiveInt, updateInventoryParams } from "../utils/inventoryUrlState";
import { navigationFromLocation } from "../utils/returnNavigation";
import {
  canArchiveAssets,
  canCreateAssets,
  canEditAssets,
  CRITICALITY_LABELS,
  INVENTORY_STATUS_LABELS,
  ROLE_LABELS,
  SOFTWARE_TYPE_LABELS,
} from "../utils/assetPermissions";

const PAGE_SIZE = 15;

function AssetRelationshipsSummary({ asset }) {
  // These numbers represent relationships recorded in Visor OT, not
  // a claim about which software/devices physically exist in the plant.
  if (asset.asset_type === "HARDWARE") {
    const softwareCount = asset.software_count ?? 0;
    const interfaceCount = asset.interface_count ?? 0;
    return (
      <div className="assets-relation-counts">
        <span>{softwareCount} {softwareCount === 1 ? "software asociado" : "software asociados"}</span>
        <span className="pcap-path">
          {interfaceCount} {interfaceCount === 1 ? "interfaz asociada" : "interfaces asociadas"}
        </span>
      </div>
    );
  }
  const hardwareCount = asset.hardware_count ?? 0;
  return (
    <div className="assets-relation-counts">
      <span>{hardwareCount} {hardwareCount === 1 ? "hardware asociado" : "hardware asociados"}</span>
    </div>
  );
}

function Assets() {
  const { user } = useOutletContext();
  const [searchParams, setSearchParams] = useSearchParams();
  const location = useLocation();
  const navigationState = navigationFromLocation(location);

  const assetType = searchParams.get("type") || "ALL";
  const inventoryStatus = searchParams.get("inventory_status") || "ACTIVE";
  const search = searchParams.get("q") || "";
  const criticality = searchParams.get("criticality") || "ALL";
  const expandedAssetId = readPositiveInt(searchParams.get("expanded"), null);
  const [assets, setAssets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [busyId, setBusyId] = useState(null);
  const [exporting, setExporting] = useState(false);
  const [pendingAsset, setPendingAsset] = useState(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  function changeQueryFilter(name, value) {
    setSearchParams(updateInventoryParams(searchParams, name, value),
      { replace: name === "q" || name === "expanded" });
  }

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError("");
    getAssets(inventoryStatus)
      .then((items) => { if (active) setAssets(items); })
      .catch((err) => { if (active) setError(err.message); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [inventoryStatus]);

  const relationshipOptions = RELATIONSHIP_FILTERS[assetType] ||
    [{ value: "ALL", label: "Selecciona Hardware o Software" }];
  const desiredRelation = searchParams.get("relation") || "ALL";
  const relationshipFilter = relationshipOptions.some((item) => item.value === desiredRelation) ? desiredRelation : "ALL";

  const filtered = useMemo(() => filterInventoryAssets(assets, {
    assetType,
    criticality,
    relationshipFilter,
    search,
  }), [assets, search, criticality, assetType, relationshipFilter]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const currentPage = Math.min(readPositiveInt(searchParams.get("page")), totalPages);
  const visible = filtered.slice((currentPage - 1) * PAGE_SIZE, currentPage * PAGE_SIZE);

  async function downloadInventory() {
    if (exporting) return;
    setError("");
    setExporting(true);
    try {
      await exportAssetsExcel();
    } catch (err) {
      setError(err.message);
    } finally {
      setExporting(false);
    }
  }

  async function confirmInventoryStatusChange() {
    if (!pendingAsset || busyId !== null) return;

    const asset = pendingAsset;
    const archived = asset.inventory_status === "ARCHIVED";

    setError("");
    setNotice("");
    setBusyId(asset.id);

    try {
      const updated = archived
        ? await restoreAsset(asset.id)
        : await archiveAsset(asset.id);
      setAssets((current) => {
        if (inventoryStatus === "ALL") {
          // The mutation response contains asset fields only, so retain the
          // relation counts from the listing. Archiving does not unlink.
          return current.map((item) => item.id === updated.id
            ? { ...item, ...updated } : item);
        }
        return current.filter((item) => item.id !== updated.id);
      });
      setNotice(archived ? "Activo restaurado correctamente." : "Activo archivado correctamente.");
    } catch (err) {
      setError(err.message);
    } finally {
      setBusyId(null);
      setPendingAsset(null);
    }
  }

  return (
    <section className="page">
      <header className="page-header assets-page-heading">
        <div>
          <span className="page-eyebrow">ACTIVOS</span>
          <h1>Inventario</h1>
          <p>Registro de activos OT y su información técnica y operacional.</p>
        </div>
        <div className="table-actions">
          {canCreateAssets(user) && (
            <Link className="button-secondary" to="/assets/import">Importar Excel</Link>
          )}
          <button type="button" className="button-secondary"
            disabled={exporting}
            title="Descarga todos los activos, incluidos los archivados, en dos hojas: Hardware y Software."
            onClick={downloadInventory}>
            {exporting ? "Preparando Excel..." : "Exportar Excel"}
          </button>
          {canCreateAssets(user) && (
            <Link className="button-primary assets-primary-link" to="/assets/new">
              Registrar activo
            </Link>
          )}
        </div>
      </header>

      <SuccessNotice message={notice} onClose={() => setNotice("")} />
      {error && <div className="error-message">{error}</div>}

      <div className="panel">
        <div className="panel-header">
          <div>
            <h2>Activos registrados</h2>
            <p>Consulta los activos inventariados y sus datos disponibles.</p>
          </div>
          <span className="record-count">{assets.length} registros en esta vista</span>
        </div>

        <div className="table-toolbar assets-toolbar">
          <div className="search-box">
            <input type="search" aria-label="Buscar activos"
              placeholder="Buscar nombre, fabricante, modelo, producto, versión o rol..."
              value={search} onChange={(event) => changeQueryFilter("q", event.target.value)} />
          </div>

          <select className="table-filter-select" aria-label="Filtrar tipo de activo"
            value={assetType} onChange={(event) => changeQueryFilter("type", event.target.value)}>
            <option value="ALL">Todos los tipos</option>
            <option value="HARDWARE">Hardware</option>
            <option value="SOFTWARE">Software</option>
          </select>

          <select className="table-filter-select assets-relationship-filter"
            aria-label="Filtrar vinculaciones"
            title={assetType === "ALL"
              ? "Selecciona Hardware o Software para filtrar sus vinculaciones"
              : "Filtra las asociaciones registradas en Visor OT"}
            disabled={assetType === "ALL"}
            value={assetType === "ALL" ? "ALL" : relationshipFilter}
            onChange={(event) => changeQueryFilter("relation", event.target.value)}>
            {relationshipOptions.map(({ value, label }) => (
              <option key={value} value={value}>{label}</option>
            ))}
          </select>

          <select className="table-filter-select" aria-label="Filtrar criticidad"
            value={criticality} onChange={(event) => changeQueryFilter("criticality", event.target.value)}>
            <option value="ALL">Todas las criticidades</option>
            {Object.entries(CRITICALITY_LABELS).map(([value, label]) => (
              <option key={value} value={value}>{label}</option>
            ))}
          </select>

          <select className="table-filter-select" aria-label="Filtrar estado de inventario"
            value={inventoryStatus}
            onChange={(event) => changeQueryFilter("inventory_status", event.target.value)}>
            <option value="ACTIVE">En inventario</option>
            <option value="ARCHIVED">Archivados</option>
            <option value="ALL">Todos los estados</option>
          </select>
          <span className="filtered-count">{filtered.length} resultados</span>
        </div>

        {loading ? (
          <div className="empty-state">Cargando activos...</div>
        ) : !error && filtered.length === 0 ? (
          <div className="empty-state observations-empty">
            <strong>No se encontraron activos.</strong>
            <p>{assets.length === 0
              ? "No hay registros en este estado del inventario."
              : "Prueba con otros términos de búsqueda o filtros."}</p>
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
                    <th>Vinculaciones</th>
                    <th>Estado</th>
                    <th>Acciones</th>
                  </tr>
                </thead>
                <tbody>
                  {visible.map((asset) => (
                    <Fragment key={asset.id}>
                      <tr>
                      <td>
                        <strong className="pcap-name">{asset.name}</strong>
                        <div className="pcap-path">ID #{asset.id}</div>
                      </td>
                      <td>
                        <span>{asset.asset_type === "HARDWARE" ? "Hardware" : "Software"}</span>
                        <div className="pcap-path">
                          {asset.hardware
                            ? ROLE_LABELS[asset.hardware.role] || "Sin clasificar"
                            : asset.software
                              ? SOFTWARE_TYPE_LABELS[asset.software.software_type]
                                || "Software"
                              : "Sin datos técnicos"}
                        </div>
                      </td>
                      <td>
                        {asset.hardware?.manufacturer
                          || asset.software?.manufacturer
                          || "Sin registrar"}
                        <div className="pcap-path">
                          {asset.hardware
                            ? asset.hardware.model || "Modelo sin registrar"
                            : asset.software
                              ? [asset.software.product,
                                asset.software.version || "Versión desconocida"]
                                .filter(Boolean).join(" · ")
                              : "Sin datos técnicos"}
                        </div>
                      </td>
                      <td>{CRITICALITY_LABELS[asset.criticality] || asset.criticality}</td>
                      <td>
                        <AssetRelationshipsSummary asset={asset} />
                        <button type="button" className="asset-relations-toggle"
                          aria-expanded={expandedAssetId === asset.id}
                          aria-controls={expandedAssetId === asset.id
                            ? "asset-relations-" + asset.id : undefined}
                          onClick={() => changeQueryFilter("expanded", expandedAssetId === asset.id ? "" : asset.id)}>
                          {expandedAssetId === asset.id
                            ? "Ocultar vinculaciones" : "Ver vinculaciones"}
                        </button>
                      </td>
                      <td>
                        <span className={asset.inventory_status === "ARCHIVED"
                          ? "status status-archived" : "status status-imported"}>
                          {INVENTORY_STATUS_LABELS[asset.inventory_status] || asset.inventory_status}
                        </span>
                      </td>
                      <td>
                        <div className="table-actions">
                          <Link className="button-link" to={"/assets/" + asset.id} state={navigationState}>Ver</Link>
                          {canEditAssets(user) && (
                            <Link className="button-link" to={"/assets/" + asset.id + "/edit"} state={navigationState}>
                              Editar
                            </Link>
                          )}
                          {canArchiveAssets(user) && (
                            <button type="button" className="button-secondary assets-archive-button"
                              disabled={busyId === asset.id}
                              onClick={() => setPendingAsset(asset)}>
                              {busyId === asset.id
                                ? "Procesando..."
                                : asset.inventory_status === "ARCHIVED" ? "Restaurar" : "Archivar"}
                            </button>
                          )}
                        </div>
                      </td>
                      </tr>
                      <AssetRelationsRow
                        asset={asset} open={expandedAssetId === asset.id}
                        canManage={canEditAssets(user)} navigationState={navigationState} />
                    </Fragment>
                  ))}
                </tbody>
              </table>
            </div>

            {totalPages > 1 && (
              <div className="pagination">
                <span>Página {currentPage} de {totalPages}</span>
                <div className="pagination-actions">
                  <button disabled={currentPage === 1}
                    onClick={() => changeQueryFilter("page", currentPage - 1)}>Anterior</button>
                  <button disabled={currentPage === totalPages}
                    onClick={() => changeQueryFilter("page", currentPage + 1)}>Siguiente</button>
                </div>
              </div>
            )}
          </>
        )}
      </div>

      {pendingAsset && (
        <ConfirmAssetStatusModal
          asset={pendingAsset}
          busy={busyId !== null}
          onCancel={() => setPendingAsset(null)}
          onConfirm={confirmInventoryStatusChange}
        />
      )}
    </section>
  );
}

export default Assets;
