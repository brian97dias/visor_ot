import { useEffect, useState } from "react";
import { Link } from "react-router-dom";

import { getHardwareForSoftware, getInstalledSoftware } from "../api/assets";
import { getInterfaces } from "../api/interfaces";
import { ROLE_LABELS, SOFTWARE_TYPE_LABELS } from "../utils/assetPermissions";

function InventoryState({ value }) {
  return value === "ARCHIVED" ? (
    <span className="asset-relation-archived">Archivado</span>
  ) : null;
}

function SoftwareLinks({ results }) {
  return (
    <section className="asset-relation-section">
      <h4>Software instalado <span>({results.length})</span></h4>
      {results.length === 0 ? (
        <p className="interface-hint">No hay software asociado en Visor OT.</p>
      ) : (
        <ul className="asset-relation-list">
          {results.map((row) => (
            <li key={row.id}>
              <div>
                <Link to={"/assets/" + row.software_asset_id}>{row.name}</Link>
                <div className="interface-hint">
                  {SOFTWARE_TYPE_LABELS[row.software?.software_type] || "Software"}
                  {" · "}{row.software?.product || "Producto no registrado"}
                  {" · "}{row.software?.version || "Versión desconocida"}
                  <InventoryState value={row.inventory_status} />
                </div>
              </div>
              <Link className="button-link" to={"/assets/" + row.software_asset_id}>Ver activo</Link>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function HardwareLinks({ results }) {
  return (
    <section className="asset-relation-section">
      <h4>Hardware donde está instalado <span>({results.length})</span></h4>
      {results.length === 0 ? (
        <p className="interface-hint">Este software no tiene hardware asociado en Visor OT.</p>
      ) : (
        <ul className="asset-relation-list">
          {results.map((row) => (
            <li key={row.id}>
              <div>
                <Link to={"/assets/" + row.hardware_asset_id}>{row.hardware_name}</Link>
                <div className="interface-hint">
                  {ROLE_LABELS[row.hardware_role] || row.hardware_role || "Sin clasificar"}
                  {" · "}
                  {[row.manufacturer, row.model].filter(Boolean).join(" · ") || "Modelo no registrado"}
                  <InventoryState value={row.inventory_status} />
                </div>
              </div>
              <Link className="button-link" to={"/assets/" + row.hardware_asset_id}>Ver activo</Link>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function InterfaceLinks({ value, onPage, loading, error }) {
  const results = value?.results || [];
  const count = value?.count || 0;
  const page = value?.page || 1;
  const pageSize = value?.page_size || 25;
  const totalPages = Math.max(1, Math.ceil(count / pageSize));

  return (
    <section className="asset-relation-section">
      <h4>Interfaces vinculadas <span>({count})</span></h4>
      {count === 0 ? (
        <p className="interface-hint">No hay interfaces asociadas en Visor OT.</p>
      ) : (
        <>
          <ul className="asset-relation-list">
            {results.map((item) => {
              const ips = [...new Set(
                [item.declared_ip, ...(item.observed_ips || [])].filter(Boolean)
              )];
              return (
                <li key={item.id}>
                  <div>
                    <Link to={"/assets/interfaces/" + item.id}>
                      {item.mac || "Interfaz #" + item.id + " sin MAC"}
                    </Link>
                    <div className="interface-hint">
                      {ips.join(", ") || "Sin IP conocida"}
                      {item.has_active_evidence ? " · Evidencia activa" : " · Sin evidencia activa"}
                    </div>
                  </div>
                  <Link className="button-link" to={"/assets/interfaces/" + item.id}>Ver interfaz</Link>
                </li>
              );
            })}
          </ul>
          {loading && <p className="interface-hint" role="status">Cargando página de interfaces...</p>}
          {error && <p className="error-message" role="alert">{error}</p>}
          {totalPages > 1 && (
            <div className="asset-relation-pages">
              <span>Página {page} de {totalPages}</span>
              <div className="table-actions">
                <button type="button" className="button-secondary"
                  disabled={loading || page <= 1}
                  onClick={() => onPage(page - 1)}>Anterior</button>
                <button type="button" className="button-secondary"
                  disabled={loading || page >= totalPages}
                  onClick={() => onPage(page + 1)}>Siguiente</button>
              </div>
            </div>
          )}
        </>
      )}
    </section>
  );
}

/** Read-only expansion: mounted for each visible row so closing/reopening
 * preserves fetched data until the inventory page or filters unmount it.
 * Never writes installations or interface assignments.
 */
export default function AssetRelationsRow({ asset, open, canManage }) {
  const [links, setLinks] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [revision, setRevision] = useState(0);
  const [interfaceLoading, setInterfaceLoading] = useState(false);
  const [interfaceError, setInterfaceError] = useState("");

  useEffect(() => {
    if (!open || links !== null) return;
    let active = true;
    setLoading(true);
    setError("");
    const query = asset.asset_type === "HARDWARE"
      ? Promise.all([
          getInstalledSoftware(asset.id),
          getInterfaces({ hardwareId: asset.id, evidence: "ALL", page: 1 }),
        ]).then(([software, interfaces]) => ({
          software: software.results || [], interfaces,
        }))
      : getHardwareForSoftware(asset.id).then((hardware) => ({
          hardware: hardware.results || [],
        }));

    query.then((data) => {
      if (active) setLinks(data);
    }).catch((err) => {
      if (active) setError(err.message);
    }).finally(() => {
      if (active) setLoading(false);
    });
    return () => { active = false; };
  }, [open, links, asset.asset_type, asset.id, revision]);

  async function changeInterfacePage(page) {
    if (!open || interfaceLoading || !links?.interfaces) return;
    setInterfaceLoading(true);
    setInterfaceError("");
    try {
      const response = await getInterfaces({ hardwareId: asset.id, evidence: "ALL", page });
      setLinks((previous) => previous ? { ...previous, interfaces: response } : previous);
    } catch (err) {
      setInterfaceError(err.message);
    } finally {
      setInterfaceLoading(false);
    }
  }

  if (!open) return null;

  return (
    <tr className="asset-relations-expanded" id={"asset-relations-" + asset.id}>
      <td colSpan={7}>
        <div className="asset-relations-content" aria-live="polite">
          <div className="asset-relations-heading">
            <div>
              <h3>Vinculaciones de {asset.name}</h3>
              <p className="interface-hint">
                Asociaciones registradas en Visor OT. No equivalen a una
                identificación automática del firmware o de las interfaces físicas.
              </p>
            </div>
            <div className="table-actions">
              {canManage && asset.inventory_status === "ACTIVE" && (
                <Link className="button-secondary" to={"/assets/" + asset.id + "/edit"}>
                  Gestionar asociaciones
                </Link>
              )}
              <button type="button" className="button-secondary"
                disabled={loading || interfaceLoading}
                onClick={() => {
                  setLinks(null);
                  setInterfaceError("");
                  setRevision((value) => value + 1);
                }}>
                Recargar vinculaciones
              </button>
            </div>
          </div>

          {loading && <p className="interface-hint">Consultando vinculaciones...</p>}
          {!loading && error && (
            <div className="asset-relation-error">
              <p className="error-message" role="alert">{error}</p>
              <button type="button" className="button-secondary"
                onClick={() => setRevision((value) => value + 1)}>Reintentar</button>
            </div>
          )}
          {!loading && links && (
            <div className={"asset-relations-columns" +
              (asset.asset_type === "SOFTWARE" ? " asset-relations-single" : "")}>
              {asset.asset_type === "HARDWARE" ? (
                <>
                  <SoftwareLinks results={links.software} />
                  <InterfaceLinks value={links.interfaces} onPage={changeInterfacePage}
                    loading={interfaceLoading} error={interfaceError} />
                </>
              ) : <HardwareLinks results={links.hardware} />}
            </div>
          )}
        </div>
      </td>
    </tr>
  );
}
