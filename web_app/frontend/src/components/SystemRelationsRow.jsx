import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";

import { getSystemHardware, getSystemSoftware } from "../api/systems";
import { ROLE_LABELS, SOFTWARE_TYPE_LABELS } from "../utils/assetPermissions";
import { groupSoftwareByHardware } from "../utils/systemRelations";

/**
 * Read-only, lazy expansion of System -> Hardware -> installed Software.
 * The backend endpoints exclude unlinked memberships and installations.
 */
export default function SystemRelationsRow({ system, open, navigationState }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [revision, setRevision] = useState(0);

  useEffect(() => {
    if (!open || data !== null) return;
    let current = true;
    setLoading(true);
    setError("");
    Promise.all([getSystemHardware(system.id), getSystemSoftware(system.id)])
      .then(([membership, software]) => {
        if (current) setData({ membership, software });
      })
      .catch(err => { if (current) setError(err.message); })
      .finally(() => { if (current) setLoading(false); });
    return () => { current = false; };
  }, [open, data, revision, system.id]);

  const softwareByHost = useMemo(() => {
    return groupSoftwareByHardware(data?.software?.results || []);
  }, [data]);

  if (!open) return null;
  const hardware = data?.membership?.results || [];
  const count = data?.software?.software_count || 0;

  return <tr className="asset-relations-expanded system-relations-expanded"
    id={"system-relations-" + system.id}>
    <td colSpan={5}>
      <div className="asset-relations-content" aria-live="polite">
        <div className="asset-relations-heading">
          <div>
            <h3>Vinculaciones de {system.name}</h3>
            <p className="interface-hint">
              Hardware participante y Software instalado mediante relaciones vigentes.
              No se crean asociaciones directas entre Sistema OT y Software.
            </p>
          </div>
          <div className="table-actions">
            <button type="button" className="button-secondary" disabled={loading}
              onClick={() => { setData(null); setRevision(value => value + 1); }}>
              Recargar vinculaciones
            </button>
          </div>
        </div>
        {loading && <p className="interface-hint" role="status">Consultando dispositivos y software...</p>}
        {!loading && error && <div className="asset-relation-error">
          <p className="error-message" role="alert">{error}</p>
          <button type="button" className="button-secondary"
            onClick={() => {setData(null); setRevision(value => value + 1);}}>
            Reintentar
          </button>
        </div>}
        {!loading && data && <section className="asset-relation-section">
          <h4>Hardware participante <span>({hardware.length})</span>
            <span className="system-relations-software-count">
              · {count} {count === 1 ? "variante de Software" : "variantes de Software"}
            </span>
          </h4>
          {hardware.length === 0 ? (
            <p className="interface-hint">Este sistema no tiene dispositivos Hardware asociados.</p>
          ) : (
            <ul className="system-hardware-tree">
              {hardware.map(host => {
                const software = softwareByHost.get(host.hardware_asset_id) || [];
                return <li className="system-hardware-tree-item" key={host.id}>
                  <div className="system-hardware-tree-title">
                    <Link className="entity-link" to={"/assets/" + host.hardware_asset_id}
                      state={navigationState}>{host.hardware_name}</Link>
                    <span className="interface-hint">
                      {ROLE_LABELS[host.hardware_role] || host.hardware_role || "Sin rol"}
                      {host.hardware_status === "ARCHIVED" ? " · Hardware archivado" : ""}
                    </span>
                  </div>
                  {software.length === 0 ? <p className="interface-hint system-no-software">
                    Sin Software instalado registrado.
                  </p> : <ul className="system-hardware-software-list">
                    {software.map(item => <li key={item.software_asset_id}>
                      <Link className="entity-link" to={"/assets/" + item.software_asset_id}
                        state={navigationState}>{item.name}</Link>
                      <span className="interface-hint">
                        {SOFTWARE_TYPE_LABELS[item.software_type] || item.software_type || "Software"}
                        {" · "}{item.version || "Versión desconocida"}
                        {item.inventory_status === "ARCHIVED" ? " · Software archivado" : ""}
                      </span>
                    </li>)}
                  </ul>}
                </li>;
              })}
            </ul>
          )}
        </section>}
      </div>
    </td>
  </tr>;
}
