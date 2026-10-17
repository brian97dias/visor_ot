import { useEffect, useState } from "react";
import { Link, useLocation } from "react-router-dom";

import { getSystemSoftware } from "../api/systems";
import { navigationFromLocation } from "../utils/returnNavigation";
import { SOFTWARE_TYPE_LABELS } from "../utils/assetPermissions";

function AssetLink({ assetId, name, navigationState }) {
  return <Link className="entity-link" to={"/assets/" + assetId}
    state={navigationState}>{name}</Link>;
}

/** Read-only derived system software. No OTSystem<->Software assignment exists. */
export default function SystemSoftwareSection({ systemId, revision = 0 }) {
  const location = useLocation();
  const navigationState = navigationFromLocation(location);
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [refresh, setRefresh] = useState(0);

  useEffect(() => {
    let current = true;
    setLoading(true);
    setError("");
    setData(null);
    getSystemSoftware(systemId)
      .then(result => { if (current) setData(result); })
      .catch(err => { if (current) setError(err.message); })
      .finally(() => { if (current) setLoading(false); });
    return () => { current = false; };
  }, [systemId, revision, refresh]);

  return <section className="panel assets-detail-section">
    <div className="panel-header">
      <div>
        <h2>Software relacionado</h2>
        <p className="interface-hint">
          Firmware, sistemas operativos y aplicaciones instalados actualmente
          en los Hardware participantes.
        </p>
      </div>
      <button type="button" className="button-secondary"
        disabled={loading} onClick={() => setRefresh(value => value + 1)}>
        Recargar software
      </button>
    </div>
    <div className="interface-panel-padding">
      <p className="interface-hint">
        Vista derivada de las pertenencias e instalaciones vigentes. No registra
        asociaciones directas entre un Software y este Sistema OT.
      </p>
      {data && <p className="interface-hint">
        {data.participant_hardware_count} Hardware participantes ·{" "}
        {data.software_count} variantes de Software ·{" "}
        {data.installation_count} instalaciones vigentes
      </p>}
    </div>
    {loading ? <p className="interface-panel-padding interface-hint">
      Consultando software relacionado...
    </p> : error ? <div className="interface-panel-padding">
      <p className="error-message" role="alert">{error}</p>
      <button type="button" className="button-secondary"
        onClick={() => setRefresh(value => value + 1)}>Reintentar</button>
    </div> : !data?.results?.length ? <p className="interface-panel-padding interface-hint">
      {data?.participant_hardware_count === 0 ?
        "Este sistema todavía no tiene Hardware participante." :
        "Los Hardware participantes no tienen instalaciones de Software vigentes."}
    </p> : <div className="table-container">
      <table className="data-table">
        <thead><tr>
          <th>Software</th><th>Tipo</th><th>Versión</th>
          <th>Hardware donde está instalado</th><th>Estado</th>
        </tr></thead>
        <tbody>{data.results.map(row => <tr key={row.software_asset_id}>
          <td>
            <AssetLink assetId={row.software_asset_id} name={row.name}
              navigationState={navigationState}/>
            <div className="pcap-path">
              {[row.manufacturer, row.product].filter(Boolean).join(" · ") || "Producto desconocido"}
            </div>
          </td>
          <td>{SOFTWARE_TYPE_LABELS[row.software_type] || row.software_type}</td>
          <td>{row.version || "Desconocida"}</td>
          <td>
            <div className="system-software-hosts">
              {row.hardware.map(host =>
                <div key={host.hardware_asset_id} className="system-software-host">
                  <AssetLink assetId={host.hardware_asset_id} name={host.name}
                    navigationState={navigationState}/>
                  {host.inventory_status === "ARCHIVED" &&
                    <span className="interface-hint"> (Hardware archivado)</span>}
                </div>)}
            </div>
            <small className="interface-hint">
              {row.hardware_count} {row.hardware_count === 1 ? "dispositivo" : "dispositivos"}
            </small>
          </td>
          <td>{row.inventory_status === "ARCHIVED" ?
            "Archivado (instalación vigente)" : "En inventario"}</td>
        </tr>)}</tbody>
      </table>
    </div>}
  </section>;
}
