import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { getSoftwareHistory } from "../api/assets";

const identityText = (data) => {
  if (!data) return "Sin información técnica";
  return [
    data.manufacturer || "Fabricante desconocido",
    data.product || "Producto desconocido",
    data.version || "Versión desconocida",
  ].join(" · ");
};

/** Read-only provenance including snapshots captured when software was linked. */
export default function SoftwareHistorySection({ asset }) {
  const [history, setHistory] = useState(null);
  const [error, setError] = useState("");
  useEffect(() => {
    let active = true;
    getSoftwareHistory(asset.id)
      .then((data) => { if (active) setHistory(data); })
      .catch((err) => { if (active) setError(err.message); });
    return () => { active = false; };
  }, [asset.id]);

  return (
    <section className="panel assets-detail-section">
      <div className="panel-header"><h2>Instalaciones de software</h2></div>
      {error && <p role="alert" className="error-message">{error}</p>}
      {!error && !history && <p className="interface-panel-padding">Cargando historial...</p>}
      {history && (
        <>
          <p className="interface-panel-padding interface-hint">
            {history.active_installation_count} instalaciones vigentes ·{" "}
            {history.installation_history_count} registros históricos.
            Las identidades guardadas son evidencia de lo registrado en cada momento,
            no una confirmación de la versión real del dispositivo.
          </p>
          {history.installations.length ? (
            <div className="table-container">
              <table className="data-table">
                <thead><tr>
                  <th>Hardware</th><th>Identidad registrada</th><th>Fecha de asociación</th><th>Estado</th>
                </tr></thead>
                <tbody>
                  {history.installations.map((row) => (
                    <tr key={row.id}>
                      <td><Link className="entity-link" to={"/assets/" + row.hardware_asset_id}>{row.hardware_name}</Link></td>
                      <td>
                        {identityText(row.identity_snapshot)}
                        {row.identity_snapshot?._source === "migration_current_value_not_verified" && (
                          <div className="interface-hint">
                            Reconstruida al migrar; identidad original no verificada.
                          </div>
                        )}
                      </td>
                      <td>{new Date(row.registered_at).toLocaleString("es-CO")}</td>
                      <td>{row.unlinked_at
                        ? "Desvinculada " + new Date(row.unlinked_at).toLocaleString("es-CO")
                        : "Vigente"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : <p className="interface-panel-padding interface-hint">
            Software sin instalaciones registradas. Puede vincularse desde un hardware.
          </p>}
        </>
      )}
      {history && (
        <>
          <div className="panel-header"><h2>Auditoría de correcciones técnicas</h2></div>
          {history.corrections.length ? (
            <div className="table-container">
              <table className="data-table">
                <thead><tr><th>Fecha y usuario</th><th>Valor anterior</th><th>Valor corregido</th><th>Motivo</th></tr></thead>
                <tbody>
                  {history.corrections.map((row) => (
                    <tr key={row.id}>
                      <td>{new Date(row.changed_at).toLocaleString("es-CO")}<div className="interface-hint">{row.changed_by}</div></td>
                      <td>{identityText(row.identity_before)}</td>
                      <td>{identityText(row.identity_after)}</td>
                      <td>{row.reason}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : <p className="interface-panel-padding interface-hint">
            No se han registrado correcciones técnicas.
          </p>}
        </>
      )}
    </section>
  );
}
