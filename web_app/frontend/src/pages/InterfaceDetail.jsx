import { useEffect, useState } from "react";
import { Link, useLocation, useOutletContext, useParams } from "react-router-dom";

import { getAssets } from "../api/assets";
import { getInterface, identifyInterface, unlinkInterface } from "../api/interfaces";
import { canCreateAssets } from "../utils/assetPermissions";
import SuccessNotice from "../components/SuccessNotice";
import { getBackNavigation, navigationFromLocation } from "../utils/returnNavigation";

export default function InterfaceDetail() {
  const { interfaceId } = useParams();
  const { user } = useOutletContext();
  const location = useLocation();
  const back = getBackNavigation(location, "/assets/interfaces");
  const canManage = canCreateAssets(user);
  const [entry, setEntry] = useState(null);
  const [assets, setAssets] = useState([]);
  const [assetId, setAssetId] = useState("");
  const [page, setPage] = useState(1);
  const [revision, setRevision] = useState(0);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [confirmUnlink, setConfirmUnlink] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError("");
    getInterface(interfaceId, page)
      .then((data) => { if (active) setEntry(data); })
      .catch((err) => { if (active) setError(err.message); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [interfaceId, page, revision]);

  useEffect(() => {
    if (!canManage) return;
    getAssets("ACTIVE")
      .then((items) => setAssets(items.filter((item) => item.asset_type === "HARDWARE")))
      .catch((err) => setError(err.message));
  }, [canManage]);

  async function act(operation) {
    setSaving(true);
    setError("");
    setNotice("");
    try {
      if (operation === "identify") {
        if (!assetId) throw new Error("Selecciona un hardware.");
        await identifyInterface(interfaceId, Number(assetId));
        setNotice("Interfaz asociada al hardware seleccionado.");
      } else {
        await unlinkInterface(interfaceId);
        setNotice("Interfaz desvinculada. Sus observaciones se conservan.");
      }
      setConfirmUnlink(false);
      setRevision((current) => current + 1);
    } catch (err) { setError(err.message); }
    finally { setSaving(false); }
  }

  if (!entry && loading) return <section className="page">Cargando interfaz...</section>;
  if (!entry) return <section className="page"><div className="error-message">{error || "Interfaz no encontrada."}</div>
    <Link to={back.to} state={back.state}>Volver</Link></section>;

  const observations = entry.observations || { count: 0, page: 1, page_size: 25, results: [] };
  const pages = Math.max(1, Math.ceil(observations.count / observations.page_size));

  return (
    <section className="page">
      <div className="breadcrumbs">
        <Link to="/assets/interfaces">Interfaces</Link><span>/</span><span>#{entry.id}</span>
      </div>
      <Link className="button-secondary assets-back-link" to={back.to} state={back.state}>← Volver</Link>
      <header className="page-header">
        <span className="page-eyebrow">INTERFAZ #{entry.id}</span>
        <h1>{entry.mac || "Sin MAC"}</h1>
        <p>Información consolidada y procedencia de las observaciones.</p>
      </header>
      <SuccessNotice message={notice} onClose={() => setNotice("")} />
      {error && <div className="error-message">{error}</div>}

      <section className="panel assets-detail-section">
        <div className="panel-header"><h2>Identificación de la interfaz</h2></div>
        <div className="assets-detail-grid">
          <div><span>MAC</span><strong>{entry.mac || "No disponible"}</strong></div>
          <div><span>IP declarada</span><strong>{entry.declared_ip || "No declarada"}</strong></div>
          <div><span>IP observadas</span><strong>{entry.observed_ips?.join(", ") || "No observadas"}</strong></div>
          <div><span>Activo relacionado</span>
            <strong>{entry.hardware
              ? <Link className="entity-link" to={"/assets/" + entry.hardware.asset} state={navigationFromLocation(location)}>{entry.hardware.asset_name}</Link>
              : "Sin asociar"}</strong>
          </div>
          <div><span>Rol</span><strong>{entry.hardware?.role || "Sin identificar"}</strong></div>
          <div><span>Evidencias activas</span><strong>{entry.active_observation_count}</strong></div>
          <div><span>Identificada por</span><strong>{entry.identified_by || "No identificada"}</strong></div>
          <div><span>Fecha de asociación</span><strong>{entry.identified_at
            ? new Date(entry.identified_at).toLocaleString("es-CO") : "Sin asociación"}</strong></div>
        </div>
      </section>

      {canManage && (
        <section className="panel interface-management">
          <h2>Gestión de hardware</h2>
          {entry.hardware ? (
            <div>
              <p>Actualmente asociada a {entry.hardware.asset_name}.</p>
              {confirmUnlink ? (
                <div className="table-actions">
                  <span>¿Desvincular y conservar sus evidencias?</span>
                  <button className="button-secondary" type="button"
                    disabled={saving} onClick={() => setConfirmUnlink(false)}>Cancelar</button>
                  <button className="button-primary" type="button"
                    disabled={saving} onClick={() => act("unlink")}>
                    {saving ? "Procesando..." : "Confirmar"}
                  </button>
                </div>
              ) : (
                <button className="button-secondary" type="button"
                  onClick={() => setConfirmUnlink(true)}>Desvincular hardware</button>
              )}
            </div>
          ) : (
            <div className="interface-form-fields">
              <label>Hardware existente
                <select value={assetId} disabled={saving}
                  onChange={(event) => setAssetId(event.target.value)}>
                  <option value="">Selecciona un activo de hardware</option>
                  {assets.map((asset) => <option key={asset.id} value={asset.id}>
                    {asset.name} · {asset.hardware?.role || "Hardware"}
                  </option>)}
                </select>
              </label>
              <button className="button-primary" type="button"
                disabled={!assetId || saving} onClick={() => act("identify")}>
                {saving ? "Asociando..." : "Asociar al hardware"}
              </button>
            </div>
          )}
        </section>
      )}

      <section className="panel">
        <div className="panel-header">
          <div><h2>Evidencia de las ingestas</h2>
            <p>Las observaciones originales se conservan, incluso si se excluye una ingesta.</p></div>
          <span className="record-count">{observations.count} registros</span>
        </div>
        {loading ? <div className="empty-state">Cargando observaciones...</div> :
          observations.results.length === 0 ? <div className="empty-state">Sin observaciones PCAP.</div> :
          <div className="table-container">
            <table className="data-table">
              <thead><tr><th>Ingesta</th><th>IP observadas</th><th>Primera vez</th><th>Última vez</th><th>Estado</th></tr></thead>
              <tbody>{observations.results.map((item) => <tr key={item.id}>
                <td>#{item.ingestion_id} · {item.ingestion_filename}</td>
                <td>{item.ips.join(", ") || "No observada"}</td>
                <td>{item.first_seen}</td>
                <td>{item.last_seen}</td>
                <td>{item.ingestion_status === "ACTIVE" ? "Activa" : "Excluida"}</td>
              </tr>)}</tbody>
            </table>
          </div>}
        <div className="pagination">
          <span>Página {observations.page} de {pages}</span>
          <div className="pagination-actions">
            <button type="button" disabled={loading || observations.page <= 1}
              onClick={() => setPage(observations.page - 1)}>Anterior</button>
            <button type="button" disabled={loading || observations.page >= pages}
              onClick={() => setPage(observations.page + 1)}>Siguiente</button>
          </div>
        </div>
      </section>
    </section>
  );
}
