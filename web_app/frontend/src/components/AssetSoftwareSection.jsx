import { useEffect, useState } from "react";
import { Link } from "react-router-dom";

import {
  associateExistingSoftware, getAssets,
  getInstalledSoftware, unlinkInstalledSoftware,
} from "../api/assets";
import SuccessNotice from "./SuccessNotice";
import { canCreateAssets, SOFTWARE_TYPE_LABELS } from "../utils/assetPermissions";

/** Installation management shared by hardware detail and hardware edit views.
 * Association changes are saved immediately, separately from AssetForm.
 */
export default function AssetSoftwareSection({ asset, user, embedded = false }) {
  const canManage = canCreateAssets(user) && asset.inventory_status === "ACTIVE";
  const [installed, setInstalled] = useState([]);
  const [candidates, setCandidates] = useState([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [revision, setRevision] = useState(0);
  const [showChooser, setShowChooser] = useState(false);
  const [softwareAssetId, setSoftwareAssetId] = useState("");
  const [search, setSearch] = useState("");
  const [pendingUnlink, setPendingUnlink] = useState(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  useEffect(() => {
    let active = true;
    setLoading(true);
    getInstalledSoftware(asset.id)
      .then((data) => { if (active) setInstalled(data.results || []); })
      .catch((err) => { if (active) setError(err.message); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [asset.id, revision]);

  useEffect(() => {
    if (!showChooser || !canManage) return;
    let active = true;
    getAssets("ACTIVE")
      .then((items) => {
        if (active) setCandidates(items.filter((item) => item.asset_type === "SOFTWARE"));
      })
      .catch((err) => { if (active) setError(err.message); });
    return () => { active = false; };
  }, [showChooser, canManage, revision]);

  const installedIds = new Set(installed.map((row) => row.software_asset_id));
  const available = candidates.filter((item) =>
    !installedIds.has(item.id) &&
    [item.name, item.software?.product, item.software?.manufacturer, item.software?.version]
      .join(" ").toLocaleLowerCase("es-CO")
      .includes(search.trim().toLocaleLowerCase("es-CO"))
  );

  async function associate() {
    if (busy || !softwareAssetId) return;
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await associateExistingSoftware(asset.id, Number(softwareAssetId));
      setRevision((current) => current + 1);
      setShowChooser(false);
      setSoftwareAssetId("");
      setSearch("");
      setNotice("Software asociado. El cambio se guardó inmediatamente.");
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function unlink() {
    if (busy || !pendingUnlink) return;
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await unlinkInstalledSoftware(asset.id, pendingUnlink.id);
      setRevision((current) => current + 1);
      setPendingUnlink(null);
      setNotice("Software desvinculado. Se conserva el historial de instalación.");
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  const registerUrl = "/assets/new?type=SOFTWARE&hardware_id=" + asset.id + "&from=hardware";

  return (
    <section className={embedded ? "assets-form-section" : "panel assets-detail-section"}>
      <div className={embedded ? "interface-section-header" : "panel-header"}>
        <div>
          <h2>Software instalado</h2>
          <p className="interface-hint">Firmware, sistemas operativos y aplicaciones asociados a este hardware.</p>
        </div>
        {canManage && (
          <button className="button-secondary" type="button" disabled={busy}
            onClick={() => { setShowChooser((value) => !value); setError(""); }}>
            {showChooser ? "Cerrar selector" : "Añadir software"}
          </button>
        )}
      </div>
      {embedded && canManage && (
        <p className="interface-hint">
          Las instalaciones se guardan inmediatamente, por separado de «Guardar cambios».
        </p>
      )}
      <SuccessNotice message={notice} onClose={() => setNotice("")} />
      {error && <div className="error-message interface-panel-padding" role="alert">{error}</div>}
      {loading ? (
        <div className="interface-panel-padding">Cargando software...</div>
      ) : installed.length > 0 ? (
        <div className="table-container">
          <table className="data-table">
            <thead><tr><th>Software</th><th>Tipo</th><th>Versión</th><th>Acciones</th></tr></thead>
            <tbody>
              {installed.map((row) => (
                <tr key={row.id}>
                  <td>
                    <Link to={"/assets/" + row.software_asset_id}>{row.name}</Link>
                    <div className="pcap-path">
                      {row.software.manufacturer || "Fabricante desconocido"} · {row.software.product}
                    </div>
                  </td>
                  <td>{SOFTWARE_TYPE_LABELS[row.software.software_type] || row.software.software_type}</td>
                  <td>{row.software.version || "Desconocida"}</td>
                  <td>
                    {canManage && (
                      <button type="button" className="button-secondary" disabled={busy}
                        onClick={() => setPendingUnlink(row)}>Desvincular</button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="interface-panel-padding interface-hint">
          Este hardware no tiene software asociado.
        </div>
      )}

      {showChooser && canManage && (
        <div className="interface-panel-padding">
          <div className="assets-field">
            <label htmlFor={"installed-software-search-" + asset.id}>Buscar software existente</label>
            <input id={"installed-software-search-" + asset.id} value={search}
              placeholder="Buscar fabricante, producto o versión..."
              onChange={(event) => setSearch(event.target.value)}/>
          </div>
          <div className="assets-field">
            <label htmlFor={"installed-software-" + asset.id}>Seleccionar software</label>
            <select id={"installed-software-" + asset.id}
              value={softwareAssetId} disabled={busy}
              onChange={(event) => setSoftwareAssetId(event.target.value)}>
              <option value="">Selecciona una variante existente</option>
              {available.map((item) => (
                <option value={item.id} key={item.id}>
                  {item.name} · {item.software?.product} · {item.software?.version || "Versión desconocida"}
                </option>
              ))}
            </select>
          </div>
          <div className="table-actions interface-panel-actions">
            <Link to={registerUrl} className="button-secondary">Registrar software nuevo</Link>
            <button type="button" className="button-secondary"
              onClick={() => { setShowChooser(false); setSoftwareAssetId(""); setSearch(""); }}>
              Cancelar
            </button>
            <button type="button" className="button-primary"
              disabled={busy || !softwareAssetId} onClick={associate}>
              {busy ? "Guardando..." : "Asociar existente"}
            </button>
          </div>
        </div>
      )}
      {pendingUnlink && canManage && (
        <div className="interface-panel-padding">
          <p>¿Desvincular «{pendingUnlink.name}»? Se conservará el historial.</p>
          <div className="table-actions interface-panel-actions">
            <button type="button" className="button-secondary" disabled={busy}
              onClick={() => setPendingUnlink(null)}>Cancelar</button>
            <button type="button" className="button-primary" disabled={busy}
              onClick={unlink}>Confirmar desvinculación</button>
          </div>
        </div>
      )}
    </section>
  );
}
