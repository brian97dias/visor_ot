import { useEffect, useState } from "react";
import { Link } from "react-router-dom";

import {
  associateHardwareToSoftware, getAssets,
  getHardwareForSoftware, unlinkHardwareFromSoftware,
} from "../api/assets";
import { canCreateAssets, ROLE_LABELS } from "../utils/assetPermissions";
import SuccessNotice from "./SuccessNotice";
import SearchableHardwareSelect from "./SearchableHardwareSelect";

/** Reciprocal view of SoftwareInstallation from Edit Software.
 * This component sits inside the AssetForm HTML form. All mutation controls
 * are type=button and persist independently of Guardar cambios.
 */
export default function SoftwareHardwareSection({ asset, user, onInstallationsChange }) {
  const canManage = canCreateAssets(user) && asset.inventory_status === "ACTIVE";
  const [installed, setInstalled] = useState([]);
  const [candidates, setCandidates] = useState([]);
  const [loading, setLoading] = useState(true);
  const [loadingChoices, setLoadingChoices] = useState(false);
  const [revision, setRevision] = useState(0);
  const [showChooser, setShowChooser] = useState(false);
  const [selectedId, setSelectedId] = useState(null);
  const [pendingUnlink, setPendingUnlink] = useState(null);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    setLoading(true);
    getHardwareForSoftware(asset.id)
      .then((data) => { if (active) setInstalled(data.results || []); })
      .catch((err) => { if (active) setError(err.message); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [asset.id, revision]);

  useEffect(() => {
    if (!showChooser || !canManage) return;
    let active = true;
    setLoadingChoices(true);
    getAssets("ACTIVE")
      .then((assets) => {
        if (active) {
          setCandidates(assets.filter((item) => item.asset_type === "HARDWARE"));
        }
      })
      .catch((err) => { if (active) setError(err.message); })
      .finally(() => { if (active) setLoadingChoices(false); });
    return () => { active = false; };
  }, [showChooser, canManage, revision]);

  const installedIds = new Set(installed.map((row) => row.hardware_asset_id));
  const available = candidates.filter((item) => !installedIds.has(item.id));

  function closeSelector() {
    setShowChooser(false);
    setSelectedId(null);
    setError("");
  }

  async function associate() {
    if (!canManage || busy || selectedId == null) return;
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await associateHardwareToSoftware(asset.id, selectedId);
      closeSelector();
      setRevision((value) => value + 1);
      onInstallationsChange?.();
      setNotice("Hardware asociado. La instalación se guardó inmediatamente.");
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function unlink() {
    if (!canManage || busy || !pendingUnlink) return;
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await unlinkHardwareFromSoftware(asset.id, pendingUnlink.id);
      setPendingUnlink(null);
      setRevision((value) => value + 1);
      onInstallationsChange?.();
      setNotice("Hardware desvinculado. Su instalación histórica se conserva.");
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="assets-form-section">
      <div className="interface-section-header">
        <div>
          <h2>Hardware donde está instalado</h2>
          <p className="interface-hint">
            Dispositivos que alojan esta variante de Software.
          </p>
        </div>
        {canManage && (
          <button type="button" className="button-secondary" disabled={busy}
            onClick={() => {
              if (showChooser) closeSelector();
              else { setError(""); setShowChooser(true); }
            }}>
            {showChooser ? "Cerrar selector" : "Asociar hardware"}
          </button>
        )}
      </div>
      <p className="interface-hint">
        Las asociaciones se guardan inmediatamente, por separado de «Guardar cambios».
      </p>
      <SuccessNotice message={notice} onClose={() => setNotice("")} />
      {error && <div className="error-message" role="alert">{error}</div>}

      {loading ? (
        <p className="interface-hint">Cargando hardware vinculado...</p>
      ) : installed.length ? (
        <div className="table-container">
          <table className="data-table">
            <thead>
              <tr><th>Hardware</th><th>Modelo / fabricante</th><th>Rol</th><th>Acciones</th></tr>
            </thead>
            <tbody>
              {installed.map((row) => (
                <tr key={row.id}>
                  <td><Link to={"/assets/" + row.hardware_asset_id}>{row.hardware_name}</Link></td>
                  <td>{[row.manufacturer, row.model].filter(Boolean).join(" · ") || "Sin registrar"}</td>
                  <td>{ROLE_LABELS[row.hardware_role] || row.hardware_role}</td>
                  <td>
                    {canManage && (
                      <button type="button" className="button-secondary" disabled={busy}
                        onClick={() => setPendingUnlink(row)}>
                        Desvincular
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="interface-hint">
          Este software no tiene hardware asociado actualmente.
        </p>
      )}

      {showChooser && canManage && (
        <div className="software-install-editor">
          <SearchableHardwareSelect
            options={available} selectedId={selectedId}
            onChange={setSelectedId} disabled={busy || loadingChoices}
          />
          {loadingChoices && <p className="interface-hint">Buscando hardware disponible...</p>}
          {!loadingChoices && available.length === 0 && (
            <p className="interface-hint">
              No hay otros hardware activos disponibles para asociar.
            </p>
          )}
          <div className="table-actions interface-panel-actions">
            <button type="button" className="button-secondary" disabled={busy}
              onClick={closeSelector}>Cancelar</button>
            <button type="button" className="button-primary"
              disabled={busy || selectedId == null} onClick={associate}>
              {busy ? "Asociando..." : "Confirmar asociación"}
            </button>
          </div>
        </div>
      )}

      {pendingUnlink && canManage && (
        <div className="software-install-editor">
          <p>¿Desvincular «{pendingUnlink.hardware_name}» de este software?
            Se conservará el historial de instalación.</p>
          <div className="table-actions interface-panel-actions">
            <button type="button" className="button-secondary" disabled={busy}
              onClick={() => setPendingUnlink(null)}>Cancelar</button>
            <button type="button" className="button-primary" disabled={busy}
              onClick={unlink}>Confirmar desvinculación</button>
          </div>
        </div>
      )}
    </div>
  );
}
