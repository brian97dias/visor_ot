import { useEffect, useState } from "react";
import { Link } from "react-router-dom";

import InterfaceSelector from "./InterfaceSelector";
import SuccessNotice from "./SuccessNotice";
import { assignAssetInterface, getInterfaces, unlinkInterface } from "../api/interfaces";
import { canCreateAssets } from "../utils/assetPermissions";

/**
 * Shared immediate-save interface management for the hardware detail and edit form.
 * These operations do NOT wait for the parent's "Guardar cambios" submission.
 */
export default function AssetInterfacesSection({ asset, user, embedded = false }) {
  const canManage = canCreateAssets(user);
  const [interfaces, setInterfaces] = useState([]);
  const [loading, setLoading] = useState(true);
  const [revision, setRevision] = useState(0);
  const [showSelector, setShowSelector] = useState(false);
  const [selection, setSelection] = useState(null);
  const [busy, setBusy] = useState(false);
  const [pendingUnlink, setPendingUnlink] = useState(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError("");
    getInterfaces({ hardwareId: asset.id, evidence: "ALL" })
      .then((data) => { if (active) setInterfaces(data.results); })
      .catch((err) => { if (active) setError(err.message); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [asset.id, revision]);

  async function assign() {
    if (!selection || busy) return;
    if (selection.mode === "MANUAL" &&
        !selection.mac?.trim() && !selection.declared_ip?.trim()) {
      setError("Indica al menos una MAC o IP.");
      return;
    }
    setBusy(true);
    setNotice("");
    setError("");
    try {
      await assignAssetInterface(asset.id, selection);
      setRevision((value) => value + 1);
      setSelection(null);
      setShowSelector(false);
      setNotice("Interfaz asociada. La modificación se guardó inmediatamente.");
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function unlink() {
    if (!pendingUnlink || busy) return;
    setBusy(true);
    setNotice("");
    setError("");
    try {
      await unlinkInterface(pendingUnlink.id);
      setPendingUnlink(null);
      setRevision((value) => value + 1);
      setNotice("Interfaz desvinculada. Se conservaron sus observaciones.");
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className={embedded ? "assets-form-section" : "panel assets-detail-section"}>
      <div className={embedded ? "interface-section-header" : "panel-header"}>
        <div>
          <h2>Interfaces de red</h2>
          <p className="interface-hint">Interfaces asociadas a este hardware.</p>
        </div>
        {canManage && asset.inventory_status === "ACTIVE" && (
          <button type="button" className="button-secondary" disabled={busy}
            onClick={() => {
              setShowSelector((value) => !value);
              setSelection(null);
              setError("");
            }}>
            {showSelector ? "Cerrar selector" : "Asociar interfaz"}
          </button>
        )}
      </div>

      {embedded && canManage && (
        <p className="interface-hint">
          Los cambios de interfaces se guardan inmediatamente, por separado de
          «Guardar cambios» del activo.
        </p>
      )}

      <SuccessNotice message={notice} onClose={() => setNotice("")} />
      {error && <div className="error-message interface-panel-padding" role="alert">{error}</div>}

      {loading ? (
        <div className="interface-panel-padding">Cargando interfaces...</div>
      ) : interfaces.length ? (
        <div className="table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>MAC</th><th>IP conocidas</th><th>Evidencia</th><th>Acciones</th>
              </tr>
            </thead>
            <tbody>
              {interfaces.map((item) => (
                <tr key={item.id}>
                  <td>{item.mac || "Sin MAC"}</td>
                  <td>{[...new Set([...(item.observed_ips || []), item.declared_ip].filter(Boolean))].join(", ") || "Sin IP"}</td>
                  <td>{item.has_active_evidence ? "Activa" : "Solo histórica / ninguna"}</td>
                  <td>
                    <div className="table-actions">
                      <Link className="button-secondary" to={"/assets/interfaces/" + item.id}>Ver interfaz</Link>
                      {canManage && (
                        <button type="button" className="button-secondary" disabled={busy}
                          onClick={() => { setPendingUnlink(item); setError(""); }}>
                          Desvincular
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="interface-panel-padding interface-hint">
          Este hardware no tiene interfaces asociadas.
        </div>
      )}

      {showSelector && canManage && asset.inventory_status === "ACTIVE" && (
        <div className="interface-panel-padding">
          <InterfaceSelector value={selection} onChange={setSelection} disabled={busy} />
          <div className="table-actions interface-panel-actions">
            <button type="button" className="button-secondary" disabled={busy}
              onClick={() => { setShowSelector(false); setSelection(null); }}>
              Cancelar
            </button>
            <button type="button" className="button-primary"
              disabled={busy || !selection} onClick={assign}>
              {busy ? "Guardando..." : "Confirmar asociación"}
            </button>
          </div>
        </div>
      )}

      {pendingUnlink && canManage && (
        <div className="interface-panel-padding">
          <strong>¿Desvincular {pendingUnlink.mac || "interfaz #" + pendingUnlink.id}?</strong>
          <p className="interface-hint">Las observaciones PCAP no se eliminarán.</p>
          <div className="table-actions">
            <button type="button" className="button-secondary" disabled={busy}
              onClick={() => setPendingUnlink(null)}>Cancelar</button>
            <button type="button" className="button-primary" disabled={busy} onClick={unlink}>
              {busy ? "Procesando..." : "Confirmar desvinculación"}
            </button>
          </div>
        </div>
      )}
    </section>
  );
}
