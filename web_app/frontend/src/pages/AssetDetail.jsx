import { useEffect, useState } from "react";
import {
  Link, useLocation, useNavigate, useOutletContext, useParams,
} from "react-router-dom";

import { archiveAsset, getAsset, restoreAsset } from "../api/assets";
import SuccessNotice from "../components/SuccessNotice";
import ConfirmAssetStatusModal from "../components/ConfirmAssetStatusModal";
import InterfaceSelector from "../components/InterfaceSelector";
import { assignAssetInterface, getInterfaces, unlinkInterface } from "../api/interfaces";
import {
  canArchiveAssets,
  canEditAssets,
  canCreateAssets,
  CRITICALITY_LABELS,
  displayCost,
  displayValue,
  INVENTORY_STATUS_LABELS,
  ROLE_LABELS,
} from "../utils/assetPermissions";

function Field({ label, value, wide = false }) {
  return (
    <div className={wide ? "assets-full-row" : undefined}>
      <span>{label}</span>
      <strong>{displayValue(value)}</strong>
    </div>
  );
}

function AssetDetail() {
  const { assetId } = useParams();
  const { user } = useOutletContext();
  const location = useLocation();
  const navigate = useNavigate();
  const [asset, setAsset] = useState(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState(location.state?.notice || "");
  const [busy, setBusy] = useState(false);
  const [showConfirmation, setShowConfirmation] = useState(false);
  const [interfaces, setInterfaces] = useState([]);
  const [interfacesLoading, setInterfacesLoading] = useState(false);
  const [interfacesRevision, setInterfacesRevision] = useState(0);
  const [showInterfaceSelector, setShowInterfaceSelector] = useState(false);
  const [interfaceSelection, setInterfaceSelection] = useState(null);
  const [interfaceBusy, setInterfaceBusy] = useState(false);
  const [pendingUnlink, setPendingUnlink] = useState(null);

  useEffect(() => {
    let active = true;
    setError("");
    getAsset(assetId)
      .then((data) => { if (active) setAsset(data); })
      .catch((err) => { if (active) setError(err.message); });
    return () => { active = false; };
  }, [assetId]);

  useEffect(() => {
    if (!location.state?.notice) return;
    setNotice(location.state.notice);
    navigate(location.pathname, { replace: true, state: null });
  }, [location.state, location.pathname, navigate]);

  useEffect(() => {
    if (!asset?.hardware) return;
    let active = true;
    setInterfacesLoading(true);
    getInterfaces({ hardwareId: asset.id })
      .then((result) => { if (active) setInterfaces(result.results); })
      .catch((err) => { if (active) setError(err.message); })
      .finally(() => { if (active) setInterfacesLoading(false); });
    return () => { active = false; };
  }, [asset?.id, interfacesRevision]);

  async function assignSelectedInterface() {
    if (!interfaceSelection || !asset || interfaceBusy) return;
    if (interfaceSelection.mode === "MANUAL" &&
        !interfaceSelection.mac?.trim() &&
        !interfaceSelection.declared_ip?.trim()) {
      setError("Para el registro manual indica MAC y/o IP.");
      return;
    }
    setInterfaceBusy(true);
    setError("");
    setNotice("");
    try {
      await assignAssetInterface(asset.id, interfaceSelection);
      setInterfacesRevision((current) => current + 1);
      setInterfaceSelection(null);
      setShowInterfaceSelector(false);
      setNotice("Interfaz asociada correctamente.");
    } catch (err) { setError(err.message); }
    finally { setInterfaceBusy(false); }
  }

  async function confirmUnlinkInterface() {
    if (!pendingUnlink || interfaceBusy) return;
    setInterfaceBusy(true);
    setError("");
    setNotice("");
    try {
      await unlinkInterface(pendingUnlink.id);
      setPendingUnlink(null);
      setInterfacesRevision((current) => current + 1);
      setNotice("Interfaz desvinculada; las observaciones se conservan.");
    } catch (err) { setError(err.message); }
    finally { setInterfaceBusy(false); }
  }

  async function confirmInventoryStatusChange() {
    if (busy) return;
    const archived = asset.inventory_status === "ARCHIVED";

    setBusy(true);
    setError("");
    setNotice("");
    try {
      const updated = archived ? await restoreAsset(asset.id) : await archiveAsset(asset.id);
      setAsset(updated);
      setNotice(archived ? "Activo restaurado correctamente." : "Activo archivado correctamente.");
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
      setShowConfirmation(false);
    }
  }

  if (error && !asset) {
    return <section className="page">
      <div className="error-message">{error}</div>
      <Link className="button-link" to="/assets">Volver al inventario</Link>
    </section>;
  }

  if (!asset) {
    return <section className="page">Cargando activo...</section>;
  }

  return (
    <section className="page">
      <div className="breadcrumbs">
        <span>Activos</span><span>/</span>
        <Link to="/assets">Inventario</Link><span>/</span><span>#{asset.id}</span>
      </div>

      <header className="page-header assets-page-heading">
        <div>
          <span className="page-eyebrow">ACTIVO #{asset.id}</span>
          <h1>{asset.name}</h1>
          <p>Información administrativa y técnica del activo.</p>
        </div>

        <div className="table-actions assets-detail-actions">
          {canEditAssets(user) && (
            <Link className="button-primary assets-primary-link" to={"/assets/" + asset.id + "/edit"}>
              Editar activo
            </Link>
          )}
          {canArchiveAssets(user) && (
            <button type="button" className="button-secondary assets-archive-button"
              disabled={busy} onClick={() => setShowConfirmation(true)}>
              {busy ? "Procesando..." : asset.inventory_status === "ARCHIVED" ? "Restaurar activo" : "Archivar activo"}
            </button>
          )}
        </div>
      </header>

      <SuccessNotice message={notice} onClose={() => setNotice("")} />
      {error && <div className="error-message">{error}</div>}

      <section className="panel assets-detail-section">
        <div className="panel-header"><h2>Información general</h2></div>
        <div className="assets-detail-grid">
          <Field label="Tipo de activo"
            value={asset.asset_type === "HARDWARE" ? "Hardware" : "Software"} />
          <Field label="Criticidad"
            value={CRITICALITY_LABELS[asset.criticality] || asset.criticality} />
          <Field label="Estado en inventario"
            value={INVENTORY_STATUS_LABELS[asset.inventory_status] || asset.inventory_status} />
          <Field label="Costo de reposición" value={displayCost(asset)} />
          <Field label="Descripción" value={asset.description} wide />
          <Field label="Impacto de indisponibilidad" value={asset.impact} wide />
        </div>
      </section>

      {asset.hardware && (
        <section className="panel assets-detail-section">
          <div className="panel-header"><h2>Datos del hardware</h2></div>
          <div className="assets-detail-grid">
            <Field label="Fabricante" value={asset.hardware.manufacturer} />
            <Field label="Modelo / familia" value={asset.hardware.model} />
            <Field label="Rol" value={ROLE_LABELS[asset.hardware.role] || asset.hardware.role} />
            <Field label="Número de serie" value={asset.hardware.serial_number} />
            <Field label="Ubicación física" value={asset.hardware.physical_location} />
          </div>
        </section>
      )}

      {asset.hardware && (
        <section className="panel assets-detail-section">
          <div className="panel-header">
            <div><h2>Interfaces de red</h2>
              <p>Interfaces relacionadas con este hardware.</p>
            </div>
            {canCreateAssets(user) && asset.inventory_status === "ACTIVE" && (
              <button className="button-secondary" type="button"
                disabled={interfaceBusy}
                onClick={() => {
                  setShowInterfaceSelector((current) => !current);
                  setInterfaceSelection(null);
                }}>
                {showInterfaceSelector ? "Cerrar selector" : "Asociar interfaz"}
              </button>
            )}
          </div>

          {interfacesLoading ? (
            <div className="interface-panel-padding">Cargando interfaces...</div>
          ) : interfaces.length ? (
            <div className="table-container">
              <table className="data-table">
                <thead><tr><th>MAC</th><th>IP observadas</th><th>Evidencia</th><th>Acciones</th></tr></thead>
                <tbody>{interfaces.map((item) => (
                  <tr key={item.id}>
                    <td>{item.mac || "Sin MAC"}</td>
                    <td>{item.observed_ips?.join(", ") || item.declared_ip || "Sin IP"}</td>
                    <td>{item.has_active_evidence ? "Activa" : "Sin evidencia activa"}</td>
                    <td><div className="table-actions">
                      <Link className="button-secondary" to={"/assets/interfaces/" + item.id}>
                        Ver interfaz
                      </Link>
                      {canCreateAssets(user) && (
                        <button className="button-secondary" type="button"
                          disabled={interfaceBusy}
                          onClick={() => setPendingUnlink(item)}>
                          Desvincular
                        </button>
                      )}
                    </div></td>
                  </tr>
                ))}</tbody>
              </table>
            </div>
          ) : (
            <div className="interface-panel-padding interface-hint">
              Este hardware todavía no tiene interfaces asociadas.
            </div>
          )}

          {showInterfaceSelector && canCreateAssets(user) && (
            <div className="interface-panel-padding">
              <InterfaceSelector value={interfaceSelection}
                onChange={setInterfaceSelection} disabled={interfaceBusy} />
              <div className="table-actions interface-panel-actions">
                <button type="button" className="button-secondary"
                  disabled={interfaceBusy} onClick={() => setShowInterfaceSelector(false)}>
                  Cancelar
                </button>
                <button type="button" className="button-primary"
                  disabled={interfaceBusy || !interfaceSelection}
                  onClick={assignSelectedInterface}>
                  {interfaceBusy ? "Guardando..." : "Confirmar asociación"}
                </button>
              </div>
            </div>
          )}
          {pendingUnlink && (
            <div className="interface-panel-padding">
              <strong>¿Desvincular {pendingUnlink.mac || "interfaz #" + pendingUnlink.id}?</strong>
              <p className="interface-hint">No se borrarán las observaciones del PCAP.</p>
              <div className="table-actions">
                <button className="button-secondary" type="button" disabled={interfaceBusy}
                  onClick={() => setPendingUnlink(null)}>Cancelar</button>
                <button className="button-primary" type="button" disabled={interfaceBusy}
                  onClick={confirmUnlinkInterface}>
                  {interfaceBusy ? "Procesando..." : "Confirmar desvinculación"}
                </button>
              </div>
            </div>
          )}
        </section>
      )}

      <section className="panel assets-detail-section">
        <div className="panel-header"><h2>Registro y auditoría</h2></div>
        <div className="assets-detail-grid">
          <Field label="Creado por" value={asset.created_by} />
          <Field label="Última edición por" value={asset.updated_by} />
          <Field label="Creado el" value={new Date(asset.created_at).toLocaleString("es-CO")} />
          <Field label="Actualizado el" value={new Date(asset.updated_at).toLocaleString("es-CO")} />
          {asset.inventory_status === "ARCHIVED" && (
            <>
              <Field label="Archivado por" value={asset.archived_by} />
              <Field label="Archivado el" value={asset.archived_at
                ? new Date(asset.archived_at).toLocaleString("es-CO")
                : "Sin registrar"} />
            </>
          )}
        </div>
      </section>

      {showConfirmation && (
        <ConfirmAssetStatusModal
          asset={asset}
          busy={busy}
          onCancel={() => setShowConfirmation(false)}
          onConfirm={confirmInventoryStatusChange}
        />
      )}
    </section>
  );
}

export default AssetDetail;
