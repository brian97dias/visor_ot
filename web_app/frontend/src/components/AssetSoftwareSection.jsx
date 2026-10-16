import { useEffect, useState } from "react";
import { Link } from "react-router-dom";

import {
  associateExistingSoftware, createAsset, getAssets,
  getInstalledSoftware, unlinkInstalledSoftware,
} from "../api/assets";
import SuccessNotice from "./SuccessNotice";
import SearchableSoftwareSelect from "./SearchableSoftwareSelect";
import SoftwareFields, { emptySoftwareFields } from "./SoftwareFields";
import { buildInstalledSoftwarePayload, validateNewSoftware } from "../utils/softwareRegistration";
import {
  canCreateAssets, CRITICALITY_LABELS, SOFTWARE_TYPE_LABELS,
} from "../utils/assetPermissions";

function emptyRegistration() {
  return {
    name: "",
    description: "",
    criticality: "UNDEFINED",
    replacement_cost: "",
    replacement_currency: "",
    impact: "",
    software: emptySoftwareFields(),
  };
}

/** Shared on Hardware detail and Hardware edit.
 * All actions are type="button": this may be nested within AssetForm's <form>.
 * Associations and new software are saved immediately, independently of
 * the unsaved Hardware form fields.
 */
export default function AssetSoftwareSection({ asset, user, embedded = false }) {
  const canManage = canCreateAssets(user) && asset.inventory_status === "ACTIVE";
  const [installed, setInstalled] = useState([]);
  const [candidates, setCandidates] = useState([]);
  const [loading, setLoading] = useState(true);
  const [loadingCandidates, setLoadingCandidates] = useState(false);
  const [busy, setBusy] = useState(false);
  const [revision, setRevision] = useState(0);
  const [showChooser, setShowChooser] = useState(false);
  const [mode, setMode] = useState("existing");
  const [softwareAssetId, setSoftwareAssetId] = useState(null);
  const [registration, setRegistration] = useState(emptyRegistration);
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
    if (!showChooser || mode !== "existing" || !canManage) return;
    let active = true;
    setLoadingCandidates(true);
    getAssets("ACTIVE")
      .then((items) => {
        if (active) {
          setCandidates(items.filter((item) => item.asset_type === "SOFTWARE"));
        }
      })
      .catch((err) => { if (active) setError(err.message); })
      .finally(() => { if (active) setLoadingCandidates(false); });
    return () => { active = false; };
  }, [showChooser, mode, canManage, revision]);

  const installedIds = new Set(installed.map((row) => row.software_asset_id));
  const available = candidates.filter((item) => !installedIds.has(item.id));

  function closeChooser() {
    setShowChooser(false);
    setMode("existing");
    setSoftwareAssetId(null);
    setRegistration(emptyRegistration());
    setError("");
  }

  function updateRegistration(field, value) {
    setRegistration((current) => ({ ...current, [field]: value }));
  }

  function updateSoftware(field, value) {
    setRegistration((current) => ({
      ...current,
      software: { ...current.software, [field]: value },
    }));
  }

  async function associate() {
    if (busy || !softwareAssetId) return;
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await associateExistingSoftware(asset.id, Number(softwareAssetId));
      setRevision((current) => current + 1);
      closeChooser();
      setNotice("Software asociado. El cambio se guardó inmediatamente.");
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function registerNew() {
    if (busy || !canManage) return;
    setError("");
    setNotice("");

    const validationError = validateNewSoftware(registration, asset.id);
    if (validationError) {
      setError(validationError);
      return;
    }

    setBusy(true);
    try {
      // The existing API performs create + mandatory first installation in
      // one transaction. If association fails, no orphan asset is persisted.
      await createAsset(buildInstalledSoftwarePayload(registration, asset.id));
      setRevision((current) => current + 1);
      closeChooser();
      setNotice("Software registrado e instalado en este hardware.");
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

  return (
    <section className={embedded ? "assets-form-section" : "panel assets-detail-section"}>
      <div className={embedded ? "interface-section-header" : "panel-header"}>
        <div>
          <h2>Software instalado</h2>
          <p className="interface-hint">
            Firmware, sistemas operativos y aplicaciones asociados a este hardware.
          </p>
        </div>
        {canManage && (
          <button className="button-secondary" type="button" disabled={busy}
            onClick={() => {
              if (showChooser) closeChooser();
              else { setShowChooser(true); setError(""); }
            }}>
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
      ) : installed.length ? (
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
        <p className="interface-panel-padding interface-hint">
          Este hardware no tiene software asociado.
        </p>
      )}

      {showChooser && canManage && (
        <div className="interface-panel-padding software-install-editor"
          onKeyDown={(event) => {
            // Avoid Enter in an inline input submitting the parent Hardware form.
            if (event.key === "Enter" && event.target.tagName === "INPUT") {
              event.preventDefault();
            }
          }}>
          <div className="software-install-modes" role="group"
            aria-label="Cómo añadir software">
            <button type="button" disabled={busy}
              aria-pressed={mode === "existing"}
              className={"assets-type-choice" + (mode === "existing" ? " selected" : "")}
              onClick={() => { setMode("existing"); setError(""); }}>
              Asociar existente
            </button>
            <button type="button" disabled={busy}
              aria-pressed={mode === "new"}
              className={"assets-type-choice" + (mode === "new" ? " selected" : "")}
              onClick={() => { setMode("new"); setError(""); }}>
              Registrar nuevo
            </button>
          </div>

          {mode === "existing" ? (
            <>
              <SearchableSoftwareSelect
                options={available}
                selectedId={softwareAssetId}
                onChange={setSoftwareAssetId}
                disabled={busy || loadingCandidates}
              />
              {loadingCandidates && <p className="interface-hint">Cargando variantes...</p>}
              {!loadingCandidates && available.length === 0 && (
                <p className="interface-hint">
                  No hay variantes disponibles para asociar. Puedes registrar una nueva.
                </p>
              )}
              <div className="table-actions interface-panel-actions">
                <button type="button" className="button-secondary" disabled={busy}
                  onClick={closeChooser}>Cancelar</button>
                <button type="button" className="button-primary"
                  disabled={busy || !softwareAssetId} onClick={associate}>
                  {busy ? "Guardando..." : "Confirmar asociación"}
                </button>
              </div>
            </>
          ) : (
            <>
              <p className="interface-hint">
                Nuevo software para <strong>{asset.name}</strong>. Su primera instalación
                se registrará automáticamente al confirmar.
              </p>
              <div className="assets-field">
                <label htmlFor={"inline-software-name-" + asset.id}>Nombre del activo *</label>
                <input id={"inline-software-name-" + asset.id} maxLength={200} disabled={busy}
                  form={"inline-software-independent-" + asset.id}
                  value={registration.name}
                  placeholder="Ej. Firmware ADAM-5000"
                  onChange={(event) => updateRegistration("name", event.target.value)}/>
              </div>
              <SoftwareFields idPrefix={"inline-software-" + asset.id}
                values={registration.software} onChange={updateSoftware}
                required={false} disabled={busy} formId={"inline-software-independent-" + asset.id}/>
              <details className="software-extra-fields">
                <summary>Descripción y clasificación (opcional)</summary>
                <div className="assets-form-grid">
                  <div className="assets-field assets-full-row">
                    <label htmlFor={"inline-description-" + asset.id}>Descripción</label>
                    <textarea id={"inline-description-" + asset.id} rows={2}
                      form={"inline-software-independent-" + asset.id}
                      disabled={busy} value={registration.description}
                      onChange={(event) => updateRegistration("description", event.target.value)}/>
                  </div>
                  <div className="assets-field">
                    <label htmlFor={"inline-criticality-" + asset.id}>Criticidad</label>
                    <select id={"inline-criticality-" + asset.id}
                      form={"inline-software-independent-" + asset.id}
                      value={registration.criticality} disabled={busy}
                      onChange={(event) => updateRegistration("criticality", event.target.value)}>
                      {Object.entries(CRITICALITY_LABELS).map(([value, label]) => (
                        <option value={value} key={value}>{label}</option>
                      ))}
                    </select>
                  </div>
                  <div className="assets-field">
                    <label htmlFor={"inline-cost-" + asset.id}>Costo de reposición</label>
                    <input id={"inline-cost-" + asset.id} type="number" min="0" step="0.01"
                      form={"inline-software-independent-" + asset.id}
                      disabled={busy} value={registration.replacement_cost}
                      onChange={(event) => updateRegistration("replacement_cost", event.target.value)}/>
                  </div>
                  <div className="assets-field">
                    <label htmlFor={"inline-currency-" + asset.id}>Moneda</label>
                    <select id={"inline-currency-" + asset.id}
                      form={"inline-software-independent-" + asset.id}
                      value={registration.replacement_currency} disabled={busy}
                      onChange={(event) => updateRegistration("replacement_currency", event.target.value)}>
                      <option value="">Sin registrar</option>
                      <option value="COP">COP — Peso colombiano</option>
                      <option value="USD">USD — Dólar estadounidense</option>
                      <option value="EUR">EUR — Euro</option>
              <option value="INR">INR — Rupia india</option>
              <option value="AUD">AUD — Dólar australiano</option>
                    </select>
                  </div>
                  <div className="assets-field assets-full-row">
                    <label htmlFor={"inline-impact-" + asset.id}>Impacto de indisponibilidad</label>
                    <textarea id={"inline-impact-" + asset.id} rows={2}
                      form={"inline-software-independent-" + asset.id}
                      disabled={busy} value={registration.impact}
                      onChange={(event) => updateRegistration("impact", event.target.value)}/>
                  </div>
                </div>
              </details>
              <div className="table-actions interface-panel-actions">
                <button type="button" className="button-secondary" disabled={busy}
                  onClick={closeChooser}>Cancelar</button>
                <button type="button" className="button-primary" disabled={busy}
                  onClick={registerNew}>
                  {busy ? "Registrando..." : "Registrar e instalar software"}
                </button>
              </div>
            </>
          )}
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
