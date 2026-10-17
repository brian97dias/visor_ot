import { useEffect, useState } from "react";
import { getAssets, getSoftwareHistory } from "../api/assets";
import { getSystems } from "../api/systems";
import SystemMembershipSection from "./SystemMembershipSection";
import AssetSoftwareSection from "./AssetSoftwareSection";
import SoftwareHardwareSection from "./SoftwareHardwareSection";
import SoftwareFields from "./SoftwareFields";
import { Link } from "react-router-dom";
import InterfaceSelector from "./InterfaceSelector";
import AssetInterfacesSection from "./AssetInterfacesSection";

import {
  canEditAssetCriticality,
  CRITICALITY_LABELS,
  ROLE_LABELS,
} from "../utils/assetPermissions";

function initialValues(asset, initialType = "HARDWARE") {
  return {
    name: asset?.name || "",
    description: asset?.description || "",
    asset_type: asset?.asset_type || initialType,
    criticality: asset?.criticality || "UNDEFINED",
    impact: asset?.impact || "",
    replacement_cost: asset?.replacement_cost ?? "",
    replacement_currency: asset?.replacement_currency || "",
    hardware: {
      manufacturer: asset?.hardware?.manufacturer || "",
      model: asset?.hardware?.model || "",
      role: asset?.hardware?.role || "PLC",
      serial_number: asset?.hardware?.serial_number || "",
      physical_location: asset?.hardware?.physical_location || "",
    },
    software: {
      software_type: asset?.software?.software_type || "FIRMWARE",
      manufacturer: asset?.software?.manufacturer || "",
      product: asset?.software?.product || "",
      version: asset?.software?.version || "",
    },
  };
}

function buildPayload(values, original, editing, canEditCriticality) {
  const technicalKey = values.asset_type === "SOFTWARE" ? "software" : "hardware";
  const data = {
    name: values.name.trim(),
    description: values.description.trim(),
    criticality: values.criticality,
    impact: values.impact.trim(),
    replacement_cost: values.replacement_cost === "" ? null : values.replacement_cost,
    replacement_currency: values.replacement_currency,
    [technicalKey]: Object.fromEntries(
      Object.entries(values[technicalKey]).map(([key, value]) =>
        [key, typeof value === "string" ? value.trim() : value]
      )
    ),
  };

  if (!editing) return { ...data, asset_type: values.asset_type };
  if (!canEditCriticality) delete data.criticality;

  const differences = {};
  for (const field of [
    "name", "description", "criticality", "impact",
    "replacement_cost", "replacement_currency",
  ]) {
    if (!(field in data)) continue;
    if (String(data[field] ?? "") !== String(original[field] ?? "")) {
      differences[field] = data[field];
    }
  }

  const technicalChanges = {};
  for (const [field, value] of Object.entries(data[technicalKey])) {
    if (value !== original[technicalKey]?.[field]) technicalChanges[field] = value;
  }
  if (Object.keys(technicalChanges).length) {
    differences[technicalKey] = technicalChanges;
  }
  return differences;
}

function AssetForm({ asset = null, user, onSave, saving, error, initialType = "HARDWARE", initialHardwareId = "", onDirtyChange, backTo, backState, onBackClick }) {
  const editing = Boolean(asset);
  const canEditCriticality = canEditAssetCriticality(user);
  const [values, setValues] = useState(() => initialValues(asset, initialType));
  const [hardwareAssetId, setHardwareAssetId] = useState(String(initialHardwareId || ""));
  const [hardwareChoices, setHardwareChoices] = useState([]);
  const [loadingHardware, setLoadingHardware] = useState(false);
  const [hardwareError, setHardwareError] = useState("");
  const [softwareHistory, setSoftwareHistory] = useState(null);
  const [softwareHistoryRevision, setSoftwareHistoryRevision] = useState(0);
  const [historyError, setHistoryError] = useState("");
  const [correctionReason, setCorrectionReason] = useState("");
  const [confirmShared, setConfirmShared] = useState(false);
  const [softwareChangeType, setSoftwareChangeType] = useState("CORRECTION");
  const [localError, setLocalError] = useState("");
  const [interfaceAssignment, setInterfaceAssignment] = useState(null);
  const [systemChoices, setSystemChoices] = useState([]);
  const [selectedSystemIds, setSelectedSystemIds] = useState([]);
  const [systemError, setSystemError] = useState("");
  const [loadingSystems, setLoadingSystems] = useState(false);
  const [pendingInterface, setPendingInterface] = useState(null);
  const [showCreateSelector, setShowCreateSelector] = useState(false);
  const dirty = JSON.stringify(values) !== JSON.stringify(initialValues(asset, initialType))
    || (!editing && hardwareAssetId !== String(initialHardwareId || ""))
    || (!editing && interfaceAssignment !== null)
    || (!editing && values.asset_type === "HARDWARE" && selectedSystemIds.length > 0);
  useEffect(() => { onDirtyChange?.(dirty); }, [dirty, onDirtyChange]);

  useEffect(() => {
    if (editing || values.asset_type !== "HARDWARE") return;
    let active = true;
    setLoadingSystems(true);
    setSystemError("");
    getSystems("ACTIVE").then(rows => {
      if (active) setSystemChoices(rows);
    }).catch(err => {
      if (active) setSystemError(err.message);
    }).finally(() => {
      if (active) setLoadingSystems(false);
    });
    return () => { active = false; };
  }, [editing, values.asset_type]);

  useEffect(() => {
    if (editing || values.asset_type !== "SOFTWARE") return;
    let active = true;
    setLoadingHardware(true);
    setHardwareError("");
    getAssets("ACTIVE")
      .then((items) => {
        if (active) setHardwareChoices(items.filter((item) => item.asset_type === "HARDWARE"));
      })
      .catch((err) => { if (active) setHardwareError(err.message); })
      .finally(() => { if (active) setLoadingHardware(false); });
    return () => { active = false; };
  }, [editing, values.asset_type]);

  useEffect(() => {
    if (!editing || asset.asset_type !== "SOFTWARE") return;
    let active = true;
    setHistoryError("");
    getSoftwareHistory(asset.id)
      .then((info) => { if (active) setSoftwareHistory(info); })
      .catch((err) => { if (active) setHistoryError(err.message); });
    return () => { active = false; };
  }, [asset?.id, asset?.asset_type, editing, softwareHistoryRevision]);

  const technicalChanged = editing && values.asset_type === "SOFTWARE"
    && ["software_type", "manufacturer", "product", "version"].some(
      (field) => values.software[field].trim() !== String(asset?.software?.[field] || "").trim()
    );

  function change(field, value) {
    setValues((current) => ({ ...current, [field]: value }));
  }

  function changeHardware(field, value) {
    setValues((current) => ({
      ...current,
      hardware: { ...current.hardware, [field]: value },
    }));
  }

  function changeSoftware(field, value) {
    setValues((current) => ({
      ...current,
      software: { ...current.software, [field]: value },
    }));
  }

  async function submit(event) {
    event.preventDefault();
    setLocalError("");

    if (values.replacement_cost !== "" && !values.replacement_currency) {
      setLocalError("Selecciona la moneda del costo de reposición.");
      return;
    }
    if (values.replacement_cost === "" && values.replacement_currency) {
      setLocalError("Indica el costo de reposición o deja la moneda sin seleccionar.");
      return;
    }

    const payload = buildPayload(values, asset, editing, canEditCriticality);
    if (!editing && values.asset_type === "HARDWARE" && selectedSystemIds.length) {
      if (systemError || selectedSystemIds.some(id=>!systemChoices.some(s=>s.id===id))) {
        setLocalError("Uno de los sistemas seleccionados ya no está disponible.");
        return;
      }
      payload.system_ids = selectedSystemIds;
    }
    if (!editing && values.asset_type === "SOFTWARE" && hardwareAssetId) {
      if (!hardwareChoices.some((item) => item.id === Number(hardwareAssetId))) {
        setLocalError("El hardware seleccionado no está disponible.");
        return;
      }
      payload.hardware_asset_id = Number(hardwareAssetId);
    }
    if (editing && values.asset_type === "SOFTWARE" && technicalChanged) {
      if (softwareChangeType === "UPGRADE") {
        setLocalError("Para una actualización real, registra otra variante y reasigna el hardware.");
        return;
      }
      if (!correctionReason.trim()) {
        setLocalError("Explica el motivo de la corrección técnica.");
        return;
      }
      if (historyError) {
        setLocalError("No se pudo consultar el historial. Intenta recargar antes de corregir.");
        return;
      }
      if (!softwareHistory) {
        setLocalError("Espera mientras consultamos el historial de instalaciones.");
        return;
      }
      if (softwareHistory.active_installation_count > 1 && !confirmShared) {
        setLocalError("Confirma la corrección compartida con los hardware relacionados.");
        return;
      }
      payload.correction_reason = correctionReason.trim();
      payload.confirm_shared_correction = confirmShared;
      payload.software_change_type = "CORRECTION";
    }
    if (!editing && values.asset_type === "HARDWARE" && interfaceAssignment) {
      if (interfaceAssignment.mode === "MANUAL" &&
          !interfaceAssignment.mac?.trim() &&
          !interfaceAssignment.declared_ip?.trim()) {
        setLocalError("Indica una MAC o IP, o deja la interfaz sin seleccionar.");
        return;
      }
      payload.interface_assignment = interfaceAssignment;
    }
    await onSave(payload);
  }

  return (
    <form className="assets-form panel" onSubmit={submit}>
      <div className="assets-form-section">
        <h2>Información general</h2>
        <div className="assets-field">
          <label htmlFor="asset-name">Nombre del activo *</label>
          <input id="asset-name" required maxLength={200}
            value={values.name} onChange={(event) => change("name", event.target.value)}
            placeholder="Ej. DirectLogic 205" />
        </div>
        <div className="assets-field">
          <label htmlFor="asset-description">Descripción</label>
          <textarea id="asset-description" rows={3}
            value={values.description}
            onChange={(event) => change("description", event.target.value)}
            placeholder="Describe la función del activo en la planta" />
        </div>
        <div className="assets-field">
          <span className="assets-field-label">Tipo de activo</span>
          <div className="assets-type-select" role="group" aria-label="Tipo de activo">
            {["HARDWARE", "SOFTWARE"].map((kind) => (
              <button key={kind} type="button"
                className={"assets-type-choice" + (values.asset_type === kind ? " selected" : "")}
                aria-pressed={values.asset_type === kind}
                disabled={editing || saving}
                title={editing ? "El tipo de activo no puede cambiarse después del registro" : undefined}
                onClick={() => {
                  change("asset_type", kind);
                  setInterfaceAssignment(null);
                  setPendingInterface(null);
                  setSelectedSystemIds([]);
                  setShowCreateSelector(false);
                  setLocalError("");
                }}>
                {kind === "HARDWARE" ? "Hardware" : "Software"}
              </button>
            ))}
          </div>
          {editing && <small>El tipo de activo no se puede modificar después del registro.</small>}
        </div>
      </div>

      {values.asset_type === "HARDWARE" && (
        <>
      <div className="assets-form-section">
        <h2>Datos del hardware</h2>
        <div className="assets-form-grid">
          <div className="assets-field">
            <label htmlFor="asset-manufacturer">Fabricante</label>
            <input id="asset-manufacturer" maxLength={200}
              value={values.hardware.manufacturer}
              onChange={(event) => changeHardware("manufacturer", event.target.value)}
              placeholder="Ej. AutomationDirect" />
          </div>
          <div className="assets-field">
            <label htmlFor="asset-model">Modelo / familia</label>
            <input id="asset-model" maxLength={200}
              value={values.hardware.model}
              onChange={(event) => changeHardware("model", event.target.value)}
              placeholder="Ej. DirectLOGIC DL205" />
          </div>
          <div className="assets-field">
            <label htmlFor="asset-role">Rol del hardware *</label>
            <select id="asset-role" required
              value={values.hardware.role}
              onChange={(event) => changeHardware("role", event.target.value)}>
              {Object.entries(ROLE_LABELS).map(([value, label]) => (
                <option key={value} value={value}>{label}</option>
              ))}
            </select>
          </div>
          <div className="assets-field">
            <label htmlFor="asset-serial">Número de serie</label>
            <input id="asset-serial" maxLength={150}
              value={values.hardware.serial_number}
              onChange={(event) => changeHardware("serial_number", event.target.value)}
              placeholder="Opcional / desconocido" />
          </div>
          <div className="assets-field assets-full-row">
            <label htmlFor="asset-location">Ubicación física</label>
            <input id="asset-location" maxLength={255}
              value={values.hardware.physical_location}
              onChange={(event) => changeHardware("physical_location", event.target.value)}
              placeholder="Ej. Sala de control" />
          </div>
        </div>
      </div>

      {!editing && <div className="assets-form-section">
        <h2>Sistemas OT (opcional)</h2>
        <p className="interface-hint">
          Puedes asociar este hardware a uno o varios sistemas registrados.
          También puedes hacerlo después desde el detalle del Hardware o del Sistema.
        </p>
        {loadingSystems && <p className="interface-hint">Cargando sistemas...</p>}
        {systemError && <p className="error-message" role="alert">{systemError}</p>}
        {!loadingSystems && !systemError && systemChoices.length===0 &&
          <p className="interface-hint">Todavía no hay sistemas activos disponibles.</p>}
        {systemChoices.map(system=>(
          <label className="system-initial-choice" key={system.id}>
            <input type="checkbox" checked={selectedSystemIds.includes(system.id)}
              disabled={saving || loadingSystems}
              onChange={event=>setSelectedSystemIds(current=>event.target.checked
                ? [...current,system.id] : current.filter(id=>id!==system.id))}/>
            <span>{system.name}</span>
          </label>
        ))}
      </div>}

      {editing ? (
        <AssetInterfacesSection asset={asset} user={user} embedded />
      ) : (
        <div className="assets-form-section">
          <h2>Interfaces de red</h2>
          <div>
            <p className="interface-hint">
              Opcional. Si no seleccionas ninguna interfaz, el hardware se registrará sin asociación.
            </p>
            <button type="button" className="button-secondary" disabled={saving}
              onClick={() => {
                setShowCreateSelector((current) => !current);
                setInterfaceAssignment(null);
                setPendingInterface(null);
              }}>
              {showCreateSelector ? "Cerrar selector" : "Asociar interfaz"}
            </button>
            {showCreateSelector && (
              <>
                <InterfaceSelector value={pendingInterface}
                  onChange={setPendingInterface} disabled={saving} />
                <div className="table-actions interface-panel-actions">
                  <button type="button" className="button-secondary" disabled={saving}
                    onClick={() => {
                      setPendingInterface(null);
                      setShowCreateSelector(false);
                    }}>
                    Cancelar
                  </button>
                  <button type="button" className="button-primary"
                    disabled={saving || !pendingInterface}
                    onClick={() => {
                      if (pendingInterface.mode === "MANUAL" &&
                          !pendingInterface.mac?.trim() &&
                          !pendingInterface.declared_ip?.trim()) {
                        setLocalError("Indica al menos una MAC o IP.");
                        return;
                      }
                      setLocalError("");
                      setInterfaceAssignment(pendingInterface);
                      setShowCreateSelector(false);
                    }}>
                    Confirmar selección
                  </button>
                </div>
              </>
            )}
            {interfaceAssignment && !showCreateSelector && (
              <p className="interface-selection-note">
                {interfaceAssignment.mode === "EXISTING"
                  ? "Interfaz #" + interfaceAssignment.interface_id + " confirmada para este hardware."
                  : "Interfaz manual preparada para el registro."}
                <button type="button" disabled={saving}
                  onClick={() => {
                    setInterfaceAssignment(null);
                    setPendingInterface(null);
                  }}>Quitar selección</button>
              </p>
            )}
          </div>
        </div>
      )}

        </>
      )}

      {values.asset_type === "SOFTWARE" && (
        <div className="assets-form-section">
          <h2>Información del software</h2>
          <SoftwareFields idPrefix="software" values={values.software}
            onChange={changeSoftware} disabled={saving} />
          <p className="interface-hint">
            El software se registra como activo del inventario; sus instalaciones
            en hardware se pueden consultar y gestionar desde cada dispositivo.
          </p>
        </div>
      )}

      {values.asset_type === "SOFTWARE" && !editing && (
        <div className="assets-form-section">
          <h2>Hardware donde se instalará</h2>
          <p className="interface-hint">
            Opcional. Puedes registrar el software sin un hardware asociado
            y vincularlo posteriormente desde el hardware correspondiente.
          </p>
          <div className="assets-field">
            <label htmlFor="software-hardware">Hardware de destino (opcional)</label>
            <select id="software-hardware" disabled={loadingHardware || saving}
              value={hardwareAssetId}
              onChange={(event) => setHardwareAssetId(event.target.value)}>
              <option value="">Sin asociar por ahora</option>
              {hardwareChoices.map((item) => (
                <option value={item.id} key={item.id}>
                  {item.name} · {item.hardware?.manufacturer || "Fabricante desconocido"}
                  {item.hardware?.model ? " · " + item.hardware.model : ""}
                </option>
              ))}
            </select>
            {loadingHardware && <small>Cargando hardware...</small>}
            {hardwareError && <small role="alert">{hardwareError}</small>}
            {!loadingHardware && !hardwareError && hardwareChoices.length === 0 && (
              <small>No hay hardware disponible; puedes registrar el software sin asociarlo.</small>
            )}
          </div>
        </div>
      )}

      {editing && values.asset_type === "SOFTWARE" && (
        <SoftwareHardwareSection asset={asset} user={user}
          onInstallationsChange={() => setSoftwareHistoryRevision((count) => count + 1)} />
      )}

      {editing && values.asset_type === "SOFTWARE" && technicalChanged && (
        <div className="assets-form-section software-correction-section">
          <h2>Corrección de datos técnicos</h2>
          <p className="interface-hint">
            ¿Estás corrigiendo un dato que se registró incorrectamente o
            registrando una actualización real del firmware?
          </p>
          <div className="assets-field">
            <label htmlFor="software-change-type">Tipo de modificación</label>
            <select id="software-change-type" value={softwareChangeType}
              disabled={saving}
              onChange={(event) => setSoftwareChangeType(event.target.value)}>
              <option value="CORRECTION">Corregir información del inventario</option>
              <option value="UPGRADE">Actualización real de software</option>
            </select>
          </div>
          {softwareChangeType === "UPGRADE" ? (
            <>
              <p className="interface-hint">
                Una actualización real requiere una nueva variante. Conserva esta
                versión y registra otra desde el inventario; después traslada
                la instalación en el hardware correspondiente.
              </p>
              <Link className="button-secondary" to="/assets/new?type=SOFTWARE">
                Registrar nueva variante
              </Link>
            </>
          ) : (
            <>
              <div className="assets-field">
                <label htmlFor="software-correction-reason">Motivo de la corrección *</label>
                <textarea id="software-correction-reason" rows={2}
                  maxLength={1000} disabled={saving}
                  value={correctionReason}
                  placeholder="Ej. Error de transcripción de la versión"
                  onChange={(event) => setCorrectionReason(event.target.value)} />
              </div>
              {softwareHistory && (
                <p className="interface-hint">
                  Instalaciones vigentes: {softwareHistory.active_installation_count}.
                  Registros históricos: {softwareHistory.installation_history_count}.
                  Las identidades registradas anteriormente se conservarán.
                </p>
              )}
              {historyError && <p className="error-message">{historyError}</p>}
              {softwareHistory?.active_installation_count > 1 && (
                <label className="software-correction-confirm">
                  <input type="checkbox" checked={confirmShared}
                    disabled={saving}
                    onChange={(event) => setConfirmShared(event.target.checked)} />
                  <span>Confirmo que el dato estaba incorrecto para todos los
                    hardware que comparten esta variante.</span>
                </label>
              )}
            </>
          )}
        </div>
      )}

      {editing && values.asset_type === "HARDWARE" && (
        <AssetSoftwareSection asset={asset} user={user} embedded />
      )}

      {editing && values.asset_type === "HARDWARE" &&
        <SystemMembershipSection asset={asset} user={user} embedded />}

      <div className="assets-form-section">
        <h2>Clasificación y valoración</h2>
        <div className="assets-form-grid">
          <div className="assets-field">
            <label htmlFor="asset-criticality">Criticidad</label>
            <select id="asset-criticality" value={values.criticality}
              disabled={!canEditCriticality}
              onChange={(event) => change("criticality", event.target.value)}>
              {Object.entries(CRITICALITY_LABELS).map(([value, label]) => (
                <option key={value} value={value}>{label}</option>
              ))}
            </select>
            {!canEditCriticality && <small>Solo el operador de planta o el administrador pueden cambiar la criticidad.</small>}
          </div>
          <div className="assets-field">
            <label htmlFor="asset-cost">Costo de reposición estimado</label>
            <input id="asset-cost" type="number" min="0" step="0.01"
              value={values.replacement_cost}
              onChange={(event) => change("replacement_cost", event.target.value)}
              placeholder="Opcional" />
          </div>
          <div className="assets-field">
            <label htmlFor="asset-currency">Moneda</label>
            <select id="asset-currency" value={values.replacement_currency}
              onChange={(event) => change("replacement_currency", event.target.value)}>
              <option value="">Sin registrar</option>
              <option value="COP">COP — Peso colombiano</option>
              <option value="USD">USD — Dólar estadounidense</option>
              <option value="EUR">EUR — Euro</option>
              <option value="INR">INR — Rupia india</option>
              <option value="AUD">AUD — Dólar australiano</option>
            </select>
          </div>
          <div className="assets-field assets-full-row">
            <label htmlFor="asset-impact">Impacto de indisponibilidad</label>
            <textarea id="asset-impact" rows={3}
              value={values.impact} onChange={(event) => change("impact", event.target.value)}
              placeholder="¿Qué pasaría si este activo dejara de estar disponible?" />
          </div>
        </div>
      </div>

      {(localError || error) && <div className="error-message assets-form-error">{localError || error}</div>}

      <div className="assets-form-actions">
        <Link className="button-link" to={backTo || (editing ? "/assets/" + asset.id : "/assets")}
          state={backState || null} onClick={onBackClick}>
          Cancelar
        </Link>
        <button className="button-primary" type="submit" disabled={saving}>
          {saving ? "Guardando..." : editing ? "Guardar cambios" : "Registrar activo"}
        </button>
      </div>
    </form>
  );
}

export default AssetForm;
