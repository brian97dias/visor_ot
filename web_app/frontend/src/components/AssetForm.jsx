import { useEffect, useState } from "react";
import { getAssets } from "../api/assets";
import AssetSoftwareSection from "./AssetSoftwareSection";
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

function AssetForm({ asset = null, user, onSave, saving, error, initialType = "HARDWARE", initialHardwareId = "" }) {
  const editing = Boolean(asset);
  const canEditCriticality = canEditAssetCriticality(user);
  const [values, setValues] = useState(() => initialValues(asset, initialType));
  const [hardwareAssetId, setHardwareAssetId] = useState(String(initialHardwareId || ""));
  const [hardwareChoices, setHardwareChoices] = useState([]);
  const [loadingHardware, setLoadingHardware] = useState(false);
  const [hardwareError, setHardwareError] = useState("");
  const [localError, setLocalError] = useState("");
  const [interfaceAssignment, setInterfaceAssignment] = useState(null);
  const [pendingInterface, setPendingInterface] = useState(null);
  const [showCreateSelector, setShowCreateSelector] = useState(false);

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
    if (!editing && values.asset_type === "SOFTWARE") {
      if (!hardwareAssetId || !hardwareChoices.some(
        (item) => item.id === Number(hardwareAssetId)
      )) {
        setLocalError("Selecciona un hardware activo donde instalar el software.");
        return;
      }
      payload.hardware_asset_id = Number(hardwareAssetId);
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
          <div className="assets-form-grid">
            <div className="assets-field assets-full-row">
              <label htmlFor="software-type">Tipo de software *</label>
              <select id="software-type" required value={values.software.software_type}
                onChange={(event) => changeSoftware("software_type", event.target.value)}>
                <option value="FIRMWARE">Firmware</option>
                <option value="OS">Sistema operativo</option>
                <option value="APPLICATION">Aplicación</option>
              </select>
            </div>
            <div className="assets-field">
              <label htmlFor="software-manufacturer">Fabricante</label>
              <input id="software-manufacturer" maxLength={200}
                value={values.software.manufacturer}
                onChange={(event) => changeSoftware("manufacturer", event.target.value)}
                placeholder="Ej. Siemens, Advantech" />
            </div>
            <div className="assets-field">
              <label htmlFor="software-product">Producto *</label>
              <input id="software-product" required maxLength={200}
                value={values.software.product}
                onChange={(event) => changeSoftware("product", event.target.value)}
                placeholder="Ej. TIA Portal, Firmware ADAM" />
            </div>
            <div className="assets-field assets-full-row">
              <label htmlFor="software-version">Versión</label>
              <input id="software-version" maxLength={100}
                value={values.software.version}
                onChange={(event) => changeSoftware("version", event.target.value)}
                placeholder="Opcional / desconocida" />
            </div>
          </div>
          <p className="interface-hint">
            El software se registra como activo independiente. Su instalación en
            uno o varios hardware se gestionará en el siguiente incremento.
          </p>
        </div>
      )}

      {values.asset_type === "SOFTWARE" && !editing && (
        <div className="assets-form-section">
          <h2>Hardware donde se instalará *</h2>
          <p className="interface-hint">
            El software debe registrarse con una primera instalación en un hardware
            activo. Podrás asociarlo a otros dispositivos más adelante.
          </p>
          <div className="assets-field">
            <label htmlFor="software-hardware">Hardware de destino *</label>
            <select id="software-hardware" required disabled={loadingHardware || saving}
              value={hardwareAssetId}
              onChange={(event) => setHardwareAssetId(event.target.value)}>
              <option value="">Selecciona un hardware del inventario</option>
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
              <small>No hay hardware disponible. Registra un hardware primero.</small>
            )}
          </div>
        </div>
      )}

      {editing && values.asset_type === "HARDWARE" && (
        <AssetSoftwareSection asset={asset} user={user} embedded />
      )}

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
        <Link className="button-link" to={editing ? "/assets/" + asset.id : "/assets"}>
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
