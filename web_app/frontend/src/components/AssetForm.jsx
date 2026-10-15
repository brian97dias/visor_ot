import { useState } from "react";
import { Link } from "react-router-dom";
import InterfaceSelector from "./InterfaceSelector";
import AssetInterfacesSection from "./AssetInterfacesSection";

import {
  canEditAssetCriticality,
  CRITICALITY_LABELS,
  ROLE_LABELS,
} from "../utils/assetPermissions";

function initialValues(asset) {
  return {
    name: asset?.name || "",
    description: asset?.description || "",
    asset_type: "HARDWARE",
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
  };
}

function buildPayload(values, original, editing, canEditCriticality) {
  const data = {
    name: values.name.trim(),
    description: values.description.trim(),
    criticality: values.criticality,
    impact: values.impact.trim(),
    replacement_cost: values.replacement_cost === "" ? null : values.replacement_cost,
    replacement_currency: values.replacement_currency,
    hardware: { ...values.hardware },
  };

  if (!editing) return { ...data, asset_type: "HARDWARE" };

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

  const hardwareChanges = {};
  for (const [field, value] of Object.entries(data.hardware)) {
    if (value !== original.hardware?.[field]) hardwareChanges[field] = value;
  }
  if (Object.keys(hardwareChanges).length) {
    differences.hardware = hardwareChanges;
  }
  return differences;
}

function AssetForm({ asset = null, user, onSave, saving, error }) {
  const editing = Boolean(asset);
  const canEditCriticality = canEditAssetCriticality(user);
  const [values, setValues] = useState(() => initialValues(asset));
  const [localError, setLocalError] = useState("");
  const [interfaceAssignment, setInterfaceAssignment] = useState(null);
  const [showCreateSelector, setShowCreateSelector] = useState(false);

  function change(field, value) {
    setValues((current) => ({ ...current, [field]: value }));
  }

  function changeHardware(field, value) {
    setValues((current) => ({
      ...current,
      hardware: { ...current.hardware, [field]: value },
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
    if (!editing && interfaceAssignment) {
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
            <span className="assets-type-choice selected">Hardware</span>
            <span className="assets-type-choice unavailable" title="No disponible en esta versión">Software (próximamente)</span>
          </div>
        </div>
      </div>

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
          <>
            <p className="interface-hint">
              Opcional. Si no seleccionas ninguna interfaz, el hardware se registrará sin asociación.
            </p>
            <button type="button" className="button-secondary" disabled={saving}
              onClick={() => {
                setShowCreateSelector((current) => !current);
                setInterfaceAssignment(null);
              }}>
              {showCreateSelector ? "Cerrar selector" : "Asociar interfaz"}
            </button>
            {showCreateSelector && (
              <InterfaceSelector value={interfaceAssignment}
                onChange={setInterfaceAssignment} disabled={saving} />
            )}
          </>
        </div>
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
