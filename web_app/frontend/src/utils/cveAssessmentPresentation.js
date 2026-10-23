/** Display helpers for the single experimental NVD configuration 12.
 * UI summaries NEVER authorize an applicability decision; Django is authoritative.
 */
export const EXPERIMENT_CVE_ID = "CVE-2021-33540";
export const EXPERIMENT_HARDWARE_ID = 2;

export const CVE_STATUS = {
  APPLIES: "Aplica a la configuración 12",
  PENDING_REVIEW: "Pendiente de revisión",
  NOT_APPLICABLE: "No aplica a la configuración 12",
};
export const EVIDENCE_STATE = {
  SATISFIED: "Condición satisfecha",
  NOT_SATISFIED: "Condición descartada",
  UNVERIFIED: "Sin verificar",
};
export const VERDICT_LABEL = {
  UNKNOWN: "No puedo verificar el firmware",
  CONFIRMED: "Corresponde al firmware vulnerable",
  NOT_MATCH: "El firmware instalado no corresponde",
};
export const SOURCE_LABEL = {
  INVENTORY: "Información del inventario",
  DOCUMENTATION: "Documentación / inspección técnica",
  SIMULATION: "Evidencia de simulación",
};

export const latestEffectiveStatus = data => {
  const latest = data?.latest_assessment;
  return latest ? (latest.stale ? "PENDING_REVIEW" : latest.effective_status)
    : "PENDING_REVIEW";
};

export const currentCriterionEvidence = (data, type) => {
  const latest = data?.latest_assessment;
  if (latest && !latest.stale) return latest.criteria_evidence?.[type]
    || data.criteria_evidence?.[type] || null;
  return data?.criteria_evidence?.[type] || null;
};

export function submissionGuard(data, form) {
  if (!data) return "Primero hay que cargar las condiciones del CVE.";
  if (!form.justification?.trim())
    return "Describe la evidencia y el motivo de tu decisión.";
  if (form.justification.length > 1000)
    return "La justificación no puede superar 1000 caracteres.";
  if (form.firmware_verdict !== "UNKNOWN" && !form.software_installation_id)
    return "Selecciona una instalación vigente antes de verificar el firmware.";
  const installations = data.active_firmware_installations || [];
  if (form.software_installation_id &&
      !installations.some(entry =>
        entry.installation_id === Number(form.software_installation_id)))
    return "La instalación seleccionada ya no figura como vigente. Actualiza los datos.";
  if (form.inventory_declared_complete && form.firmware_verdict !== "NOT_MATCH")
    return "La declaración de inventario completo solo procede al descartar el criterio.";
  if (form.inventory_declared_complete && installations.length !== 1)
    return "No se puede descartar toda la configuración mientras existan otros firmwares pendientes.";
  return "";
}

export function advisoryOutcome(data, form) {
  if (!data || !form) return "PENDING_REVIEW";
  const installed = (data.active_firmware_installations || []).some(
    row => row.installation_id === Number(form.software_installation_id)
  );
  const versionRestricted = Boolean(Object.keys(
    data.criteria_evidence?.firmware?.version_constraints || {},
  ).length);
  if (data.hardware_cpe_confirmed && installed &&
      form.firmware_verdict === "CONFIRMED" && !versionRestricted) return "APPLIES";
  if (data.hardware_cpe_confirmed && installed &&
      form.firmware_verdict === "NOT_MATCH" && form.inventory_declared_complete &&
      data.active_firmware_installations.length === 1) return "NOT_APPLICABLE";
  return "PENDING_REVIEW";
}

export function cpePartLabel(value) {
  return value === true ? "Criterio vulnerable (NVD)" :
    value === false ? "Condición de plataforma (NVD)" : "Condición NVD";
}

export function versionConstraintsText(bounds) {
  if (!bounds || typeof bounds !== "object") return "";
  return [
    ["versionStartIncluding", "Desde (incluida)"],
    ["versionStartExcluding", "Después de"],
    ["versionEndIncluding", "Hasta (incluida)"],
    ["versionEndExcluding", "Antes de"],
  ].filter(([key]) => bounds[key] !== undefined)
    .map(([key, label]) => label + ": " + bounds[key]).join(" · ");
}

export function localizedTimestamp(value) {
  if (!value) return "Sin fecha";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? "Fecha no disponible"
    : parsed.toLocaleString("es-CO");
}
