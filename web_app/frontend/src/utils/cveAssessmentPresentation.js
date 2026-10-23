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
    return "Explica el motivo de tu decisión.";
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

/** Phase-3 compact review: select only an actual, current installation. */
export function selectedFirmwareInstallation(data, requestedId) {
  const installed = data?.active_firmware_installations || [];
  if (installed.length === 1) return installed[0];
  if (requestedId === "" || requestedId == null) return null;
  return installed.find(item => item.installation_id === Number(requestedId)) || null;
}

export function proposedFirmwareDecision(data, choice, requestedId, justification,
  inventoryComplete = false) {
  const selected = selectedFirmwareInstallation(data, requestedId);
  return {
    software_installation_id: selected?.installation_id ?? null,
    firmware_verdict: choice || "UNKNOWN",
    inventory_declared_complete: choice === "NOT_MATCH" && inventoryComplete,
    justification,
  };
}

export function experimentalDescription(cveId, original, descriptions = []) {
  const records = Array.isArray(descriptions) ? descriptions : [];
  const translated = records.find(entry =>
    entry && typeof entry.value === "string" && entry.value.trim() &&
    String(entry.lang || "").toLowerCase() === "es"
  );
  const officialEnglish = records.find(entry =>
    entry && typeof entry.value === "string" && entry.value.trim() &&
    String(entry.lang || "").toLowerCase() === "en"
  );
  const source = (officialEnglish?.value || String(original || "")).trim();
  if (translated) {
    return {
      text: translated.value,
      label: "Descripción oficial en español · NVD",
      original: source,
    };
  }
  if (cveId === EXPERIMENT_CVE_ID &&
      /^In certain devices of the Phoenix Contact AXL F BK and IL BK product families/i.test(source)) {
    return {
      text: "En determinados dispositivos de las familias Phoenix Contact AXL F BK e IL BK existe un acceso FTP no documentado, protegido por contraseña, al directorio raíz.",
      label: "Traducción orientativa al español (no oficial de NVD)",
      original: source,
    };
  }
  return { text: source, label: "Descripción original de NVD", original: source };
}

/** Official NVD detail for the selected CVE, not a locally inferred result. */
export function nvdCveDetailUrl(cveId) {
  if (!/^CVE-\d{4}-\d{4,}$/i.test(String(cveId || ""))) return null;
  return "https://nvd.nist.gov/vuln/detail/" + encodeURIComponent(cveId);
}

/** NVD's web search for CVEs by a dictionary CPE name.
 * Query is an external NVD search, never a VISOR OT applicability claim.
 */
export function nvdVulnerabilitiesByCpeUrl(cpeName) {
  if (typeof cpeName !== "string") return null;
  const parts = cpeName.split(":");
  if (parts.length !== 13 || parts[0] !== "cpe" || parts[1] !== "2.3" ||
      !["h", "o", "a"].includes(parts[2]) ||
      parts.slice(3, 6).some(value => !value || value === "*")) return null;
  return "https://nvd.nist.gov/vuln/search/results?" +
    "form_type=Advanced&results_type=overview&isCpeNameSearch=true&query=" +
    encodeURIComponent(cpeName);
}

/** Direct NVD CVE API query for a concrete CPE 2.3 name.
 * NVD matches this name against CVE configurations; the result is not an
 * applicability verdict for the asset in VISOR OT.
 */
export function nvdCvesApiByCpeNameUrl(cpeName) {
  if (typeof cpeName !== "string") return null;
  const parts = cpeName.split(":");
  if (parts.length !== 13 || parts[0] !== "cpe" || parts[1] !== "2.3" ||
      !["h", "o", "a"].includes(parts[2]) ||
      parts.slice(3, 6).some(value => !value || value === "*")) return null;
  // Preserve CPE's ':' and '*' in the visible URL while escaping query
  // delimiters (e.g. '&', '=' and '#') that would alter the API parameters.
  return "https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=" +
    encodeURIComponent(cpeName).replace(/%3A/gi, ":");
}
