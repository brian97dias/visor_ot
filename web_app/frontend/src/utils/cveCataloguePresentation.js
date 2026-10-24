/** Generic CVE listing: a CPE correlation is not a vulnerability verdict. */
export const CVE_SEVERITY = {
  CRITICAL: "Crítica",
  HIGH: "Alta",
  MEDIUM: "Media",
  LOW: "Baja",
  UNKNOWN: "Sin clasificar",
};

/** Summary of scoped human assessments, never an automatic NVD verdict. */
export const CVE_EVALUATION_STATE = {
  PENDING_REVIEW: "Por validar",
  IN_REVIEW: "En revisión",
  APPLIES: "Aplica",
  NOT_APPLICABLE: "No aplica",
  STALE: "Revisar evidencia",
};

export const CVE_EVALUATION_HELP = {
  PENDING_REVIEW: "Sin evaluaciones vigentes registradas",
  IN_REVIEW: "Quedan configuraciones o activos por revisar",
  APPLIES: "Existe al menos una correspondencia vigente confirmada",
  NOT_APPLICABLE: "Todas las configuraciones y activos relacionados están descartados",
  STALE: "Cambió la evidencia desde la última evaluación",
};

/** Read-only NVD compatibility; separate from analyst decisions. */
export const CVE_TECHNICAL_STATE = {
  COMPATIBLE: "Coincidencia técnica",
  EXCLUDED: "Condiciones excluidas",
  INDETERMINATE: "Por verificar",
};
export const DEFAULT_CVE_TECHNICAL_FILTER = "ATTENTION";
export const CVE_TECHNICAL_FILTER = {
  ATTENTION: "Requieren atención",
  COMPATIBLE: "Coincidencia técnica",
  INDETERMINATE: "Por verificar",
  EXCLUDED: "Condiciones excluidas",
};

export const CVE_DISCOVERY_STATE = {
  QUEUED: "En cola",
  RUNNING: "Consultando NVD",
  INCOMPLETE: "Reanudación pendiente",
  COMPLETED: "Completada",
  FAILED: "Con error",
};

export function cvePageCount(total, size = 15) {
  return Math.max(1, Math.ceil(Math.max(0, Number(total) || 0) / size));
}

export function cveHardwareCandidates(rows) {
  return (rows || []).filter(row =>
    row.asset_type === "HARDWARE" && Number(row.confirmed_count) > 0
  );
}

export function toggleCveHardwareSelection(selected, hardwareId, maximum = 100) {
  if (selected.includes(hardwareId)) {
    return selected.filter(id => id !== hardwareId);
  }
  return selected.length >= maximum ? selected : [...selected, hardwareId];
}

export function cveHardwareSelectionValid(ids) {
  return Array.isArray(ids) && ids.length > 0 && ids.length <= 100 &&
    ids.every(id => Number.isSafeInteger(id) && id > 0) &&
    new Set(ids).size === ids.length;
}

export function isCveDiscoveryActive(status) {
  return ["QUEUED", "RUNNING", "INCOMPLETE"].includes(status);
}


/** A CVE may be associated with several assets. Open the hardware that
 * explains the row's positive technical result, not simply the lowest ID.
 */
export function preferredCveHardwareId(row) {
  const contexts = Array.isArray(row?.related_assets) ? row.related_assets : [];
  const valid = contexts.filter(item => Number.isSafeInteger(item?.hardware_id) &&
    item.hardware_id > 0);
  const primary = valid.find(item => item.technical_result === "COMPATIBLE") ||
    valid[0];
  return primary?.hardware_id ?? null;
}

/** Honor only hardware IDs actually related to this CVE; never open
 * arbitrary inventory assets from an untrusted URL query parameter.
 */
export function selectedCveHardwareId(hardware, requestedId) {
  const available = Array.isArray(hardware) ? hardware : [];
  const candidate = Number(requestedId);
  const found = requestedId != null && requestedId !== "" &&
    Number.isSafeInteger(candidate) && candidate > 0
    ? available.find(item => Number(item.hardware_id) === candidate)
    : null;
  return String((found || available[0])?.hardware_id || "");
}


/** Human-review progress is a server-computed projection across every NVD
 * alternative for the selected hardware, not a generated analyst decision.
 */
export function cveReviewProgress(summary) {
  if (!summary || !Number.isInteger(summary.total_configurations)) {
    return "Estado de revisión no disponible";
  }
  const total = Math.max(0, summary.total_configurations);
  const reviewed = Math.max(0, Math.min(total,
    Number(summary.reviewed_configurations) || 0));
  return reviewed + " de " + total + " configuraciones con revisión vigente";
}

/** Choose one main NVD evidence item, retaining all other items for audit. */
export function groupCveEvidence(rows) {
  const configs = Array.isArray(rows) ? rows : [];
  const primary = configs.find(row =>
    row.latest_assessment?.effective_status === "APPLIES" &&
    !row.latest_assessment?.stale
  ) || configs.find(row => row.technical_result === "COMPATIBLE")
    || configs[0] || null;
  return { primary, others: configs.filter(row => row !== primary) };
}

/** A human verdict is for the hardware/CVE, not 96 mandatory reviews. */
export function cveHumanReviewMessage(summary) {
  switch (summary?.status) {
    case "APPLIES":
      return "Existe al menos una correspondencia vigente confirmada para este hardware.";
    case "NOT_APPLICABLE":
      return "Todas las alternativas NVD fueron descartadas con evidencia vigente.";
    case "STALE":
      return "La evidencia del inventario o de NVD cambió. Es necesario revisar decisiones anteriores.";
    case "IN_REVIEW":
      return "Existe historial de revisión, pero aún no hay una conclusión definitiva.";
    default:
      return "Todavía no se ha registrado una decisión del analista para este hardware y CVE.";
  }
}


/** Origin of the current CVE/hardware applicability conclusion. */
export const CVE_APPLICABILITY_SOURCE = {
  SYSTEM: "Automático · VISOR OT",
  ANALYST: "Validado por analista",
  NONE: "Pendiente de validación",
};
