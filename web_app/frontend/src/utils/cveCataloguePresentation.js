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
  COMPATIBLE: "Compatible con el criterio",
  EXCLUDED: "Excluido por criterio técnico",
  INDETERMINATE: "Indeterminado",
};
export const CVE_TECHNICAL_FILTER = {
  ATTENTION: "Requieren atención",
  COMPATIBLE: "Compatible",
  INDETERMINATE: "Indeterminado",
  EXCLUDED: "Excluido técnicamente",
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
