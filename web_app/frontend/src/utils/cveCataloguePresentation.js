/** Generic CVE listing: a CPE correlation is not a vulnerability verdict. */
export const CVE_SEVERITY = {
  CRITICAL: "Crítica",
  HIGH: "Alta",
  MEDIUM: "Media",
  LOW: "Baja",
  UNKNOWN: "Sin clasificar",
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
