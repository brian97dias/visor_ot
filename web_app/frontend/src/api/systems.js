import { authenticatedFetch } from "./client";

async function requestSystem(path, options) {
  const response = await authenticatedFetch(path, options);
  if (response.status === 204 && response.ok) return null;
  let data;
  try { data = await response.json(); }
  catch { throw new Error("El servidor devolvió una respuesta inválida."); }
  if (!response.ok) {
    const fields = data && typeof data === "object"
      ? Object.entries(data).map(([key, value]) => {
        const values = Array.isArray(value) ? value : [value];
        return key + ": " + values.map(x => typeof x === "string" ? x : JSON.stringify(x)).join(", ");
      }).join(" | ") : "";
    throw new Error(fields || "No se pudo completar la operación de sistemas.");
  }
  return data;
}

export async function getSystems(status = "ACTIVE") {
  const data = await requestSystem("/api/assets/systems/?status=" + encodeURIComponent(status));
  return data.systems;
}
export function getSystem(id) { return requestSystem("/api/assets/systems/" + id + "/"); }
export function createSystem(payload) {
  return requestSystem("/api/assets/systems/", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}
export function updateSystem(id, payload) {
  return requestSystem("/api/assets/systems/" + id + "/", {
    method: "PATCH", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}
export function archiveSystem(id) {
  return requestSystem("/api/assets/systems/" + id + "/archive/", { method: "POST" });
}
export function restoreSystem(id) {
  return requestSystem("/api/assets/systems/" + id + "/restore/", { method: "POST" });
}

/** Current associations and historical unlink audit on a system. */
export function getSystemHardware(id) {
  return requestSystem("/api/assets/systems/" + id + "/hardware/");
}
export function addHardwareToSystem(id, hardwareAssetId) {
  return requestSystem("/api/assets/systems/" + id + "/hardware/", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ hardware_asset_id: hardwareAssetId }),
  });
}
export function unlinkHardwareFromSystem(id, membershipId) {
  return requestSystem("/api/assets/systems/" + id + "/hardware/" + membershipId + "/", {
    method: "DELETE",
  });
}
export function getHardwareSystems(assetId) {
  return requestSystem("/api/assets/" + assetId + "/systems/");
}
export function addSystemToHardware(assetId, systemId) {
  return requestSystem("/api/assets/" + assetId + "/systems/", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ system_id: systemId }),
  });
}
export function unlinkSystemFromHardware(assetId, membershipId) {
  return requestSystem("/api/assets/" + assetId + "/systems/" + membershipId + "/", {
    method: "DELETE",
  });
}
