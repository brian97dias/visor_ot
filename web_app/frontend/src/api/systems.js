import { authenticatedFetch } from "./client";

async function requestSystem(path, options) {
  const response = await authenticatedFetch(path, options);
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
