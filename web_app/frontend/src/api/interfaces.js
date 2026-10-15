import { authenticatedFetch } from "./client";

function parseError(data, fallback) {
  if (typeof data.detail === "string") return data.detail;
  if (!data || typeof data !== "object") return fallback;
  const lines = Object.entries(data).flatMap(([field, value]) => {
    const entries = Array.isArray(value) ? value : [value];
    return entries.map((entry) => (
      field + ": " + (typeof entry === "string" ? entry : JSON.stringify(entry))
    ));
  });
  return lines.join(" | ") || fallback;
}

async function request(path, options) {
  const response = await authenticatedFetch(path, options);
  let data;
  try { data = await response.json(); } catch {
    throw new Error("El servidor devolvió una respuesta inválida.");
  }
  if (!response.ok) throw new Error(parseError(data, "No fue posible completar la operación."));
  return data;
}

export function getInterfaces({
  page = 1, search = "", identification = "ALL",
  evidence = "ALL", hardwareId = null,
} = {}) {
  const params = new URLSearchParams({
    page: String(page), search, identification, evidence,
  });
  if (hardwareId !== null) params.set("hardware_id", String(hardwareId));
  return request("/api/assets/interfaces/?" + params.toString());
}

export function getInterface(interfaceId, page = 1) {
  return request("/api/assets/interfaces/" + interfaceId + "/?page=" + page);
}

export function createInterface(data) {
  return request("/api/assets/interfaces/", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });
}

export function identifyInterface(interfaceId, assetId) {
  return request("/api/assets/interfaces/" + interfaceId + "/identify/", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ asset_id: assetId }),
  });
}

export function unlinkInterface(interfaceId) {
  return request("/api/assets/interfaces/" + interfaceId + "/unlink/", {
    method: "POST",
  });
}

export function assignAssetInterface(assetId, assignment) {
  return request("/api/assets/" + assetId + "/interfaces/", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(assignment),
  });
}
