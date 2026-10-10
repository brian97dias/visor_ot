import { authenticatedFetch } from "./client";

function describeError(data, fallback) {
  if (typeof data.detail === "string") return data.detail;

  const messages = Object.entries(data)
    .flatMap(([field, value]) => {
      const entries = Array.isArray(value) ? value : [value];
      return entries.map((entry) => {
        if (typeof entry === "string") return field + ": " + entry;
        return field + ": " + JSON.stringify(entry);
      });
    });

  return messages.join(" | ") || fallback;
}

async function requestAssets(path, options) {
  const response = await authenticatedFetch(path, options);
  let data;

  try {
    data = await response.json();
  } catch {
    throw new Error("El servidor devolvió una respuesta inválida.");
  }

  if (!response.ok) {
    throw new Error(describeError(data, "No se pudo completar la solicitud de activos."));
  }
  return data;
}

export async function getAssets() {
  const data = await requestAssets("/api/assets/");
  return data.assets;
}

export function getAsset(assetId) {
  return requestAssets("/api/assets/" + assetId + "/");
}

export function createAsset(payload) {
  return requestAssets("/api/assets/", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

export function updateAsset(assetId, payload) {
  return requestAssets("/api/assets/" + assetId + "/", {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}
