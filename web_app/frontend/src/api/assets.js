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

  if (response.status === 204) return null;

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

export async function getAssets(inventoryStatus = "ACTIVE") {
  const data = await requestAssets(
    "/api/assets/?inventory_status=" + encodeURIComponent(inventoryStatus)
  );
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

export function archiveAsset(assetId) {
  return requestAssets("/api/assets/" + assetId + "/archive/", {
    method: "POST",
  });
}

export function restoreAsset(assetId, systemIds = []) {
  return requestAssets("/api/assets/" + assetId + "/restore/", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ system_ids: systemIds }),
  });
}


export function getInstalledSoftware(hardwareAssetId) {
  return requestAssets("/api/assets/" + hardwareAssetId + "/software-installations/");
}

export function associateExistingSoftware(hardwareAssetId, softwareAssetId) {
  return requestAssets("/api/assets/" + hardwareAssetId + "/software-installations/", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ software_asset_id: softwareAssetId }),
  });
}

export function unlinkInstalledSoftware(hardwareAssetId, installationId) {
  return requestAssets(
    "/api/assets/" + hardwareAssetId + "/software-installations/" + installationId + "/",
    { method: "DELETE" },
  );
}

export function getSoftwareHistory(softwareAssetId) {
  return requestAssets("/api/assets/" + softwareAssetId + "/software-history/");
}


/** Reciprocal Software -> Hardware installation management. */
export function getHardwareForSoftware(softwareAssetId) {
  return requestAssets("/api/assets/" + softwareAssetId + "/hardware-installations/");
}

export function associateHardwareToSoftware(softwareAssetId, hardwareAssetId) {
  return requestAssets("/api/assets/" + softwareAssetId + "/hardware-installations/", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ hardware_asset_id: hardwareAssetId }),
  });
}

export function unlinkHardwareFromSoftware(softwareAssetId, installationId) {
  return requestAssets(
    "/api/assets/" + softwareAssetId + "/hardware-installations/" + installationId + "/",
    { method: "DELETE" },
  );
}


/** Download the full inventory as an XLSX, without writing to the database. */
export async function exportAssetsExcel() {
  const response = await authenticatedFetch("/api/assets/export/excel/");
  if (!response.ok) {
    let message = "No se pudo exportar el inventario.";
    try {
      const data = await response.json();
      message = describeError(data, message);
    } catch {
      // An upstream gateway may send non-JSON error bodies.
    }
    throw new Error(message);
  }
  const payload = await response.blob();
  const filename = response.headers.get("Content-Disposition")
    ?.match(/filename="([^"]+)"/)?.[1] || "Visor_OT_Inventario.xlsx";
  const link = document.createElement("a");
  const url = URL.createObjectURL(payload);
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  // Give the browser time to start transferring the Blob to the download manager.
  window.setTimeout(() => URL.revokeObjectURL(url), 60_000);
}


async function postInventoryFile(path, file, extra = {}) {
  const form = new FormData();
  form.append("file", file);
  for (const [key, value] of Object.entries(extra)) form.append(key, value);
  return requestAssets(path, { method: "POST", body: form });
}
export function previewAssetsExcel(file) {
  return postInventoryFile("/api/assets/import/preview/", file);
}
export function confirmAssetsExcel(file, token, actions) {
  return postInventoryFile("/api/assets/import/confirm/", file, {
    token, actions: JSON.stringify(actions),
  });
}
