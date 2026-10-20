import { authenticatedFetch } from "./client";

async function request(path, options) {
  const response = await authenticatedFetch(path, options);
  let body;
  try { body = await response.json(); }
  catch { throw new Error("Respuesta inválida del servicio CPE."); }
  if (!response.ok) {
    const detail = Object.values(body || {})[0];
    throw new Error(Array.isArray(detail) ? detail.join(", ") :
      typeof detail === "string" ? detail : JSON.stringify(detail || body));
  }
  return body;
}

export function startCpeSearch(id, scope = "SPECIFIC") {
  return request("/api/vulnerabilities/assets/" + id + "/cpe-searches/", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ scope }),
  });
}
export function startAdvancedCpeSearch(id, payload) {
  return request("/api/vulnerabilities/assets/" + id + "/cpe-searches/advanced/", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}
export async function latestCpeSearch(id) {
  const data = await request("/api/vulnerabilities/assets/" + id + "/cpe-searches/latest/");
  return data.run;
}
export async function readCpeSearch(id, runId) {
  const data = await request("/api/vulnerabilities/assets/" + id + "/cpe-searches/" + runId + "/");
  return data.run;
}

/** Single read-only overview, avoids one request per inventory asset. */
export async function getCpeOverview() {
  const data = await request("/api/vulnerabilities/cpe-overview/");
  return data.results;
}


/** Analyst-created CPE decisions; no automatic confirmation. */
export async function getAssetCpeAssociations(id) {
  const data = await request("/api/vulnerabilities/assets/" + id + "/cpes/");
  return data.associations;
}

export async function createAssetCpeAssociation(id, payload) {
  return request("/api/vulnerabilities/assets/" + id + "/cpes/", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

export async function updateAssetCpeAssociation(id, associationId, payload) {
  return request("/api/vulnerabilities/assets/" + id + "/cpes/" + associationId + "/", {
    method: "PATCH", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

/** Bulk enqueue is specific-only; software is explicitly reported, never queued yet. */
export function startBulkCpeSearch(assetIds) {
  return request("/api/vulnerabilities/cpe-searches/bulk/", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ asset_ids: assetIds, scope: "SPECIFIC" }),
  });
}
