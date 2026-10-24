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
/** Verify an NVD CPE UUID through the existing PostgreSQL/worker queue. */
export function startExternalCpeVerification(assetId, cpeNameId) {
  return request("/api/vulnerabilities/assets/" + assetId + "/cpe-verifications/", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ cpe_name_id: cpeNameId }),
  });
}

export async function listExternalCpeVerifications(assetId) {
  const data = await request("/api/vulnerabilities/assets/" + assetId + "/cpe-verifications/");
  return data.verifications;
}

export async function readExternalCpeVerification(assetId, runId) {
  const data = await request("/api/vulnerabilities/assets/" + assetId +
    "/cpe-verifications/" + runId + "/");
  return data.verification;
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

/** Analyst-triggered bulk enqueue supports both hardware and software. */
export function startBulkCpeSearch(assetIds) {
  return request("/api/vulnerabilities/cpe-searches/bulk/", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ asset_ids: assetIds, scope: "SPECIFIC" }),
  });
}

/** Single assisted configuration-12 assessment; read-only GET makes no NVD call. */
export function getExperimentalCveAssessment() {
  return request("/api/vulnerabilities/assets/2/cve-assessments/CVE-2021-33540/");
}

/** Append a reviewed assessment; never edits CPEs or inventory relationships. */
export function createExperimentalCveAssessment(payload) {
  return request("/api/vulnerabilities/assets/2/cve-assessments/CVE-2021-33540/", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}


// Generic CVE discovery: browser requests only enqueue/read completed jobs.
const CVE_DISCOVERY_BASE = "/api/vulnerabilities/cve-discoveries/";

function cvexQuery(values) {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(values || {})) {
    if (value !== "" && value !== undefined && value !== null) {
      params.set(key, String(value));
    }
  }
  return params.size ? "?" + params.toString() : "";
}

export function listCveCatalogue(filters = {}) {
  return request("/api/vulnerabilities/cves/" + cvexQuery(filters));
}
export async function readCveCatalogue(cveId) {
  const result = await request("/api/vulnerabilities/cves/" +
    encodeURIComponent(cveId) + "/");
  return result.cve;
}
export function listCveHardware(cveId, page = 1, pageSize = 15) {
  return request("/api/vulnerabilities/cves/" + encodeURIComponent(cveId) +
    "/hardware/" + cvexQuery({ page, page_size: pageSize }));
}

export function enqueueCveDiscovery(hardwareIds) {
  return request(CVE_DISCOVERY_BASE, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ hardware_ids: hardwareIds }),
  });
}
export async function readCveDiscoveryRun(runId) {
  const result = await request(CVE_DISCOVERY_BASE + runId + "/");
  return result.run;
}
export function listCveDiscoveryFindings(runId, page = 1, pageSize = 20) {
  return request(CVE_DISCOVERY_BASE + runId + "/findings/" +
    cvexQuery({ page, page_size: pageSize }));
}


// Scoped general CVE assessment. The experimental endpoint remains unchanged.
export function readGeneralCveAssessment(cveId, hardwareId) {
  return request("/api/vulnerabilities/cves/" + encodeURIComponent(cveId) +
    "/hardware/" + hardwareId + "/assessment/");
}
export function createGeneralCveAssessment(cveId, hardwareId, payload) {
  return request("/api/vulnerabilities/cves/" + encodeURIComponent(cveId) +
    "/hardware/" + hardwareId + "/assessment/", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
}


/** Persist a verified SYSTEM correspondence in the existing NVD audit history. */
export function ensureAutomaticCveAssessment(cveId, hardwareId) {
  return request("/api/vulnerabilities/cves/" + encodeURIComponent(cveId) +
    "/hardware/" + hardwareId + "/assessment/automatic/", { method: "POST" });
}
