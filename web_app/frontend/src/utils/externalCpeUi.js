/** View-only helpers for worker-verified NVD UUIDs. No association is created here. */
export const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function normalizedCpeUuid(value) {
  const trimmed = String(value || "").trim();
  return UUID_PATTERN.test(trimmed) ? trimmed.toLowerCase() : "";
}

export function externalCpeStatus(run) {
  if (!run) return "";
  if (run.status === "QUEUED") return "En cola";
  if (run.status === "RUNNING") return "Consultando NVD";
  if (run.status === "FAILED") return "Error de verificación";
  const key = run.verification_status;
  return ({
    VERIFIED: "Verificado en NVD", NOT_FOUND: "No encontrado en NVD",
    INCOMPATIBLE_PART: "Tipo CPE incompatible",
    INVALID_RESPONSE: "Respuesta NVD inválida",
  })[key] || "Sin resultado verificable";
}

export function externalCpeEvidence(run) {
  if (!run || run.status !== "COMPLETED") return null;
  if (run.verification_status === "VERIFIED")
    return (run.candidates || [])[0] || null;
  if (run.verification_status === "INCOMPATIBLE_PART")
    return run.queries?.[0]?.official_cpe || null;
  return null;
}

export function canReviewExternalCpe(run, allowed) {
  return Boolean(allowed && run?.status === "COMPLETED" &&
    run.verification_status === "VERIFIED" &&
    run.identity_is_current && (run.candidates || []).length > 0);
}

export function additionalNvdReferences(references) {
  // Product links use the shared CpeReferences display. Preserve other
  // official NVD links without following unsafe/unverified URL schemes.
  if (!Array.isArray(references)) return [];
  return references.filter(item =>
    item && typeof item.type === "string" &&
    item.type.trim().toLowerCase() !== "product" &&
    typeof item.url === "string"
  );
}

export function externalCpeAssociation(associations, candidate) {
  if (!candidate?.cpe_name_id) return null;
  return (associations || []).find(item =>
    String(item.cpe_name_id).toLowerCase() ===
    String(candidate.cpe_name_id).toLowerCase()
  ) || null;
}
