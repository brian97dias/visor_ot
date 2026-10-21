/** Presentation only; never infer catalogue completeness or human validation. */
export const CATALOGUE_VIEWS = [
  { value: "ALL", label: "Todos los productos" },
  { value: "CANDIDATES", label: "Candidatos sugeridos" },
  { value: "EXCLUDED", label: "No sugeridos" },
];
export const CPE_TYPES = [
  { value: "ALL", label: "Todos los tipos" },
  { value: "h", label: "Hardware (h)" },
  { value: "o", label: "Sistema operativo (o)" },
  { value: "a", label: "Aplicación (a)" },
];
const STATUS = {
  COMPLETED: "Completada", QUEUED: "En cola", RUNNING: "En ejecución",
  INCOMPLETE: "Interrumpida", FAILED: "Fallida",
};
export const statusLabel = status => STATUS[status] || "Estado desconocido";
const CLASS = {
  CANDIDATE: "Sugerido para revisión",
  NON_HARDWARE: "Software, no hardware",
  OTHER_VENDOR: "Fabricante diferente",
  OTHER_PRODUCT: "Modelo no relacionado",
};
export const classificationLabel = value => CLASS[value] || "No clasificado";
export function normalizeIdentity(value) {
  return String(value || "").toLowerCase().normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "").replace(/[^a-z0-9]/g, "");
}
export function preferredCatalogueSnapshot(snapshots, manufacturer) {
  if (!Array.isArray(snapshots) || !snapshots.length) return null;
  const vendor = normalizeIdentity(manufacturer);
  const matching = snapshots.find(row => {
    const text = normalizeIdentity(row.parameter);
    return vendor.length >= 3 && row.status === "COMPLETED" &&
      Number(row.stored_products) > 0 && text.includes(vendor);
  });
  return matching?.id ?? snapshots.find(row => row.status === "COMPLETED" &&
    Number(row.stored_products) > 0)?.id ?? snapshots[0].id;
}
export const DEFAULT_FILTERS = {
  view: "ALL", q: "", cpe_type: "ALL", deprecated: "ALL", limit: 25,
};
export function toCatalogueQuery(filters, after) {
  return {
    view: filters.view || "ALL",
    q: (filters.q || "").trim().slice(0, 120),
    cpe_type: filters.cpe_type || "ALL",
    deprecated: filters.deprecated || "ALL",
    limit: Number(filters.limit) || 25,
    after: Number(after) || 0,
  };
}
export function isReviewableCatalogueRow(row, complete, canReview) {
  return Boolean(canReview && complete && row?.cpe_type === "h" && row?.evidence_id > 0);
}
