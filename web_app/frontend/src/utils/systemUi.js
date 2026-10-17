export const SYSTEM_STATUS_LABELS = { ACTIVE: "Activo", ARCHIVED: "Archivado" };
export const SYSTEM_CRITICALITY_LABELS = {
  UNDEFINED: "Sin definir", LOW: "Baja", MEDIUM: "Media", HIGH: "Alta",
};
export function canManageSystems(user) {
  return user?.role === "ADMIN" || user?.role === "OPERATOR";
}
export function systemFormValues(record = null) {
  return {
    name: record?.name || "",
    description: record?.description || "",
    criticality: record?.criticality || "UNDEFINED",
    criticality_justification: record?.criticality_justification || "",
    impact: record?.impact || "",
  };
}
export function systemPayload(values) {
  return {
    name: values.name.trim(), description: values.description.trim(),
    criticality: values.criticality,
    criticality_justification: values.criticality_justification.trim(),
    impact: values.impact.trim(),
  };
}
export function filterSystems(rows, {search="", criticality="ALL"}={}) {
  const term = search.trim().toLocaleLowerCase();
  return rows.filter(row => (criticality === "ALL" || criticality === row.criticality)
    && (!term || [row.name, row.description].join(" ").toLocaleLowerCase().includes(term)));
}
