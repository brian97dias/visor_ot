/** Inventory state encoded into shareable URLs. */
export function readPositiveInt(value, fallback = 1) {
  if (!/^[1-9]\d*$/.test(String(value ?? ""))) return fallback;
  const n = Number(value);
  return Number.isSafeInteger(n) ? n : fallback;
}
export function updateInventoryParams(params, name, value) {
  const next = new URLSearchParams(params);
  const defaults = { type: "ALL", inventory_status: "ACTIVE", q: "",
    criticality: "ALL", relation: "ALL", page: "1", expanded: "" };
  if (!(name in defaults)) throw new Error("Filtro desconocido");
  const text = String(value ?? "");
  if (!text || text === defaults[name]) next.delete(name); else next.set(name, text);
  if (name === "type") next.delete("relation");
  if (name !== "page" && name !== "expanded") { next.delete("page"); next.delete("expanded"); }
  return next;
}
