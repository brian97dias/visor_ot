/** URL-based navigation state for the CPE inventory overview. */
export const CPE_OVERVIEW_PAGE_SIZE = 15;

const defaults = { type: "ALL", status: "ALL", q: "", page: "1" };

export function readCpePage(value) {
  if (!/^[1-9]\d*$/.test(String(value ?? ""))) return 1;
  const number = Number(value);
  return Number.isSafeInteger(number) ? number : 1;
}

export function updateCpeOverviewParams(params, name, value) {
  if (!(name in defaults)) throw new Error("Filtro CPE desconocido");
  const next = new URLSearchParams(params);
  const text = String(value ?? "");
  if (!text || text === defaults[name]) next.delete(name);
  else next.set(name, text);
  if (name !== "page") next.delete("page");
  return next;
}
