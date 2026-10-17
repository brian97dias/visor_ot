/** Reusable URL state helpers for paginated list screens. */
export function readPage(value) {
  if (!/^[1-9]\d*$/.test(String(value ?? ""))) return 1;
  const n = Number(value);
  return Number.isSafeInteger(n) ? n : 1;
}
export function updateListParams(params, name, value, {
  defaultValue = "", pageKey = "page", resetPage = true,
} = {}) {
  const next = new URLSearchParams(params);
  const text = String(value ?? "");
  if (!text || text === String(defaultValue)) next.delete(name);
  else next.set(name, text);
  if (resetPage && name !== pageKey) next.delete(pageKey);
  return next;
}
export function parseAssetIds(raw) {
  const ids = new Set();
  for (const part of String(raw || "").split(",")) {
    const candidate = part.trim();
    if (!/^[1-9]\d*$/.test(candidate)) continue;
    const id = Number(candidate);
    if (Number.isSafeInteger(id)) ids.add(id);
    if (ids.size >= 2) break;
  }
  return [...ids];
}
