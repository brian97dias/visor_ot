/** Never trust URLs in NVD response JSON, including historical stored records. */
export function nvdReferenceUrl(value) {
  if (typeof value !== "string" || !value || value.length > 2048 ||
      value !== value.trim() || /[\x00-\x20\x7f]/.test(value)) return null;
  try {
    const url = new URL(value);
    const host = url.hostname.replace(/\.$/, "").toLowerCase();
    const labels = host.split(".");
    if (url.protocol !== "https:" || url.username || url.password ||
        (url.port && url.port !== "443") ||
        labels.length < 2 || host.length > 253 ||
        /(?:^|\.)(?:localhost|local|internal|test|invalid|example)$/.test(host) ||
        /^\d+\.\d+\.\d+\.\d+$/.test(host) || host.includes(":") ||
        labels.some(x => !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(x) || x.length > 63)) {
      return null;
    }
    return value;
  } catch {
    return null;
  }
}

export function displayNvdReferences(value) {
  if (!Array.isArray(value)) return [];
  const seen = new Set();
  const references = [];
  for (const item of value) {
    if (!item || typeof item !== "object") continue;
    const url = nvdReferenceUrl(item.url);
    if (!url || seen.has(url)) continue;
    const rawType = typeof item.type === "string" && item.type.length <= 60
      ? item.type.trim() : "";
    const type = rawType || "Referencia";
    const group = /advisory|alert|security|patch|vulnerab/i.test(type)
      ? "Aviso de seguridad"
      : /product/i.test(type) ? "Producto" : "Otra referencia";
    references.push({url, type, group});
    seen.add(url);
    if (references.length >= 20) break;
  }
  return references;
}
