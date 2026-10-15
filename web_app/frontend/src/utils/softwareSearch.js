/** Pure software search utilities, independent of React. */
function normalize(value) {
  return String(value ?? "").toLocaleLowerCase("es-CO").replace(/\s+/g, "");
}

export function matchesSoftware(item, query) {
  const name = [
    item.name, item.software?.manufacturer, item.software?.product,
    item.software?.version, item.software?.software_type,
  ].filter(Boolean).join(" ");
  return normalize(name).includes(normalize(query));
}

export function softwareLabel(item) {
  return [item.name, item.software?.product, item.software?.version || "Versión desconocida"]
    .filter(Boolean).join(" · ");
}
