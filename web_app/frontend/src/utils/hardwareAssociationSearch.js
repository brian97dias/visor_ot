/** Pure search predicates for selecting existing hardware from a software asset. */
function normalize(value) {
  return String(value ?? "")
    .toLocaleLowerCase("es-CO")
    .normalize("NFD").replace(/[\u0300-\u036f]/g, "")
    .replace(/\s+/g, "");
}

export function matchesHardware(item, query) {
  const text = [
    item.name, item.hardware?.manufacturer, item.hardware?.model,
    item.hardware?.role, item.hardware?.serial_number, item.hardware?.physical_location,
  ].filter(Boolean).join(" ");
  return normalize(text).includes(normalize(query));
}

export function hardwareLabel(item) {
  return [item.name, item.hardware?.manufacturer, item.hardware?.model]
    .filter(Boolean).join(" · ");
}
