/** Pure payload builder; the backend validates and installs atomically. */
export function validateNewSoftware(data, hardwareId) {
  if (!Number.isInteger(Number(hardwareId)) || Number(hardwareId) < 1) {
    return "Selecciona un hardware activo.";
  }
  if (!data.name.trim() || !data.software.product.trim()) {
    return "Indica el nombre del activo y el producto del software.";
  }
  if (data.replacement_cost !== "" && !data.replacement_currency) {
    return "Selecciona la moneda del costo de reposición.";
  }
  if (data.replacement_cost === "" && data.replacement_currency) {
    return "Indica un costo de reposición o deja la moneda sin seleccionar.";
  }
  return null;
}

export function buildInstalledSoftwarePayload(data, hardwareId) {
  return {
    name: data.name.trim(),
    description: data.description.trim(),
    asset_type: "SOFTWARE",
    criticality: data.criticality,
    impact: data.impact.trim(),
    replacement_cost: data.replacement_cost === "" ? null : data.replacement_cost,
    replacement_currency: data.replacement_currency,
    hardware_asset_id: Number(hardwareId),
    software: Object.fromEntries(
      Object.entries(data.software).map(([key, value]) => [key, value.trim()])
    ),
  };
}
