export function canCreateAssets(user) {
  return user?.role === "ADMIN" || user?.role === "OPERATOR";
}

export function canEditAssets(user) {
  return ["ADMIN", "ANALYST", "OPERATOR"].includes(user?.role);
}

export function canEditAssetCriticality(user) {
  return user?.role === "ADMIN" || user?.role === "OPERATOR";
}

export const CRITICALITY_LABELS = {
  UNDEFINED: "Sin definir",
  LOW: "Baja",
  MEDIUM: "Media",
  HIGH: "Alta",
};

export const ROLE_LABELS = {
  PLC: "PLC",
  RTU: "RTU",
  HMI: "HMI",
  IED: "IED",
  SWITCH: "Switch",
  ROUTER: "Router",
  GATEWAY: "Gateway",
  FIREWALL: "Firewall",
  SERVER: "Servidor",
  WORKSTATION: "Estación de trabajo",
  IO_MODULE: "Módulo de entradas/salidas",
  OTHER: "Otro",
};

export function displayValue(value) {
  return value === null || value === undefined || value === ""
    ? "Sin registrar"
    : value;
}

export function displayCost(asset) {
  if (asset.replacement_cost === null || asset.replacement_cost === "") {
    return "Sin registrar";
  }
  const amount = Number(asset.replacement_cost);
  if (!Number.isFinite(amount)) return "Sin registrar";
  return new Intl.NumberFormat("es-CO", {
    style: "currency",
    currency: asset.replacement_currency || "COP",
    minimumFractionDigits: 0,
    maximumFractionDigits: 2,
  }).format(amount);
}
