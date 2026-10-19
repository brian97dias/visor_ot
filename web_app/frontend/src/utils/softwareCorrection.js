/** Form-level checks for auditable corrections to a software variant. */
export function validateSoftwareCorrection({
  changeType, reason, historyError, history, confirmShared,
}) {
  if (changeType === "UPGRADE") {
    return {
      field: "changeType",
      message: "Para una actualización real, registra otra variante y reasigna el hardware.",
    };
  }
  if (!(reason || "").trim()) {
    return {
      field: "reason",
      message: "Explica el motivo de la corrección técnica.",
    };
  }
  if (historyError) {
    return {
      field: "history",
      message: "No se pudo consultar el historial. Intenta recargar antes de corregir.",
    };
  }
  if (!history) {
    return {
      field: "history",
      message: "Espera mientras consultamos el historial de instalaciones.",
    };
  }
  if (history.active_installation_count > 1 && !confirmShared) {
    return {
      field: "confirmShared",
      message: "Confirma la corrección compartida con los hardware relacionados.",
    };
  }
  return null;
}
