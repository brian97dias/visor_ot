/** Generic CVE listing: a CPE correlation is not a vulnerability verdict. */
export const CVE_SEVERITY = {
  CRITICAL: "Crítica",
  HIGH: "Alta",
  MEDIUM: "Media",
  LOW: "Baja",
  UNKNOWN: "Sin clasificar",
};

/** Summary of scoped human assessments, never an automatic NVD verdict. */
export const CVE_EVALUATION_STATE = {
  PENDING_REVIEW: "Por validar",
  IN_REVIEW: "En revisión",
  APPLIES: "Aplica",
  APPLIES_CONDITIONAL: "Aplica condicionada",
  NOT_APPLICABLE: "No aplica",
  STALE: "Revisar evidencia",
};

export const CVE_EVALUATION_HELP = {
  PENDING_REVIEW: "Sin evaluaciones vigentes registradas",
  IN_REVIEW: "Quedan configuraciones o activos por revisar",
  APPLIES: "Existe al menos una correspondencia vigente confirmada",
  APPLIES_CONDITIONAL: "El analista acepta gestionar el CVE con condiciones pendientes",
  NOT_APPLICABLE: "Todas las configuraciones y activos relacionados están descartados",
  STALE: "Cambió la evidencia desde la última evaluación",
};

/** Read-only NVD compatibility; separate from analyst decisions. */
export const CVE_TECHNICAL_STATE = {
  COMPATIBLE: "Coincidencia técnica",
  EXCLUDED: "Condiciones excluidas",
  INDETERMINATE: "Por verificar",
};
export const DEFAULT_CVE_TECHNICAL_FILTER = "ATTENTION";
export const CVE_TECHNICAL_FILTER = {
  ATTENTION: "Requieren atención",
  COMPATIBLE: "Coincidencia técnica",
  INDETERMINATE: "Por verificar",
  EXCLUDED: "Condiciones excluidas",
};

export const CVE_DISCOVERY_STATE = {
  QUEUED: "En cola",
  RUNNING: "Consultando NVD",
  INCOMPLETE: "Reanudación pendiente",
  COMPLETED: "Completada",
  FAILED: "Con error",
};

export function cvePageCount(total, size = 15) {
  return Math.max(1, Math.ceil(Math.max(0, Number(total) || 0) / size));
}

export function cveHardwareCandidates(rows) {
  return (rows || []).filter(row =>
    row.asset_type === "HARDWARE" && Number(row.confirmed_count) > 0
  );
}

export function toggleCveHardwareSelection(selected, hardwareId, maximum = 100) {
  if (selected.includes(hardwareId)) {
    return selected.filter(id => id !== hardwareId);
  }
  return selected.length >= maximum ? selected : [...selected, hardwareId];
}

export function cveHardwareSelectionValid(ids) {
  return Array.isArray(ids) && ids.length > 0 && ids.length <= 100 &&
    ids.every(id => Number.isSafeInteger(id) && id > 0) &&
    new Set(ids).size === ids.length;
}

export function isCveDiscoveryActive(status) {
  return ["QUEUED", "RUNNING", "INCOMPLETE"].includes(status);
}


/** A CVE may be associated with several assets. Open the hardware that
 * explains the row's positive technical result, not simply the lowest ID.
 */
export function preferredCveHardwareId(row) {
  const contexts = Array.isArray(row?.related_assets) ? row.related_assets : [];
  const valid = contexts.filter(item => Number.isSafeInteger(item?.hardware_id) &&
    item.hardware_id > 0);
  const primary = valid.find(item => item.technical_result === "COMPATIBLE") ||
    valid[0];
  return primary?.hardware_id ?? null;
}

/** Honor only hardware IDs actually related to this CVE; never open
 * arbitrary inventory assets from an untrusted URL query parameter.
 */
export function selectedCveHardwareId(hardware, requestedId) {
  const available = Array.isArray(hardware) ? hardware : [];
  const candidate = Number(requestedId);
  const found = requestedId != null && requestedId !== "" &&
    Number.isSafeInteger(candidate) && candidate > 0
    ? available.find(item => Number(item.hardware_id) === candidate)
    : null;
  return String((found || available[0])?.hardware_id || "");
}


/** Human-review progress is a server-computed projection across every NVD
 * alternative for the selected hardware, not a generated analyst decision.
 */
export function cveReviewProgress(summary) {
  if (!summary || !Number.isInteger(summary.total_configurations)) {
    return "Estado de revisión no disponible";
  }
  const total = Math.max(0, summary.total_configurations);
  const reviewed = Math.max(0, Math.min(total,
    Number(summary.reviewed_configurations) || 0));
  return reviewed + " de " + total + " configuraciones con revisión vigente";
}

/** Choose one main NVD evidence item, retaining all other items for audit. */
export function groupCveEvidence(rows) {
  const configs = Array.isArray(rows) ? rows : [];
  const primary = configs.find(row =>
    row.latest_assessment?.effective_status === "APPLIES" &&
    !row.latest_assessment?.stale
  ) || configs.find(row =>
    row.latest_assessment?.effective_status === "APPLIES_CONDITIONAL" &&
    !row.latest_assessment?.stale
  ) || configs.find(row => row.technical_result === "COMPATIBLE")
    || configs[0] || null;
  return { primary, others: configs.filter(row => row !== primary) };
}

/** A human verdict is for the hardware/CVE, not 96 mandatory reviews. */
export function cveHumanReviewMessage(summary) {
  switch (summary?.status) {
    case "APPLIES":
      return "Existe al menos una correspondencia vigente confirmada para este hardware.";
    case "NOT_APPLICABLE":
      return "Todas las alternativas NVD fueron descartadas con evidencia vigente.";
    case "APPLIES_CONDITIONAL":
      return "El analista decidió gestionar el CVE con condiciones pendientes.";
    case "STALE":
      return "La evidencia del inventario o de NVD cambió. Es necesario revisar decisiones anteriores.";
    case "IN_REVIEW":
      return "Existe historial de revisión, pero aún no hay una conclusión definitiva.";
    default:
      return "Todavía no se ha registrado una decisión del analista para este hardware y CVE.";
  }
}


/** Origin of the current CVE/hardware applicability conclusion. */
export const CVE_APPLICABILITY_SOURCE = {
  SYSTEM: "Automático",
  ANALYST: "Validado por analista",
  NONE: "Pendiente de validación",
};


/** Explain product identity separately from verified vulnerable versions. */
export function nvdCriterionIdentityBadge(item) {
  if (item?.technical_identity === "PLATFORM_DISTINCT") {
    return { label: "Plataforma incompatible", state: "NOT_SATISFIED" };
  }
  if (item?.technical_identity === "DISTINCT" &&
      item?.technical_result === "EXCLUDED") {
    return { label: "Plataforma distinta", state: "NOT_SATISFIED" };
  }
  if (["a", "o"].includes(item?.part)) {
    if (item.technical_identity === "MATCHED" && item.technical_matched_cpe) {
      if (item.technical_result === "COMPATIBLE") {
        return { label: "Coincidencia técnica", state: "SATISFIED" };
      }
      if (item.technical_result === "EXCLUDED") {
        return { label: "Versión fuera de rango", state: "NOT_SATISFIED" };
      }
      return { label: "Versión por verificar", state: "UNVERIFIED" };
    }
    return { label: "Producto por verificar", state: "UNVERIFIED" };
  }
  if (item?.technical_identity === "MATCHED" && item.technical_matched_cpe) {
    return { label: "CPE confirmado", state: "SATISFIED" };
  }
  return item?.state === "SATISFIED"
    ? { label: "CPE confirmado", state: "SATISFIED" }
    : { label: "Sin verificar", state: "UNVERIFIED" };
}

/** A saved positive links one installed software to a hardware/CVE.
 * A current human reopening suppresses the previous automatic display.
 * No state is written by projecting the evidence into a checkbox.
 */
export function currentCveSoftwareLink(config, context) {
  if (!config || !context) return null;
  const last = config.latest_assessment;
  const currentPositive = last && !last.stale &&
    ["APPLIES", "APPLIES_CONDITIONAL"].includes(last.effective_status);
  const proof = !last && context.applicability?.source === "SYSTEM" &&
    context.applicability.automatic_evidence?.configuration_index === config.index
    ? context.applicability.automatic_evidence : null;
  const provedInstallation = proof?.criteria?.find(row =>
    row.vulnerable === true && row.software_installation_id)?.software_installation_id;
  const installationId = currentPositive
    ? last.software_installation_id : provedInstallation;
  if (installationId == null) return null;
  const sw = (context.installed_software || []).find(row =>
    Number(row.installation_id) === Number(installationId));
  if (!sw) return null;

  const part = sw.software_type === "APPLICATION" ? "a" :
    ["FIRMWARE", "OS"].includes(sw.software_type) ? "o" : null;
  if (!part) return null;
  const leaves = [];
  function visit(node) {
    if (node?.kind === "CRITERION") {
      if (node.vulnerable === true && node.part === part) leaves.push(node);
    } else {
      for (const child of node?.children || []) visit(child);
    }
  }
  visit(config.tree);
  if (!leaves.length) return null;

  // When present, prefer the NVD criterion actually evaluated for the
  // installed version. A discretionary link may have no proven criterion.
  const evidence = last?.conditional_evidence?.linked_software?.[0];
  const criterion = leaves.find(row =>
    row.technical_software_installation_id != null &&
    Number(row.technical_software_installation_id) === Number(installationId)
  ) || leaves.find(row => evidence?.criteria && row.criteria === evidence.criteria)
    || leaves.find(row => (evidence?.candidate_nvd_criteria || []).includes(row.criteria))
    || leaves[0];

  return {
    installationId: String(installationId),
    criterionKey: criterion.match_criteria_id || criterion.criteria,
    source: currentPositive ? last.source : "SYSTEM",
  };
}

/** Reopening must propose a DIFFERENT state, never reaffirm a verdict. */
export function allowedCveDecisionTransitions(currentStatus) {
  const actions = ["CONFIRMED", "CONDITIONAL", "NOT_MATCH"];
  const already = {
    APPLIES: "CONFIRMED",
    APPLIES_CONDITIONAL: "CONDITIONAL",
    NOT_APPLICABLE: "NOT_MATCH",
  }[currentStatus];
  return already ? actions.filter(action => action !== already) : actions;
}


/** Only hardware-scoped evidence may enter the interactive CVE detail.
 * A historical audit of an unrelated NVD platform is never a candidate.
 * The full configuration list remains available separately for audit/engine.
 */
export function selectCveOperationalGroups(context) {
  const relevant = (context?.relevant_configurations || []).filter(row =>
    row.hardware_scope === "MATCHED" || row.hardware_scope === "UNSCOPED"
  );
  const selectedIndexes = new Set(relevant.map(row => row.index));
  const hardwareSoftware = (context?.hardware_software_configurations || [])
    .filter(row => row.hardware_scope === "MATCHED" &&
      selectedIndexes.has(row.index));
  return {
    reviewPool: hardwareSoftware.length ? hardwareSoftware : relevant,
    hardwareSoftware,
    independentConfigs: hardwareSoftware.length ? relevant.filter(row =>
      row.hardware_scope === "UNSCOPED" &&
      !hardwareSoftware.some(hw => hw.index === row.index)
    ) : [],
  };
}


/** Installation USED to evaluate a negative CVE conclusion.
 * This is evidence, not a positive vulnerability/CVE association. It does not
 * turn NOT_APPLICABLE into an affected-software hardening finding.
 */
export function currentCveEvaluatedSoftware(config, context) {
  if (!config || !context) return null;
  const last = config.latest_assessment;
  if (last?.stale || (last && last.effective_status !== "NOT_APPLICABLE")) {
    return null;
  }
  if (last && last.source !== "SYSTEM" && last.source !== "ANALYST") return null;
  if (!last && config.technical_result !== "EXCLUDED") return null;
  const candidates = last?.evaluated_software?.length
    ? last.evaluated_software : (last?.source === "ANALYST" ? [] :
      config.evaluated_software || []);
  const proof = candidates.find(item =>
    (context.installed_software || []).some(sw =>
      Number(sw.installation_id) === Number(item.software_installation_id))
  );
  if (!proof) return null;
  const all = [];
  function walk(node) {
    if (node?.kind === "CRITERION" && node.vulnerable === true &&
        ["a", "o"].includes(node.part)) all.push(node);
    for (const child of node?.children || []) walk(child);
  }
  walk(config.tree);
  const criterion = all.find(item => item.criteria === proof.criterion) ||
    all.find(item => Number(item.technical_software_installation_id) ===
      Number(proof.software_installation_id));
  if (!criterion) return null;
  return {
    installationId: String(proof.software_installation_id),
    criterionKey: criterion.match_criteria_id || criterion.criteria,
    source: last?.source || "SYSTEM",
    evidenceOnly: true,
  };
}


/** The persisted association is to an installation, not a display-only
 * NVD criterion. Switching between OR criteria for that SAME installation
 * must not manufacture an A -> A audit decision.
 */
export function isSavedCveLinkSelection(saved, criterionKey, installationId) {
  return Boolean(saved) && Boolean(criterionKey) &&
    saved.installationId === String(installationId);
}

/** Normalize legacy audit wording visually, without rewriting stored history. */
export function cveAuditJustification(justification, source) {
  const text = String(justification || "");
  return source === "SYSTEM"
    ? text.replace(/^VISOR OT confirmó automáticamente/, "El sistema confirmó automáticamente")
    : text;
}

/** Three summary buckets; stale/in-progress audits remain pending, not safe. */
export function displayCveApplicability(status) {
  return ["APPLIES", "APPLIES_CONDITIONAL", "NOT_APPLICABLE"].includes(status)
    ? status : "PENDING_REVIEW";
}
export const CVE_CATALOGUE_FILTER_STATES = {
  PENDING_REVIEW: "Por validar",
  APPLIES: "Aplica",
  APPLIES_CONDITIONAL: "Aplica condicionada",
  NOT_APPLICABLE: "No aplica",
};


/** Keep full NVD tree for evaluation, surface confirmed OR candidates first. */
export function relevantNvdChildren(node) {
  const children = Array.isArray(node?.children) ? node.children : [];
  if (node?.operator !== "OR" || children.length < 2) {
    return { visible: children, alternatives: [] };
  }
  const matched = item => item?.kind === "CRITERION" ?
    item.technical_identity === "MATCHED" && Boolean(item.technical_matched_cpe) :
    (item?.children || []).some(matched);
  const visible = children.filter(matched);
  return visible.length ? {
    visible, alternatives: children.filter(child => !matched(child)),
  } : {visible: children.slice(0, 1), alternatives: children.slice(1)};
}
/** Presentation-only selection of an OR branch.
 * Keep every NVD alternative accessible; never change technical evaluation.
 */
export function displayNvdGroupBranches(node, selectedCriterion = "") {
  const { visible, alternatives } = relevantNvdChildren(node);
  if (node?.operator !== "OR") return { shown: visible, hidden: [] };
  const ordered = [...visible, ...alternatives];
  const hasSelected = branch => branch?.kind === "CRITERION"
    ? (branch.match_criteria_id || branch.criteria) === selectedCriterion
    : (branch?.children || []).some(hasSelected);
  const focused = ordered.find(hasSelected) || visible[0] || ordered[0];
  return {
    shown: focused ? [focused] : [],
    hidden: ordered.filter(branch => branch !== focused),
  };
}

/** Labels describe NVD criteria, not assets proven to be affected. */
export function nvdAlternativeGroupLabel(branches) {
  const kinds = new Set();
  const inspect = node => {
    if (node?.kind === "CRITERION") {
      kinds.add(node.part === "h" ? "hardware" :
        ["a", "o"].includes(node.part) ? "software" : "otro");
    }
    for (const child of node?.children || []) inspect(child);
  };
  (branches || []).forEach(inspect);
  return kinds.size === 1 && kinds.has("hardware")
    ? "Otras alternativas de hardware NVD"
    : kinds.size === 1 && kinds.has("software")
      ? "Otras alternativas de software NVD" : "Otras alternativas NVD";
}

export const cveAssetRoleLabel = role =>
  role === "PLATFORM" ? "Plataforma" :
  role === "VULNERABLE" ? "Vulnerable" : "Relacionado";
