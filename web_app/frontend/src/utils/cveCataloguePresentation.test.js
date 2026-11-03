import test from "node:test";
import assert from "node:assert/strict";
import {
  CVE_SEVERITY, CVE_DISCOVERY_STATE, CVE_EVALUATION_STATE,
  CVE_EVALUATION_HELP, CVE_TECHNICAL_STATE, CVE_TECHNICAL_FILTER,
  CVE_APPLICABILITY_SOURCE,
  DEFAULT_CVE_TECHNICAL_FILTER,
  cvePageCount,
  cveHardwareCandidates, toggleCveHardwareSelection,
  cveHardwareSelectionValid, isCveDiscoveryActive,
  preferredCveHardwareId, selectedCveHardwareId, cveEvaluationDetailUrl,
  cveReviewProgress,
  groupCveEvidence, selectCveOperationalGroups, cveHumanReviewMessage,
  cveApplicabilityExplanation, cveConfigurationHighlights,
  CVE_CONTEXTUAL_SCOPE, cveContextualScopeSummary,
  cveScopeCriterionLabels, cveHardwareApplicabilityLabel,
  canConfirmCveWithExternalEvidence,
  relevantNvdChildren, displayNvdGroupBranches, operationalNvdGroupBranches,
  displayedNvdSoftwareCriterion, canSelectNvdCriterionSoftware,
  nvdAlternativeGroupLabel,
  currentCveSoftwareLink, currentCveEvaluatedSoftware,
  currentCveScopedEvaluatedSoftware,
  allowedCveDecisionTransitions, isSavedCveLinkSelection,
  preferredCveCorrespondenceVerdict, updatedCveReviewChoice,
  cveHistoryDecisionDescription, cveHistorySoftwareLabel,
  cveAssetRoleLabel,
  displayCveApplicability, CVE_CATALOGUE_FILTER_STATES,
  nvdCriterionIdentityBadge, cveAuditJustification,
} from "./cveCataloguePresentation.js";

test("nested NVD hardware OR shows only confirmed CPU without dropping software OR", () => {
  const hardware = model => ({
    kind: "CRITERION", part: "h",
    criteria: "cpe:2.3:h:siemens:simatic_s7-1200_cpu_" + model + ":-:*:*:*:*:*:*:*",
    technical_identity: model === "1215c" ? "MATCHED" : "DISTINCT",
    technical_matched_cpe: model === "1215c" ? "cpe:verified:cpu1215c" : null,
  });
  const seventy = ["1212c", "1214fc", "1215c", ...Array.from(
    {length: 67}, (_, i) => "other" + i,
  )].map(hardware);
  const direct = {kind:"GROUP",operator:"OR",children:seventy};
  assert.deepEqual(
    operationalNvdGroupBranches(direct).shown.map(row => row.criteria),
    [seventy[2].criteria],
  );
  assert.equal(operationalNvdGroupBranches(direct).hidden.length, 0);
  const wrapped = {kind:"GROUP",operator:"OR",children:seventy.map(row => ({
    kind:"GROUP", operator:"OR", children:[row],
  }))};
  assert.equal(operationalNvdGroupBranches(wrapped).shown.length, 1);
  assert.deepEqual(operationalNvdGroupBranches(wrapped).hidden, []);
  const software = {kind:"GROUP",operator:"OR",children:[
    {kind:"CRITERION",part:"a",criteria:"cpe:simatic_step7"},
    {kind:"CRITERION",part:"a",criteria:"cpe:step7_v17"},
  ]};
  assert.equal(operationalNvdGroupBranches(software).hidden.length, 1);
});

test("compact applicability text distinguishes technical and human conclusions", () => {
  const summary = (status, source, counts) => cveApplicabilityExplanation({
    applicability: {status, source},
    technical_configuration_counts: counts,
  });
  assert.match(summary("APPLIES", "SYSTEM"), /CPE/);
  assert.match(summary("NOT_APPLICABLE", "SYSTEM"), /descartadas/);
  assert.match(summary("NOT_APPLICABLE", "ANALYST"), /analista/);
  assert.match(summary("APPLIES_CONDITIONAL", "ANALYST"), /correspondencia parcial/);
  assert.match(summary("IN_REVIEW", "NONE"), /reabierta/);
  assert.match(summary("STALE", "NONE"), /inventario cambió/);
  assert.match(summary("PENDING_REVIEW", "NONE", {
    EXCLUDED: 19, INDETERMINATE: 29,
  }), /19 configuración\(es\).*29 alternativa\(s\)/);
  assert.match(summary("PENDING_REVIEW", "NONE", {
    EXCLUDED: 0, INDETERMINATE: 2,
  }), /no existe evidencia suficiente/);
});

test("scope summary preserves all original NVD branches and distinguishes 2019-10943", () => {
  const make = (index, relation, technical_result, criteria) => ({
    index, position: index + 1, technical_result, contextual_scope: relation,
    tree: {kind: "GROUP", children: [{kind: "CRITERION", part: "h", criteria}]},
  });
  const branches = Array.from({length: 11}, (_, index) => make(
    index, index === 5 ? "PERTINENT" : index === 10 ? "OUT_OF_SCOPE" : "FOREIGN",
    index === 5 ? "EXCLUDED" : index === 10 ? "INDETERMINATE" : "EXCLUDED",
    "cpe:2.3:h:siemens:simatic_s7-1200_cpu_1215c:-:*:*:*:*:*:*:*",
  ));
  const originals = JSON.parse(JSON.stringify(branches));
  const context = {
    configurations: branches,
    nvd_technical_result: "INDETERMINATE",
    technical_result: "EXCLUDED",
    contextual_selection: {
      pertinent_indexes: [5],
      foreign_indexes: [0, 1, 2, 3, 4, 6, 7, 8, 9],
      uncertain_indexes: [],
      out_of_scope_indexes: [10],
      evaluated_indexes: [5],
      configurations: branches.map(({index, position, technical_result, contextual_scope}) =>
        ({index, position, technical_result, relation: contextual_scope,
          reason: "Motivo técnico registrado"})),
    },
    applicability: {status: "NOT_APPLICABLE", source: "SYSTEM",
      automatic_evidence: {proof_scope: "NVD_HARDWARE_CONTEXT",
        evaluated_configuration_indexes: [5]}},
  };
  const summary = cveContextualScopeSummary(context);
  assert.equal(summary.total, 11);
  assert.equal(summary.pertinentCount, 1);
  assert.equal(summary.foreignCount, 9);
  assert.equal(summary.outOfScopeCount, 1);
  assert.equal(summary.uncertainCount, 0);
  assert.deepEqual(summary.evaluatedIndexes, [5]);
  assert.equal(summary.groups[0].entries[0].position, 6);
  assert.equal(summary.groups[2].entries[0].position, 11);
  assert.equal(summary.rawResult, "INDETERMINATE");
  assert.equal(summary.contextualResult, "EXCLUDED");
  assert.equal(summary.proof.proof_scope, "NVD_HARDWARE_CONTEXT");
  assert.deepEqual(branches, originals);
  assert.match(cveApplicabilityExplanation(context), /La configuración NVD pertinente quedó excluida/);
  assert.match(cveApplicabilityExplanation(context), /no demuestra ausencia/);
  assert.equal(CVE_CONTEXTUAL_SCOPE.OUT_OF_SCOPE.label, "Software sin anclaje");
});

test("scope facts show distinct platforms but never assert software absence", () => {
  const scope = cveContextualScopeSummary({
    contextual_selection: {configurations: [
      {index: 0, position: 1, relation: "FOREIGN", technical_result: "EXCLUDED"},
      {index: 1, position: 2, relation: "UNCERTAIN",
        technical_result: "INDETERMINATE"},
      {index: 2, position: 3, relation: "OUT_OF_SCOPE",
        technical_result: "INDETERMINATE"},
    ]},
  });
  assert.equal(scope.foreignCount, 1);
  assert.equal(scope.uncertainCount, 1);
  assert.equal(scope.outOfScopeCount, 1);
  assert.match(CVE_CONTEXTUAL_SCOPE.OUT_OF_SCOPE.note, /No se afirma/);
  assert.match(cveApplicabilityExplanation({
    applicability: {status: "PENDING_REVIEW", source: "NONE"},
    contextual_selection: {configurations: [
      {index: 0, relation: "FOREIGN"},
    ]},
  }), /No se ha acreditado ninguna/);
  assert.equal(cveContextualScopeSummary({}), null);
});

test("manual vendor advisory override is available only for excluded matched hardware", () => {
  const config = {
    hardware_scope: "MATCHED", contextual_scope: "PERTINENT",
    technical_result: "EXCLUDED",
  };
  const context = {applicability: {status: "NOT_APPLICABLE", source: "SYSTEM"}};
  assert.equal(canConfirmCveWithExternalEvidence(config, context, true), true);
  assert.equal(canConfirmCveWithExternalEvidence(config, context, false), false);
  assert.equal(canConfirmCveWithExternalEvidence(
    {...config, hardware_scope: "DISTINCT", contextual_scope: "FOREIGN"},
    context, true
  ), false);
  assert.equal(canConfirmCveWithExternalEvidence(
    {...config, technical_result: "INDETERMINATE"}, context, true
  ), false);
  assert.equal(canConfirmCveWithExternalEvidence(
    config, {applicability: {status: "PENDING_REVIEW"}}, true
  ), false);
  assert.equal(canConfirmCveWithExternalEvidence(
    config, {applicability: {status: "NOT_APPLICABLE", source: "ANALYST"}}, true
  ), true);
});

test("NVD criterion titles are grounded in the tree, not inferred device matching", () => {
  const labels = cveScopeCriterionLabels({tree: {kind: "GROUP", children: [
    {kind: "CRITERION", criteria:
      "cpe:2.3:h:siemens:simatic_s7-1200_cpu_1215c:-:*:*:*:*:*:*:*"},
    {kind: "CRITERION", criteria:
      "cpe:2.3:o:siemens:simatic_s7-1200_cpu_1215c_firmware:*:*:*:*:*:*:*:*"},
    {kind: "CRITERION", criteria:
      "cpe:2.3:h:siemens:simatic_s7-1200_cpu_1215c:-:*:*:*:*:*:*:*"},
  ]}});
  assert.deepEqual(labels, [
    "Hardware: siemens / simatic_s7-1200_cpu_1215c",
    "Firmware / SO: siemens / simatic_s7-1200_cpu_1215c_firmware",
  ]);
  assert.deepEqual(cveScopeCriterionLabels(null), []);
});

test("a hardware row distinguishes human override from the previous SYSTEM verdict", () => {
  assert.equal(cveHardwareApplicabilityLabel({
    scoped_applicability: {status: "APPLIES", source: "ANALYST"},
  }), "Aplica · Validado por analista");
  assert.equal(cveHardwareApplicabilityLabel({
    scoped_applicability: {status: "NOT_APPLICABLE", source: "SYSTEM"},
  }), "No aplica · Automático");
  assert.equal(cveHardwareApplicabilityLabel({}), null);
  assert.match(cveApplicabilityExplanation({
    applicability: {status: "APPLIES", source: "ANALYST"},
  }), /analista.*«Aplica»/);
});

test("compact evidence labels only represent demonstrated CPE and version facts", () => {
  const config = {
    technical_result: "EXCLUDED",
    tree: {
      kind: "GROUP", operator: "AND", children: [
        {kind: "CRITERION", part: "h", technical_identity: "MATCHED"},
        {kind: "CRITERION", part: "o", technical_identity: "MATCHED"},
      ],
    },
    evaluated_software: [{
      software_installation_id: 5,
      reason: "FIRMWARE_OR_SOFTWARE_VERSION_EXCLUDED",
    }],
  };
  const original = JSON.stringify(config);
  assert.deepEqual(cveConfigurationHighlights(config), [
    {label: "CPE hardware confirmado", kind: "verified"},
    {label: "CPE software identificado", kind: "verified"},
    {label: "Versión fuera de rango", kind: "excluded"},
  ]);
  assert.equal(JSON.stringify(config), original, "presentational grouping is read-only");
  const pending = {
    technical_result: "INDETERMINATE",
    tree: {kind: "GROUP", children: [
      {kind: "CRITERION", part: "o", technical_identity: "UNKNOWN"},
    ]},
  };
  assert.deepEqual(cveConfigurationHighlights(pending), [
    {label: "Evidencia pendiente", kind: "pending"},
  ]);
  assert.deepEqual(cveConfigurationHighlights(null), []);
  assert.deepEqual(cveConfigurationHighlights({
    technical_result: "EXCLUDED",
    tree: {kind: "GROUP", children: []},
  }), []);
});

test("severity and run state never claim that a candidate CVE applies", () => {
  assert.equal(CVE_SEVERITY.HIGH, "Alta");
  assert.equal(CVE_DISCOVERY_STATE.COMPLETED, "Completada");
  assert.equal(isCveDiscoveryActive("RUNNING"), true);
  assert.equal(isCveDiscoveryActive("COMPLETED"), false);
  assert.equal(isCveDiscoveryActive("FAILED"), false);
});

test("only hardware with confirmed CPE is available for selection", () => {
  const rows = [
    { asset_id: 2, asset_type: "HARDWARE", confirmed_count: 1 },
    { asset_id: 4, asset_type: "SOFTWARE", confirmed_count: 2 },
    { asset_id: 6, asset_type: "HARDWARE", confirmed_count: 0 },
  ];
  assert.deepEqual(cveHardwareCandidates(rows).map(row => row.asset_id), [2]);
});

test("hardware selection toggles without duplicates or exceeding batch limit", () => {
  assert.deepEqual(toggleCveHardwareSelection([], 2), [2]);
  assert.deepEqual(toggleCveHardwareSelection([2], 2), []);
  assert.deepEqual(toggleCveHardwareSelection([2], 4), [2, 4]);
  assert.deepEqual(toggleCveHardwareSelection([2, 4], 6, 2), [2, 4]);
  assert.equal(cveHardwareSelectionValid([2, 4]), true);
  assert.equal(cveHardwareSelectionValid([2, 2]), false);
  assert.equal(cveHardwareSelectionValid([]), false);
  assert.equal(cveHardwareSelectionValid([0]), false);
});

test("catalogue pagination clamps empty or invalid totals", () => {
  assert.equal(cvePageCount(0), 1);
  assert.equal(cvePageCount(16), 2);
  assert.equal(cvePageCount(undefined), 1);
  assert.equal(cvePageCount(101, 20), 6);
});


test("catalogue statuses explain scoped evaluation rather than NVD fetch", () => {
  assert.equal(CVE_EVALUATION_STATE.PENDING_REVIEW, "Por validar");
  assert.equal(CVE_EVALUATION_STATE.IN_REVIEW, "En revisión");
  assert.equal(CVE_EVALUATION_STATE.APPLIES, "Aplica");
  assert.equal(CVE_EVALUATION_STATE.NOT_APPLICABLE, "No aplica");
  assert.equal(CVE_EVALUATION_STATE.STALE, "Revisar evidencia");
  assert.match(CVE_EVALUATION_HELP.APPLIES, /al menos una/i);
  assert.match(CVE_EVALUATION_HELP.NOT_APPLICABLE, /pertinentes/i);
});

test("technical compatibility has its own labels and an attention filter", () => {
  assert.equal(CVE_TECHNICAL_STATE.COMPATIBLE, "Coincidencia técnica");
  assert.equal(CVE_TECHNICAL_STATE.EXCLUDED, "Condiciones excluidas");
  assert.equal(CVE_TECHNICAL_STATE.INDETERMINATE, "Por verificar");
  assert.equal(CVE_TECHNICAL_FILTER.ATTENTION, "Requieren atención");
  assert.equal(CVE_EVALUATION_STATE.NOT_APPLICABLE, "No aplica");
  assert.notEqual(CVE_EVALUATION_STATE.NOT_APPLICABLE,
    CVE_TECHNICAL_STATE.EXCLUDED);
});

test("default CVE view prioritizes unresolved/compatible results", () => {
  assert.equal(DEFAULT_CVE_TECHNICAL_FILTER, "ATTENTION");
  assert.equal(CVE_TECHNICAL_FILTER.ATTENTION, "Requieren atención");
  assert.equal(CVE_TECHNICAL_FILTER.EXCLUDED, "Condiciones excluidas");
});


test("CVE Ver selects the hardware explaining the positive technical result", () => {
  const row = { related_assets: [
    { hardware_id: 2, technical_result: "EXCLUDED" },
    { hardware_id: 10, technical_result: "COMPATIBLE" },
    { hardware_id: 12, technical_result: "INDETERMINATE" },
  ] };
  assert.equal(preferredCveHardwareId(row), 10);
  assert.equal(preferredCveHardwareId({ related_assets: [
    { hardware_id: 2, technical_result: "INDETERMINATE" },
    { hardware_id: 10, technical_result: "EXCLUDED" },
  ] }), 2);
  assert.equal(preferredCveHardwareId({ related_assets: [] }), null);
});

test("CVE hardware deep link accepts only related asset IDs", () => {
  const rows = [{ hardware_id: 2 }, { hardware_id: 10 }];
  assert.equal(selectedCveHardwareId(rows, "10"), "10");
  assert.equal(selectedCveHardwareId(rows, "99"), "2");
  assert.equal(selectedCveHardwareId(rows, "10;DROP TABLE"), "2");
  assert.equal(selectedCveHardwareId(rows, null), "2");
  assert.equal(selectedCveHardwareId([], "10"), "");
});


test("the per-hardware CVE progress includes every NVD alternative", () => {
  assert.equal(cveReviewProgress({
    total_configurations: 96, reviewed_configurations: 1,
  }), "1 de 96 configuraciones con revisión vigente");
  assert.equal(cveReviewProgress({
    total_configurations: 96, reviewed_configurations: 0,
  }), "0 de 96 configuraciones con revisión vigente");
  assert.equal(cveReviewProgress(null), "Estado de revisión no disponible");
  assert.equal(cveReviewProgress({total_configurations: 3, reviewed_configurations: 40}),
    "3 de 3 configuraciones con revisión vigente");
});

test("one primary configuration represents the CVE with NVD alternatives available", () => {
  const unrelated = {index:0,technical_result:"EXCLUDED"};
  const matched = {index:8,technical_result:"COMPATIBLE"};
  const unresolved = {index:16,technical_result:"INDETERMINATE"};
  const grouped = groupCveEvidence([unrelated,unresolved,matched]);
  assert.equal(grouped.primary.index,8);
  assert.deepEqual(grouped.others.map(x=>x.index),[0,16]);
  assert.equal(groupCveEvidence([]).primary,null);
});

test("current audited positive is primary, stale evidence loses priority", () => {
  const technical={index:8,technical_result:"COMPATIBLE"};
  const audited={index:3,technical_result:"INDETERMINATE",
    latest_assessment:{effective_status:"APPLIES",stale:false}};
  assert.equal(groupCveEvidence([technical,audited]).primary.index,3);
  const old={...audited,latest_assessment:{effective_status:"PENDING_REVIEW",stale:true}};
  assert.equal(groupCveEvidence([technical,old]).primary.index,8);
});

test("one human verdict does not imply mandatory reviews of 96 configurations", () => {
  assert.match(cveHumanReviewMessage({status:"PENDING_REVIEW"}),/no se ha registrado/i);
  assert.match(cveHumanReviewMessage({status:"APPLIES"}),/al menos una/i);
  assert.match(cveHumanReviewMessage({status:"NOT_APPLICABLE"}),/Todas/i);
  assert.match(cveHumanReviewMessage({status:"STALE"}),/cambió/i);
  assert.match(cveHumanReviewMessage({status:"IN_REVIEW"}),/historial/i);
});


test("applicability names the origin without inventing analyst decisions", () => {
  assert.equal(CVE_APPLICABILITY_SOURCE.SYSTEM, "Automático");
  assert.equal(CVE_APPLICABILITY_SOURCE.ANALYST, "Validado por analista");
  assert.equal(CVE_APPLICABILITY_SOURCE.NONE, "Pendiente de validación");
  assert.equal(CVE_EVALUATION_STATE.APPLIES, "Aplica");
  assert.equal(CVE_EVALUATION_STATE.PENDING_REVIEW, "Por validar");
});


test("a matched CPE product does not imply the NVD vulnerable version applies", () => {
  const fw = {
    part: "o", technical_identity: "MATCHED",
    technical_matched_cpe: "cpe:2.3:o:siemens:simatic_s7-1200_cpu_1215c_firmware:4.5.2:*:*:*:*:*:*:*",
    technical_result: "INDETERMINATE",
  };
  assert.deepEqual(nvdCriterionIdentityBadge(fw),
    {label:"Versión por verificar",state:"UNVERIFIED"});
  assert.deepEqual(nvdCriterionIdentityBadge({
    ...fw, technical_result:"COMPATIBLE",
  }), {label:"Coincidencia técnica",state:"SATISFIED"});
  assert.deepEqual(nvdCriterionIdentityBadge({
    ...fw, technical_result:"EXCLUDED",
  }), {label:"Versión fuera de rango",state:"NOT_SATISFIED"});
  assert.deepEqual(nvdCriterionIdentityBadge({
    ...fw, technical_identity:"UNKNOWN", technical_matched_cpe:null,
  }), {label:"Producto por verificar",state:"UNVERIFIED"});
  assert.deepEqual(nvdCriterionIdentityBadge({
    part:"h", technical_identity:"MATCHED",
    technical_matched_cpe:"cpe:2.3:h:siemens:simatic_s7-1200_cpu_1215c:-:*:*:*:*:*:*:*",
  }), {label:"CPE confirmado",state:"SATISFIED"});
});

test("platform mismatch badges explain proven software and hardware exclusions", () => {
  assert.deepEqual(nvdCriterionIdentityBadge({
    part: "a", technical_identity: "PLATFORM_DISTINCT",
    technical_result: "EXCLUDED",
  }), {label:"Plataforma incompatible", state:"NOT_SATISFIED"});
  assert.deepEqual(nvdCriterionIdentityBadge({
    part: "h", technical_identity: "DISTINCT",
    technical_result: "EXCLUDED",
  }), {label:"Plataforma distinta", state:"NOT_SATISFIED"});
});

test("automatic history reads El sistema without changing a persisted justification", () => {
  const old = "VISOR OT confirmó automáticamente la correspondencia de la configuración NVD 9.";
  assert.equal(cveAuditJustification(old, "SYSTEM"),
    "El sistema confirmó automáticamente la correspondencia de la configuración NVD 9.");
  assert.equal(cveAuditJustification(old, "ANALYST"), old);
});

test("CVE filters show exactly four applicability choices", () => {
  assert.deepEqual(Object.keys(CVE_CATALOGUE_FILTER_STATES),
    ["PENDING_REVIEW", "APPLIES", "APPLIES_CONDITIONAL", "NOT_APPLICABLE"]);
  for (const status of ["PENDING_REVIEW","IN_REVIEW","STALE",null]) {
    assert.equal(displayCveApplicability(status), "PENDING_REVIEW");
  }
  assert.equal(displayCveApplicability("APPLIES"), "APPLIES");
  assert.equal(displayCveApplicability("NOT_APPLICABLE"), "NOT_APPLICABLE");
});


test("conditioned applicability is a distinct, human-only visible state", () => {
  assert.equal(displayCveApplicability("APPLIES_CONDITIONAL"), "APPLIES_CONDITIONAL");
  assert.equal(CVE_CATALOGUE_FILTER_STATES.APPLIES_CONDITIONAL, "Aplica condicionada");
  assert.equal(cveAssetRoleLabel("PLATFORM"), "Plataforma");
  assert.equal(cveAssetRoleLabel("VULNERABLE"), "Vulnerable");
});

test("OR groups show verified platform and preserve every alternative", () => {
  const alternative = {kind: "CRITERION", technical_identity: "UNKNOWN"};
  const found = {kind: "CRITERION", technical_identity: "MATCHED",
    technical_matched_cpe: "cpe:2.3:h:siemens:cpu_1215c:-:*:*:*:*:*:*:*"};
  const group = relevantNvdChildren({
    operator: "OR", children: [alternative, found, alternative],
  });
  assert.deepEqual(group.visible, [found]);
  assert.equal(group.alternatives.length, 2);
  const andGroup = relevantNvdChildren({
    operator: "AND", children: [alternative, found],
  });
  assert.equal(andGroup.visible.length, 2);
  assert.equal(andGroup.alternatives.length, 0);
});

test("audited conditional NVD evidence is primary over unrelated candidates", () => {
  const pending = {index: 0, technical_result: "INDETERMINATE"};
  const conditional = {index: 8, technical_result: "INDETERMINATE",
    latest_assessment: {effective_status: "APPLIES_CONDITIONAL", stale: false}};
  assert.equal(groupCveEvidence([pending, conditional]).primary.index, 8);
});


test("CVE OR presentation shows one alternative but retains every NVD branch", () => {
  const hiddenHardware = {kind: "CRITERION", part: "h", criteria: "hardware-b",
    technical_identity: "UNKNOWN"};
  const verifiedHardware = {kind: "CRITERION", part: "h", criteria: "hardware-a",
    technical_identity: "MATCHED", technical_matched_cpe: "cpe:2.3:h:siemens:cpu:-:*:*:*:*:*:*:*"};
  const group = {operator: "OR", children: [hiddenHardware, verifiedHardware]};
  const original = JSON.stringify(group);
  const initial = displayNvdGroupBranches(group);
  assert.deepEqual(initial.shown, [verifiedHardware]);
  assert.deepEqual(initial.hidden, [hiddenHardware]);
  assert.equal(nvdAlternativeGroupLabel(initial.hidden), "Otras alternativas de hardware NVD");
  const promoted = displayNvdGroupBranches(group, "hardware-b");
  assert.deepEqual(promoted.shown, [hiddenHardware]);
  assert.deepEqual(promoted.hidden, [verifiedHardware]);
  assert.equal(JSON.stringify(group), original, "NVD original must not be mutated");
});

test("AND groups keep mandatory criteria visible even with a selected software", () => {
  const software = {kind: "CRITERION", part: "o", criteria: "firmware"};
  const hardware = {kind: "CRITERION", part: "h", criteria: "plc"};
  const andGroup = {operator: "AND", children: [software, hardware]};
  const result = displayNvdGroupBranches(andGroup, "firmware");
  assert.deepEqual(result.shown, [software, hardware]);
  assert.deepEqual(result.hidden, []);
});

test("NVD alternative group labels distinguish software and mixed criteria", () => {
  const fw = {kind: "CRITERION", part: "o", criteria: "firmware"};
  const app = {kind: "CRITERION", part: "a", criteria: "application"};
  const hw = {kind: "CRITERION", part: "h", criteria: "plc"};
  const grouped = {kind: "GROUP", children: [fw, app]};
  assert.equal(nvdAlternativeGroupLabel([grouped]),
    "Otras alternativas de software NVD");
  assert.equal(nvdAlternativeGroupLabel([fw, hw]),
    "Otras alternativas NVD");
  assert.equal(nvdAlternativeGroupLabel([]), "Otras alternativas NVD");
});

test("single NVD criterion does not invent an OR alternative", () => {
  const one = {kind: "CRITERION", part: "o", criteria: "firmware"};
  const group = {operator: "OR", children: [one]};
  const result = displayNvdGroupBranches(group);
  assert.deepEqual(result.shown, [one]);
  assert.deepEqual(result.hidden, []);
});

test("an automatic or analyst verdict can be reopened only into other states", () => {
  assert.deepEqual(allowedCveDecisionTransitions("APPLIES"),
    ["CONDITIONAL", "NOT_MATCH", "UNKNOWN"]);
  assert.deepEqual(allowedCveDecisionTransitions("NOT_APPLICABLE"),
    ["CONFIRMED", "CONDITIONAL", "UNKNOWN"]);
  assert.deepEqual(allowedCveDecisionTransitions("APPLIES_CONDITIONAL"),
    ["CONFIRMED", "NOT_MATCH", "UNKNOWN"]);
  assert.deepEqual(allowedCveDecisionTransitions("PENDING_REVIEW"),
    ["CONFIRMED", "CONDITIONAL", "NOT_MATCH", "UNKNOWN"]);
});

test("operational detail hides unrelated hardware even with automatic history", () => {
  const otherCpu = Array.from({length: 47}, (_, index) => ({
    index, position: index + 1, hardware_scope: "DISTINCT",
    technical_result: "EXCLUDED",
    history: [{status: "NOT_APPLICABLE", source: "SYSTEM"}],
  }));
  const main = {
    index: 47, position: 13, hardware_scope: "MATCHED",
    technical_result: "EXCLUDED", history: [{status: "NOT_APPLICABLE"}],
  };
  const context = {
    relevant_configurations: [...otherCpu, main],
    hardware_software_configurations: [main],
    configurations: [...otherCpu, main],
  };
  const result = selectCveOperationalGroups(context);
  assert.deepEqual(result.reviewPool.map(row => row.position), [13]);
  assert.deepEqual(result.hardwareSoftware.map(row => row.position), [13]);
  assert.deepEqual(result.independentConfigs, []);
  assert.equal(context.configurations.length, 48);
  assert.deepEqual(selectCveOperationalGroups({
    relevant_configurations: otherCpu,
    hardware_software_configurations: [],
  }).reviewPool, []);
});

test("only the hardware-anchored NVD config is operational among 96", () => {
  const other = Array.from({length: 96}, (_, index) => ({
    index, position: index + 1, hardware_scope: "UNVERIFIED",
    technical_result: "INDETERMINATE",
  }));
  const relevant = {...other[8], hardware_scope: "MATCHED",
    contextual_scope: "PERTINENT", technical_result: "COMPATIBLE"};
  const context = {
    configurations: other,
    relevant_configurations: [relevant],
    hardware_software_configurations: [relevant],
    contextual_selection: {pertinent_indexes: [8], evaluated_indexes: [8]},
  };
  const result = selectCveOperationalGroups(context);
  assert.deepEqual(result.reviewPool.map(row => row.position), [9]);
  assert.deepEqual(result.hardwareSoftware.map(row => row.position), [9]);
  assert.equal(context.configurations.length, 96);
});

test("STEP 7 OR exposes eight selectable software choices inside matched hardware", () => {
  const step7 = Array.from({length: 8}, (_, index) => ({
    kind: "CRITERION", part: "a", vulnerable: true,
    criteria: "cpe:2.3:a:siemens:simatic_step_7:17:update" + index +
      ":*:*:*:*:*:*",
    match_criteria_id: "STEP7-" + index,
    technical_identity: "UNKNOWN",
  }));
  const or = {kind: "GROUP", operator: "OR", children: step7};
  const original = JSON.stringify(or);
  const initial = operationalNvdGroupBranches(or);
  assert.equal(initial.shown.length, 1);
  assert.equal(initial.hidden.length, 7);
  assert.equal(nvdAlternativeGroupLabel(initial.hidden),
    "Otras alternativas de software NVD");
  const selected = operationalNvdGroupBranches(or, "STEP7-5");
  assert.equal(selected.shown[0].match_criteria_id, "STEP7-5");
  assert.equal(selected.hidden.length, 7);
  assert.equal(displayedNvdSoftwareCriterion(or, "STEP7-5").match_criteria_id,
    "STEP7-5");
  assert.equal(canSelectNvdCriterionSoftware(selected.shown[0], "STEP7-5"), true);
  assert.equal(canSelectNvdCriterionSoftware(initial.hidden[0], "STEP7-5", true),
    false);
  assert.equal(JSON.stringify(or), original);
});

test("hardware detail hides unscoped software even when it is present in NVD", () => {
  const standalone = {
    index: 0, hardware_scope: "UNSCOPED", technical_result: "COMPATIBLE",
  };
  const platform = {
    index: 1, hardware_scope: "MATCHED", technical_result: "INDETERMINATE",
  };
  const foreign = {
    index: 2, hardware_scope: "DISTINCT", technical_result: "EXCLUDED",
  };
  const value = selectCveOperationalGroups({
    relevant_configurations: [platform, standalone, foreign],
    hardware_software_configurations: [platform],
  });
  assert.deepEqual(value.reviewPool.map(row => row.index), [1]);
  assert.deepEqual(value.independentConfigs, []);
  assert.deepEqual(selectCveOperationalGroups({
    relevant_configurations: [standalone, foreign],
  }).reviewPool, []);
});

test("audit timeline highlights software name and historic version, not installation IDs", () => {
  const oldRecord = {
    source: "SYSTEM", status: "NOT_APPLICABLE",
    justification: "Software instalado #25, instalación #5, versión 4.5.2",
    negative_evidence: {excluded_by: [{
      reason: "FIRMWARE_OR_SOFTWARE_VERSION_EXCLUDED",
    }]},
    software_display: [{
      software_installation_id: 5, software_asset_id: 25,
      software_name: "Firmware SIMATIC S7-1200 CPU 1215C",
      installed_version: "4.5.2",
    }],
  };
  assert.equal(cveHistoryDecisionDescription(oldRecord),
    "La versión evaluada está fuera del intervalo vulnerable NVD.");
  assert.deepEqual(cveHistorySoftwareLabel(oldRecord), [{
    key: "5",
    label: "Firmware SIMATIC S7-1200 CPU 1215C · Versión 4.5.2",
    detail: "Software #25",
  }]);
  assert.equal(cveHistoryDecisionDescription({
    source: "SYSTEM", status: "APPLIES",
  }), "Los CPE y las versiones comprobadas cumplen los criterios NVD.");
  assert.equal(cveHistoryDecisionDescription({
    source: "ANALYST", justification: "Revisión manual documentada.",
  }), "Revisión manual documentada.");
  assert.deepEqual(cveHistorySoftwareLabel({software_display: []}), []);
});

test("historic software fallback never invents a product or version", () => {
  const legacy = {
    software_display: [{
      software_installation_id: 5,
      software_asset_id: 25,
      software_name: null,
      installed_version: null,
    }],
  };
  assert.deepEqual(cveHistorySoftwareLabel(legacy), [{
    key: "5", label: "Software #25", detail: "",
  }]);
  assert.match(cveHistoryDecisionDescription({
    status: "NOT_APPLICABLE",
    source: "SYSTEM",
    negative_evidence: {excluded_by: [
      {reason: "DISTINCT_PLATFORM_VERIFIED"},
    ]},
  }), /plataforma NVD/);
});

test("negative system decision marks evaluated firmware but never a positive link", () => {
  const negative = {
    index: 12,
    technical_result: "EXCLUDED",
    latest_assessment: {
      source: "SYSTEM", effective_status: "NOT_APPLICABLE",
      status: "NOT_APPLICABLE", stale: false,
      evaluated_software: [{
        software_installation_id: 5, software_asset_id: 25,
        criterion: "cpe:2.3:o:siemens:cpu_1215c_firmware:*:*:*:*:*:*:*:*",
      }],
    },
    tree: { kind: "GROUP", children: [{
      kind: "CRITERION", vulnerable: true, part: "o",
      criteria: "cpe:2.3:o:siemens:cpu_1215c_firmware:*:*:*:*:*:*:*:*",
      match_criteria_id: "firmware-criterion",
    }] },
  };
  const context = { installed_software: [{
    installation_id: 5, software_asset_id: 25,
    software_type: "FIRMWARE", version: "4.5.2",
  }] };
  assert.equal(currentCveSoftwareLink(negative, context), null);
  const evidence = currentCveEvaluatedSoftware(negative, context);
  assert.deepEqual(evidence, {
    installationId: "5", criterionKey: "firmware-criterion",
    source: "SYSTEM", evidenceOnly: true,
  });
  assert.equal(isSavedCveLinkSelection(evidence, "firmware-criterion", "5"), true);
  assert.equal(isSavedCveLinkSelection(evidence, "", ""), false);
  const stale = {
    ...negative,
    latest_assessment: { ...negative.latest_assessment, stale: true },
  };
  assert.equal(currentCveEvaluatedSoftware(stale, context), null);
  const reopened = {
    ...negative,
    latest_assessment: {
      ...negative.latest_assessment, source: "ANALYST",
      effective_status: "APPLIES_CONDITIONAL", status: "APPLIES_CONDITIONAL",
    },
  };
  assert.equal(currentCveEvaluatedSoftware(reopened, context), null);
});

test("analyst NOT_APPLICABLE rechecks reviewed firmware only for its recorded STEP 7 alternative", () => {
  // The actual CVE-2021-42029 assessment for PLC-TRA-01 has no positive
  // software link. Its negative review records installation #3 (firmware 4.5.2)
  // against application-type NVD criterion STEP 7. The mismatch is precisely
  // what the analyst reviewed, and must not be silently discarded by React.
  const step7 = {
    kind: "CRITERION", vulnerable: true, part: "a",
    criteria: "cpe:2.3:a:siemens:simatic_step_7:*:*:*:*:*:*:*:*",
    match_criteria_id: "BBCA2BFB-EEEB-4722-AC33-CBBFE92289BC",
  };
  const second = {
    kind: "CRITERION", vulnerable: true, part: "a",
    criteria: "cpe:2.3:a:siemens:other_application:*:*:*:*:*:*:*:*",
    match_criteria_id: "OTHER-STEP-7-ALTERNATIVE",
  };
  const config = {
    index: 0, tree: {kind:"GROUP",operator:"OR",children:[step7,second]},
    latest_assessment: null,
  };
  const decision = {
    configuration_index: 0,
    status: "NOT_APPLICABLE", effective_status: "NOT_APPLICABLE",
    source: "ANALYST", stale: false, software_installation_id: null,
    evaluated_software: [
      {software_installation_id:3, software_asset_id:6, installed_version:"4.5.2"},
    ],
    selected_nvd_criterion: {
      key: step7.match_criteria_id, criteria: step7.criteria, part:"a",
    },
  };
  const context = {
    hardware_asset_id: 5, hardware_cve_decision: decision,
    installed_software: [
      {installation_id:3,software_asset_id:6,software_type:"FIRMWARE",
       version:"4.5.2"},
    ],
  };
  // Preserve the negative conclusion and do NOT fabricate a vulnerable link.
  assert.equal(currentCveSoftwareLink(config, context), null);
  const saved = currentCveScopedEvaluatedSoftware(config, context);
  assert.deepEqual(saved, {
    installationId:"3",criterionKey:step7.match_criteria_id,
    source:"ANALYST",evidenceOnly:true,
  });
  assert.ok(isSavedCveLinkSelection(saved, step7.match_criteria_id,"3"));
  assert.equal(isSavedCveLinkSelection(saved, second.match_criteria_id,"3"),false);
  assert.equal(currentCveScopedEvaluatedSoftware({...config,index:1},context),
    null, "a verdict for NVD configuration 1 must not check configuration 2");
});

test("saved negative review stays unchecked when stale, removed, mismatched, or reopened", () => {
  const key = "NVD-STEP7";
  const config = {index:0,tree:{kind:"GROUP",children:[{
    kind:"CRITERION",part:"a",vulnerable:true,
    match_criteria_id:key, criteria:"cpe:2.3:a:siemens:simatic_step_7:*",
  }]}};
  const global = {
    configuration_index:0,source:"ANALYST",status:"NOT_APPLICABLE",
    effective_status:"NOT_APPLICABLE",stale:false,
    selected_nvd_criterion:{key,criteria:"cpe:2.3:a:siemens:simatic_step_7:*"},
    evaluated_software:[{
      software_installation_id:3, software_asset_id:6,installed_version:"4.5.2",
    }],
  };
  const software = [{
    installation_id:3,software_asset_id:6,software_type:"FIRMWARE",version:"4.5.2",
  }];
  const context = {installed_software:software,hardware_cve_decision:global};
  assert.ok(currentCveScopedEvaluatedSoftware(config,context));
  assert.equal(currentCveScopedEvaluatedSoftware(config,{
    ...context,hardware_cve_decision:{...global,stale:true},
  }),null);
  assert.equal(currentCveScopedEvaluatedSoftware(config,{
    ...context,hardware_cve_decision:{...global,effective_status:"PENDING_REVIEW",
      status:"PENDING_REVIEW"},
  }),null);
  assert.equal(currentCveScopedEvaluatedSoftware(config,{
    ...context,installed_software:[],
  }),null);
  assert.equal(currentCveScopedEvaluatedSoftware(config,{
    ...context,installed_software:[{...software[0],version:"4.6.0"}],
  }),null);
  assert.equal(currentCveScopedEvaluatedSoftware(config,{
    ...context,installed_software:[{...software[0],software_asset_id:42}],
  }),null);
  assert.equal(currentCveScopedEvaluatedSoftware(config,{
    ...context,hardware_cve_decision:{
      ...global,selected_nvd_criterion:{key:"other-leaf"},
    },
  }),null, "never check an unrelated NVD alternative");
  assert.equal(currentCveScopedEvaluatedSoftware(config,{
    ...context,hardware_cve_decision:{
      ...global,evaluated_software:[],
    },
  }),null, "no stored reviewed software means no checked box");
});

test("saved SYSTEM software association is visible without a new analyst action", () => {
  const criterion = {
    kind:"CRITERION", vulnerable:true, part:"o", criteria:"cpe:nvd:firmware",
    match_criteria_id:"nvd-fw", technical_software_installation_id:5,
  };
  const config = {
    index:8, tree:{kind:"GROUP", children:[criterion]},
    latest_assessment:{
      status:"APPLIES", effective_status:"APPLIES", source:"SYSTEM",
      stale:false, software_installation_id:5,
    },
  };
  const context = {
    installed_software:[{installation_id:5, software_type:"FIRMWARE"}],
    applicability:{source:"SYSTEM"},
  };
  assert.deepEqual(currentCveSoftwareLink(config,context), {
    installationId:"5", criterionKey:"nvd-fw", source:"SYSTEM",
  });
  assert.equal(currentCveSoftwareLink({...config,
    latest_assessment:{...config.latest_assessment, stale:true}},context),null);
});

test("analyst conditional link is checked only when saved and current", () => {
  const criterion = {kind:"CRITERION", vulnerable:true, part:"a",
    criteria:"cpe:nvd:step7", match_criteria_id:"nvd-step7"};
  const config = {index:0, tree:{kind:"GROUP", children:[criterion]},
    latest_assessment:{
      status:"APPLIES_CONDITIONAL", effective_status:"APPLIES_CONDITIONAL",
      source:"ANALYST", stale:false, software_installation_id:17,
      conditional_evidence:{linked_software:[{criteria:null,
        candidate_nvd_criteria:["cpe:nvd:step7"]}]},
    }};
  const context = {installed_software:[
    {installation_id:17, software_type:"APPLICATION"},
  ]};
  assert.deepEqual(currentCveSoftwareLink(config,context),{
    installationId:"17", criterionKey:"nvd-step7", source:"ANALYST",
  });
  assert.equal(currentCveSoftwareLink({...config, latest_assessment:{
    status:"PENDING_REVIEW", effective_status:"PENDING_REVIEW",
    source:"ANALYST", software_installation_id:null, stale:false,
  }},context),null, "reopening suppresses previously saved check");
  assert.equal(currentCveSoftwareLink({...config, latest_assessment:{
    ...config.latest_assessment, software_installation_id:null,
  }},context),null, "an unlinked partial assessment does not check software");
});

test("automatic NVD proof can display a current link before audit is synchronized", () => {
  const config = {index:3, tree:{kind:"GROUP", children:[
    {kind:"CRITERION", part:"o", vulnerable:true,
      criteria:"cpe:nvd:fw",match_criteria_id:"nvd-fw"},
  ]}, latest_assessment:null};
  const context = {installed_software:[
    {installation_id:2, software_type:"FIRMWARE"},
  ], applicability:{source:"SYSTEM", automatic_evidence:{
    configuration_index:3, criteria:[
      {vulnerable:false, software_installation_id:null},
      {vulnerable:true, software_installation_id:2},
    ],
  }}};
  assert.deepEqual(currentCveSoftwareLink(config,context),{
    installationId:"2", criterionKey:"nvd-fw",source:"SYSTEM",
  });
  assert.equal(currentCveSoftwareLink({...config,index:4},context),null);
});

test("rechecking a saved CVE software link is an unchanged draft", () => {
  const automatic = {
    installationId:"5", criterionKey:"nvd-firmware", source:"SYSTEM",
  };
  assert.equal(isSavedCveLinkSelection(automatic,"nvd-firmware","5"),true);
  assert.equal(isSavedCveLinkSelection(automatic,"nvd-firmware",5),true);
  assert.equal(isSavedCveLinkSelection(automatic,"nvd-firmware",""),false);
  assert.equal(isSavedCveLinkSelection(automatic,"different-criterion","5"),true,
    "the database stores the installation, not the displayed OR criterion");
  assert.equal(isSavedCveLinkSelection(null,"nvd-firmware","5"),false);
});

test("STEP 7 NVD V16 Update 4 can be focused without a software installation", () => {
  const make = (version, update, id) => ({
    kind: "CRITERION", part: "a", vulnerable: true, match_criteria_id: id,
    criteria: `cpe:2.3:a:siemens:simatic_step_7:${version}:${update}:*:*:*:*:*:*`,
    technical_identity: "UNKNOWN",
  });
  const options = [
    make("16", "update1", "step7-16-u1"),
    make("16", "update4", "step7-16-u4"),
    make("17", "update1", "step7-17-u1"),
  ];
  const or = {kind: "GROUP", operator: "OR", children: options};
  const snapshot = JSON.stringify(or);
  const selected = operationalNvdGroupBranches(or, "step7-16-u4");
  assert.deepEqual(selected.shown, [options[1]]);
  assert.deepEqual(selected.hidden, [options[0], options[2]]);
  assert.equal(JSON.stringify(or), snapshot);
  // The selection only focuses presentation; no installed software was needed.
});

test("software NVD OR remains reachable within a hardware AND constraint", () => {
  const step7 = [
    {kind:"CRITERION",part:"a",vulnerable:true,criteria:"software15"},
    {kind:"CRITERION",part:"a",vulnerable:true,criteria:"software16"},
  ];
  const cpu = {kind:"CRITERION",part:"h",vulnerable:false,
    criteria:"cpu1215c",technical_identity:"MATCHED",
    technical_matched_cpe:"cpe:2.3:h:siemens:cpu1215c:-:*:*:*:*:*:*:*"};
  const and={kind:"GROUP",operator:"AND",children:[
    {kind:"GROUP",operator:"OR",children:step7},
    {kind:"GROUP",operator:"OR",children:[cpu]},
  ]};
  const children=operationalNvdGroupBranches(and,"software16");
  assert.equal(children.shown.length,2);
  assert.deepEqual(operationalNvdGroupBranches(children.shown[0],"software16").shown,
    [step7[1]]);
  assert.deepEqual(operationalNvdGroupBranches(children.shown[1]).shown,[cpu]);
});

test("only the examined alternative allows software checkboxes", () => {
  const first = {kind:"CRITERION", part:"a", vulnerable:true,
    criteria:"cpe:2.3:a:siemens:step_7:16:update1:*:*:*:*:*:*",
    match_criteria_id:"step7-u1"};
  const second = {...first,
    criteria:"cpe:2.3:a:siemens:step_7:16:update4:*:*:*:*:*:*",
    match_criteria_id:"step7-u4"};
  const or={kind:"GROUP", operator:"OR", children:[first,second]};
  const and={kind:"GROUP",operator:"AND",children:[
    or,{kind:"GROUP",operator:"OR",children:[{
      kind:"CRITERION",part:"h",vulnerable:false,criteria:"siemens-s7-1200",
      technical_identity:"MATCHED",technical_matched_cpe:"cpe:hw"
    }]}
  ]};
  assert.equal(displayedNvdSoftwareCriterion(and).match_criteria_id,"step7-u1");
  assert.equal(displayedNvdSoftwareCriterion(and,"step7-u4").match_criteria_id,
    "step7-u4");
  assert.equal(canSelectNvdCriterionSoftware(first,"step7-u1"),true);
  assert.equal(canSelectNvdCriterionSoftware(first,"step7-u1",true),false);
  assert.equal(canSelectNvdCriterionSoftware(second,"step7-u1"),false);
  assert.equal(canSelectNvdCriterionSoftware(second,"step7-u4"),true);
  assert.equal(canSelectNvdCriterionSoftware(second,"step7-u4",true),false);
  assert.equal(canSelectNvdCriterionSoftware({
    kind:"CRITERION",part:"h",vulnerable:false,criteria:"siemens-s7-1200"
  },"siemens-s7-1200"),false);
  assert.equal(canSelectNvdCriterionSoftware(first,""),false);
});

test("correspondence buttons follow checkbox and verified NVD installation", () => {
  const eligible = [5, 8];
  // Unmarked: a conditional review, no installed software presumed.
  assert.equal(preferredCveCorrespondenceVerdict("", eligible), "CONDITIONAL");
  assert.equal(preferredCveCorrespondenceVerdict(null, eligible), "CONDITIONAL");
  // A checked NVD-compatible installation is eligible for confirmation.
  assert.equal(preferredCveCorrespondenceVerdict("5", eligible), "CONFIRMED");
  assert.equal(preferredCveCorrespondenceVerdict(8, eligible), "CONFIRMED");
  // A checked, but unrelated application/firmware remains a partial review.
  assert.equal(preferredCveCorrespondenceVerdict("25", eligible), "CONDITIONAL");
  // Switching the checkbox updates any open positive form.
  assert.equal(updatedCveReviewChoice("CONFIRMED", "CONDITIONAL"), "CONDITIONAL");
  assert.equal(updatedCveReviewChoice("CONDITIONAL", "CONFIRMED"), "CONFIRMED");
  // "No corresponde" is available with or without a checked installation.
  assert.equal(updatedCveReviewChoice("NOT_MATCH", "CONFIRMED"), "NOT_MATCH");
  assert.equal(updatedCveReviewChoice("NOT_MATCH", "CONDITIONAL"), "NOT_MATCH");
  assert.equal(updatedCveReviewChoice("", "CONFIRMED"), "");
});

test("same official CVE yields distinct detail links for each evaluated PLC", () => {
  const common = { cve_id: "CVE-2021-42029" };
  assert.equal(cveEvaluationDetailUrl({ ...common, hardware_id: 1 }),
    "/vulnerabilities/cve/CVE-2021-42029?hardware=1");
  assert.equal(cveEvaluationDetailUrl({ ...common, hardware_id: 5 }),
    "/vulnerabilities/cve/CVE-2021-42029?hardware=5");
  assert.equal(cveEvaluationDetailUrl({ ...common, hardware_id: null }),
    "/vulnerabilities/cve/CVE-2021-42029");
  assert.equal(cveEvaluationDetailUrl({ ...common, hardware_id: "invalid" }),
    "/vulnerabilities/cve/CVE-2021-42029");
});
