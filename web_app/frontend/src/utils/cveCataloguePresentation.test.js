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
  preferredCveHardwareId, selectedCveHardwareId, cveReviewProgress,
  groupCveEvidence, cveHumanReviewMessage,
} from "./cveCataloguePresentation.js";

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
  assert.match(CVE_EVALUATION_HELP.NOT_APPLICABLE, /todas/i);
});

test("technical compatibility has its own labels and an attention filter", () => {
  assert.equal(CVE_TECHNICAL_STATE.COMPATIBLE, "Coincidencia técnica");
  assert.equal(CVE_TECHNICAL_STATE.EXCLUDED, "No aplica técnicamente");
  assert.equal(CVE_TECHNICAL_STATE.INDETERMINATE, "Por verificar");
  assert.equal(CVE_TECHNICAL_FILTER.ATTENTION, "Requieren atención");
  assert.equal(CVE_EVALUATION_STATE.NOT_APPLICABLE, "No aplica");
  assert.notEqual(CVE_EVALUATION_STATE.NOT_APPLICABLE,
    CVE_TECHNICAL_STATE.EXCLUDED);
});

test("default CVE view prioritizes unresolved/compatible results", () => {
  assert.equal(DEFAULT_CVE_TECHNICAL_FILTER, "ATTENTION");
  assert.equal(CVE_TECHNICAL_FILTER.ATTENTION, "Requieren atención");
  assert.equal(CVE_TECHNICAL_FILTER.EXCLUDED, "No aplica técnicamente");
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
  assert.equal(CVE_APPLICABILITY_SOURCE.SYSTEM, "Automático · VISOR OT");
  assert.equal(CVE_APPLICABILITY_SOURCE.ANALYST, "Validado por analista");
  assert.equal(CVE_APPLICABILITY_SOURCE.NONE, "Pendiente de validación");
  assert.equal(CVE_EVALUATION_STATE.APPLIES, "Aplica");
  assert.equal(CVE_EVALUATION_STATE.PENDING_REVIEW, "Por validar");
});
