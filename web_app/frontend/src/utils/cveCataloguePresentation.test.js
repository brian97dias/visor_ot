import test from "node:test";
import assert from "node:assert/strict";
import {
  CVE_SEVERITY, CVE_DISCOVERY_STATE, CVE_EVALUATION_STATE,
  CVE_EVALUATION_HELP, CVE_TECHNICAL_STATE, CVE_TECHNICAL_FILTER,
  DEFAULT_CVE_TECHNICAL_FILTER,
  cvePageCount,
  cveHardwareCandidates, toggleCveHardwareSelection,
  cveHardwareSelectionValid, isCveDiscoveryActive,
  preferredCveHardwareId, selectedCveHardwareId,
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
