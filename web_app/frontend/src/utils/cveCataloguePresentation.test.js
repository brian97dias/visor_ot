import test from "node:test";
import assert from "node:assert/strict";
import {
  CVE_SEVERITY, CVE_DISCOVERY_STATE, CVE_EVALUATION_STATE,
  CVE_EVALUATION_HELP, cvePageCount,
  cveHardwareCandidates, toggleCveHardwareSelection,
  cveHardwareSelectionValid, isCveDiscoveryActive,
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
