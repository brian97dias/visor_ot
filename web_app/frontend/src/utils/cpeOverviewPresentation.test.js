import test from "node:test";
import assert from "node:assert/strict";
import { cpeCountDetails, cpeManualDecisionDetails } from "./cpeOverviewPresentation.js";

test("fully evaluated Siemens: 2 found, 1 confirmed, 1 rejected", () => {
  const data = cpeCountDetails({
    candidate_count: 2, confirmed_count: 1, rejected_count: 1, unreviewed_count: 0,
  });
  assert.deepEqual(data.map(item => item.count), [1, 1, 0]);
  assert.equal(data[2].label, "por revisar");
});

test("undoing a rejection restores one candidate without losing the confirmation", () => {
  const data = cpeCountDetails({
    candidate_count: 2, confirmed_count: 1, rejected_count: 0, unreviewed_count: 1,
  });
  assert.deepEqual(data.map(item => item.count), [1, 0, 1]);
});

test("historical missing counts stay safe and pending remains not evaluated", () => {
  assert.deepEqual(cpeCountDetails({}).map(item => item.count), [0, 0, 0]);
  const row = {
    candidate_count: 2, confirmed_count: 1,
    rejected_count: 0, legacy_pending_count: 1, unreviewed_count: 1,
  };
  assert.deepEqual(cpeCountDetails(row).map(item => item.count), [1, 0, 1]);
});

test("manual-only confirmation contributes to reviewed totals without inventing automatic results", () => {
  const row = {
    run_id: 12, candidate_count: 0, confirmed_count: 1,
    rejected_count: 0, unreviewed_count: 0,
    manual_confirmed_count: 1, manual_rejected_count: 0,
  };
  assert.deepEqual(cpeCountDetails(row).map(x => x.count), [1, 0, 0]);
  assert.deepEqual(cpeManualDecisionDetails(row), {confirmed: 1, rejected: 0});
  assert.equal(row.candidate_count, 0);
});

test("mixed or overlapping manual evidence is provenance, not a second confirmation", () => {
  const mixed = {
    candidate_count: 2, confirmed_count: 1, rejected_count: 1,
    unreviewed_count: 0, manual_confirmed_count: 1, manual_rejected_count: 0,
  };
  assert.deepEqual(cpeCountDetails(mixed).map(x => x.count), [1, 1, 0]);
  assert.deepEqual(cpeManualDecisionDetails(mixed), {confirmed: 1, rejected: 0});
  assert.equal(cpeManualDecisionDetails({
    manual_confirmed_count: 0, manual_rejected_count: 0,
  }), null);
  assert.equal(cpeManualDecisionDetails({}), null);
});
