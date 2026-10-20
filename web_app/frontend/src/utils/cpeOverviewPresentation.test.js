import test from "node:test";
import assert from "node:assert/strict";
import { cpeCountDetails } from "./cpeOverviewPresentation.js";

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
