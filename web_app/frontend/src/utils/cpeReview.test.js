import test from "node:test";
import assert from "node:assert/strict";
import {
  unreviewedCpeCandidates, reopenedWithoutCurrentCandidate, reviewedCpeAssociations,
} from "./cpeReview.js";

test("reviewed candidates are not shown twice, including case-insensitive IDs", () => {
  const candidates = [
    { cpe_name_id: "ABC" }, { cpe_name_id: "DEF" }, { cpe_name_id: "GHI" },
  ];
  const associations = [
    { cpe_name_id: "abc", validation_status: "CONFIRMED" },
    { cpe_name_id: "def", validation_status: "REJECTED" },
  ];
  assert.deepEqual(unreviewedCpeCandidates(candidates, associations), [candidates[2]]);
  assert.equal(reviewedCpeAssociations(associations).length, 2);
});

test("reopened association returns to candidate with PATCH identity", () => {
  const candidates = [{ cpe_name_id: "ABC" }];
  const associations = [{ id: 19, cpe_name_id: "abc", validation_status: "REOPENED" }];
  assert.deepEqual(unreviewedCpeCandidates(candidates, associations), candidates);
  assert.deepEqual(reviewedCpeAssociations(associations), []);
  assert.deepEqual(reopenedWithoutCurrentCandidate(candidates, associations), []);
});

test("a reopened CPE missing from the latest NVD run is not silently hidden", () => {
  const associations = [{ id: 19, cpe_name_id: "ABC", validation_status: "REOPENED" }];
  assert.deepEqual(reopenedWithoutCurrentCandidate([], associations), associations);
  assert.deepEqual(unreviewedCpeCandidates([], associations), []);
});

test("pending remains reviewed; pure utilities handle empty values", () => {
  const original = [{ cpe_name_id: "1" }];
  const reviewed = [{ cpe_name_id: "1", validation_status: "PENDING" }];
  assert.deepEqual(unreviewedCpeCandidates(original, reviewed), []);
  assert.deepEqual(unreviewedCpeCandidates(original), original);
  assert.deepEqual(reopenedWithoutCurrentCandidate([], []), []);
  assert.equal(original.length, 1);
});
