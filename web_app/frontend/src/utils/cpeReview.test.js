import test from "node:test";
import assert from "node:assert/strict";
import { unreviewedCpeCandidates } from "./cpeReview.js";

test("a reviewed CPE disappears from candidates regardless of case or status", () => {
  const candidates = [
    { cpe_name_id: "ABC", title: "one" },
    { cpe_name_id: "DEF", title: "two" },
    { cpe_name_id: "GHI", title: "three" },
  ];
  const decisions = [
    { cpe_name_id: "abc", validation_status: "CONFIRMED" },
    { cpe_name_id: "def", validation_status: "REJECTED" },
  ];
  assert.deepEqual(unreviewedCpeCandidates(candidates, decisions), [candidates[2]]);
  assert.deepEqual(unreviewedCpeCandidates(candidates, [
    ...decisions, { cpe_name_id: "ghi", validation_status: "PENDING" },
  ]), []);
});

test("candidate partition is pure and supports empty results", () => {
  const candidates = [{ cpe_name_id: "123" }];
  assert.deepEqual(unreviewedCpeCandidates(candidates), candidates);
  assert.deepEqual(unreviewedCpeCandidates([], []), []);
  assert.equal(candidates.length, 1);
});
