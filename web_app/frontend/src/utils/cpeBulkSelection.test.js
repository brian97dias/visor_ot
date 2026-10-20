import test from "node:test";
import assert from "node:assert/strict";
import {
  toggleRowSelection, togglePageSelection, countSelectedTypes,
} from "./cpeBulkSelection.js";

test("page selection preserves IDs selected on other pages", () => {
  assert.deepEqual(togglePageSelection([99], [1, 2], true), [99, 1, 2]);
  assert.deepEqual(togglePageSelection([99, 1, 2], [1, 2], false), [99]);
});

test("row selection works for hardware and software without duplicates", () => {
  const selected = toggleRowSelection([1], 1, true);
  assert.deepEqual(selected, [1]);
  assert.deepEqual(toggleRowSelection(selected, 7, true), [1, 7]);
  assert.deepEqual(toggleRowSelection([1, 7], 1, false), [7]);
});

test("mixed selection displays hardware and software counts", () => {
  assert.deepEqual(countSelectedTypes([
    { asset_type: "HARDWARE" }, { asset_type: "SOFTWARE" },
    { asset_type: "HARDWARE" },
  ]), { hardware: 2, software: 1 });
});
