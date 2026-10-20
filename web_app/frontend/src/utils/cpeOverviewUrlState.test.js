import test from "node:test";
import assert from "node:assert/strict";
import { CPE_OVERVIEW_PAGE_SIZE, readCpePage, updateCpeOverviewParams } from "./cpeOverviewUrlState.js";

test("CPE overview uses inventory-sized pages and valid page numbers", () => {
  assert.equal(CPE_OVERVIEW_PAGE_SIZE, 15);
  assert.equal(readCpePage("3"), 3);
  assert.equal(readCpePage("0"), 1);
  assert.equal(readCpePage("-2"), 1);
  assert.equal(readCpePage("invalid"), 1);
});

test("CPE overview persists filters in URL and resets pagination on changes", () => {
  const base = new URLSearchParams("type=HARDWARE&status=CANDIDATES&q=Siemens&page=3");
  const next = updateCpeOverviewParams(base, "q", "Siemens S7");
  assert.equal(next.get("type"), "HARDWARE");
  assert.equal(next.get("status"), "CANDIDATES");
  assert.equal(next.get("q"), "Siemens S7");
  assert.equal(next.has("page"), false);
  const paged = updateCpeOverviewParams(next, "page", 2);
  assert.equal(paged.get("page"), "2");
  assert.equal(updateCpeOverviewParams(paged, "type", "ALL").has("type"), false);
  assert.equal(updateCpeOverviewParams(paged, "type", "ALL").has("page"), false);
});

test("CPE overview rejects unknown query fields", () => {
  assert.throws(() => updateCpeOverviewParams(new URLSearchParams(), "unsupported", "x"));
});
