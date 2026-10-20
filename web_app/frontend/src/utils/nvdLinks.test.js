import test from "node:test";
import assert from "node:assert/strict";
import { nvdQueryUrl, nvdCpeUrl, NVD_PAGE_SIZE } from "./nvdLinks.js";

test("NVD query URLs retain each strategy and proper pagination", () => {
  const q = { strategy: "cpeMatchString", parameter: "cpe:2.3:h:siemens:s7_1200_cpu_1215c*" };
  const one = new URL(nvdQueryUrl(q));
  const next = new URL(nvdQueryUrl(q, 1));
  assert.equal(one.host, "services.nvd.nist.gov");
  assert.equal(one.searchParams.get("cpeMatchString"), q.parameter);
  assert.equal(one.searchParams.get("startIndex"), "0");
  assert.equal(next.searchParams.get("startIndex"), String(NVD_PAGE_SIZE));
  assert.equal(next.searchParams.get("resultsPerPage"), "100");
  const kw = new URL(nvdQueryUrl({strategy:"keywordSearch", parameter:"Siemens CPU 1215C"}));
  assert.equal(kw.searchParams.get("keywordSearch"), "Siemens CPU 1215C");
});

test("CPE UUID returns a direct official NVD lookup URL", () => {
  const uuid = "09F448D2-F606-44AB-8891-C27A3FF64002";
  assert.equal(new URL(nvdCpeUrl(uuid)).searchParams.get("cpeNameId"), uuid);
  assert.equal(nvdCpeUrl("javascript:alert(1)"), null);
  assert.equal(nvdQueryUrl({strategy:"unknown",parameter:"x"}), null);
  assert.equal(nvdQueryUrl({strategy:"keywordSearch",parameter:"x"}, -1), null);
});
