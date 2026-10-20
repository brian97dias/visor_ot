import test from "node:test";
import assert from "node:assert/strict";
import { nvdReferenceUrl, displayNvdReferences } from "./nvdReferences.js";

test("only official Product type is shown, not Advisory or unrelated", () => {
  const refs = displayNvdReferences([
    {url:"https://cert-portal.siemens.com/productcert/pdf/ssa-232418.pdf",type:"Advisory",source:"NVD"},
    {url:"https://www.siemens.com/products/plc",type:"Product",source:"NVD"},
    {url:"https://www.example.org/info",type:"Change Log",source:"NVD"},
    {url:"https://www.siemens.com/products/plc",type:"PRODUCT",source:"NVD"},
  ]);
  assert.equal(refs.length, 1);
  assert.equal(refs[0].group, "Producto");
  assert.equal(refs[0].type, "Producto");
  assert.equal(refs[0].url, "https://www.siemens.com/products/plc");
});
test("untrusted stored destinations never become clickable", () => {
  for (const url of [
    "javascript:alert(1)", "data:text/html,test", "http://siemens.com",
    "https://127.0.0.1/admin", "https://localhost/admin",
    "https://private.internal/config", "https://user:pass@siemens.com",
    "https://evil.test/info", "https://[::1]/",
    "https://siemens.com\nbad", "https://siemens.com:8443/",
  ]) {
    assert.equal(nvdReferenceUrl(url), null, url);
  }
});

test("legacy missing links, duplicate URLs and invalid shapes are harmless", () => {
  assert.deepEqual(displayNvdReferences(null), []);
  assert.deepEqual(displayNvdReferences({url:"https://siemens.com"}), []);
  const refs = displayNvdReferences([
    {url:"https://new.siemens.com/info",type:"Product"},
    {url:"https://new.siemens.com/info",type:"Advisory"},
    {url:"javascript:alert(1)",type:"Advisory"},
    null, "invalid", {},
  ]);
  assert.equal(refs.length, 1);
  assert.equal(refs[0].group, "Producto");
});
