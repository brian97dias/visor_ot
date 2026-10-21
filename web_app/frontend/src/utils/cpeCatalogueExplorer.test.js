import test from "node:test";
import assert from "node:assert/strict";
import {
  classificationLabel, isReviewableCatalogueRow, preferredCatalogueSnapshot,
  normalizeIdentity, statusLabel, toCatalogueQuery,
} from "./cpeCatalogueExplorer.js";

test("Phoenix Contact prefers the completed phoenixcontact catalogue, not empty snapshot", () => {
  const snapshots = [
    {id:1, parameter:"cpe:2.3:h:phoenix_contact", status:"COMPLETED", stored_products:0},
    {id:2, parameter:"cpe:2.3:h:phoenixcontact", status:"COMPLETED", stored_products:327},
    {id:3, parameter:"cpe:2.3:h:siemens", status:"COMPLETED", stored_products:3},
  ];
  assert.equal(preferredCatalogueSnapshot(snapshots, "Phoenix Contact"), 2);
  assert.equal(preferredCatalogueSnapshot(snapshots, "Siemens"), 3);
  assert.equal(preferredCatalogueSnapshot([], "Siemens"), null);
  assert.equal(normalizeIdentity("Phoenix-Contact"), "phoenixcontact");
});

test("query parsing preserves typed filters and resets to requested cursor", () => {
  assert.deepEqual(toCatalogueQuery({
    view:"EXCLUDED", q:"  FL IL 24  ", cpe_type:"h", deprecated:"NO", limit:25,
  }, 35), {view:"EXCLUDED", q:"FL IL 24", cpe_type:"h", deprecated:"NO", limit:25, after:35});
  assert.match(classificationLabel("OTHER_VENDOR"), /Fabricante/);
  assert.equal(statusLabel("FAILED"), "Fallida");
});

test("only persisted hardware in a completed snapshot can be selected", () => {
  assert.equal(isReviewableCatalogueRow({cpe_type:"h",evidence_id:3},true,true),true);
  assert.equal(isReviewableCatalogueRow({cpe_type:"o",evidence_id:3},true,true),false);
  assert.equal(isReviewableCatalogueRow({cpe_type:"h",evidence_id:3},false,true),false);
  assert.equal(isReviewableCatalogueRow({cpe_type:"h",evidence_id:3},true,false),false);
});
