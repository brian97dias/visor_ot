import assert from "node:assert/strict";
import { test } from "node:test";
import { canManageSystems, systemPayload, systemFormValues, filterSystems } from "./systemUi.js";
import { getBackNavigation, navigationFromLocation } from "./returnNavigation.js";
import { updateListParams } from "./listUrlState.js";

test("empty system form defaults to undefined criticality", () => {
  assert.equal(systemFormValues().criticality, "UNDEFINED");
  assert.equal(systemFormValues().name, "");
});
test("payload trims name and other text", () => {
  const payload = systemPayload({
    name: " 4SICS ", description: " prueba ", criticality: "HIGH",
    criticality_justification: " justificación ", impact: " parada ",
  });
  assert.equal(payload.name, "4SICS");
  assert.equal(payload.impact, "parada");
});
test("list filters match names and descriptions, case-insensitively", () => {
  const rows = [
    { id: 1, name: "4SICS", description: "Laboratorio", criticality: "UNDEFINED" },
    { id: 2, name: "Bombeo", description: "Agua", criticality: "HIGH" },
  ];
  assert.deepEqual(filterSystems(rows,{search:"labo"}).map(s=>s.id), [1]);
  assert.deepEqual(filterSystems(rows,{criticality:"HIGH"}).map(s=>s.id), [2]);
});
test("operator and admin can manage systems, analyst cannot", () => {
  assert.equal(canManageSystems({role:"ADMIN"}),true);
  assert.equal(canManageSystems({role:"OPERATOR"}),true);
  assert.equal(canManageSystems({role:"ANALYST"}),false);
});
test("systems URL filters and pagination survive detail navigation", () => {
  const params = new URLSearchParams("status=ARCHIVED&q=4SICS&page=2");
  const ctx = navigationFromLocation({pathname:"/assets/systems",search:"?"+params});
  assert.equal(getBackNavigation({state:ctx}).to,"/assets/systems?"+params);
  const changed=updateListParams(params,"q","bombeo",{defaultValue:""});
  assert.equal(changed.get("status"),"ARCHIVED");
  assert.equal(changed.has("page"),false);
});
