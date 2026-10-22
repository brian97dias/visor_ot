import test from "node:test";
import assert from "node:assert/strict";
import {
  normalizedCpeUuid, externalCpeStatus, externalCpeEvidence,
  canReviewExternalCpe, externalCpeAssociation,
} from "./externalCpeUi.js";

const uuid = "a47a92dc-5510-4c51-a59c-a0b3162ec512";
const record = {
  cpe_name_id: uuid, cpe_name: "cpe:2.3:h:siemens:simatic_s7_1200:*:*:*:*:*:*:*:*",
  title: "Siemens SIMATIC S7-1200",
};
const verified = {
  id: 27, status: "COMPLETED", verification_status: "VERIFIED",
  identity_is_current: true, candidates: [record],
};

test("only well-formed official UUID inputs may be submitted", () => {
  assert.equal(normalizedCpeUuid(" " + uuid.toUpperCase() + " "), uuid);
  for (const value of ["", "bad", "cpe:2.3:h:siemens", uuid + "-extra",
    "00000000-0000-0000-0000-00000000000x"]) {
    assert.equal(normalizedCpeUuid(value), "", value);
  }
});

test("worker states and definitive NVD outcomes have distinct display names", () => {
  assert.equal(externalCpeStatus({status:"QUEUED"}), "En cola");
  assert.equal(externalCpeStatus({status:"RUNNING"}), "Consultando NVD");
  assert.equal(externalCpeStatus({status:"FAILED"}), "Error de verificación");
  assert.equal(externalCpeStatus(verified), "Verificado en NVD");
  assert.equal(externalCpeStatus({...verified, verification_status:"NOT_FOUND"}),
    "No encontrado en NVD");
  assert.equal(externalCpeStatus({...verified, verification_status:"INCOMPATIBLE_PART"}),
    "Tipo CPE incompatible");
});

test("hardware, firmware and applications use the same verified result UI", () => {
  for (const cpeName of [
    "cpe:2.3:h:siemens:simatic_s7_1200:*:*:*:*:*:*:*:*",
    "cpe:2.3:o:cisco:ios:12.1:*:*:*:*:*:*:*",
    "cpe:2.3:a:example:app:1.0:*:*:*:*:*:*:*",
  ]) {
    const value = {...verified, candidates:[{...record,cpe_name:cpeName}]};
    assert.equal(externalCpeEvidence(value)?.cpe_name, cpeName);
    assert.equal(canReviewExternalCpe(value, true), true);
    assert.equal(canReviewExternalCpe(value, false), false);
  }
});

test("not found, failed and wrong CPE part never expose a review action", () => {
  const incompatible = {...verified,verification_status:"INCOMPATIBLE_PART",
    candidates:[], queries:[{official_cpe:record}]};
  assert.deepEqual(externalCpeEvidence(incompatible), record);
  assert.equal(canReviewExternalCpe(incompatible,true), false);
  assert.equal(externalCpeEvidence({...verified,verification_status:"NOT_FOUND"}), null);
  assert.equal(canReviewExternalCpe({...verified,status:"FAILED"},true), false);
  assert.equal(canReviewExternalCpe({...verified,identity_is_current:false},true), false);
  assert.equal(canReviewExternalCpe({...verified,candidates:[]},true), false);
});

test("previously reviewed CPE is selected by UUID regardless of casing", () => {
  const association = {id:5,cpe_name_id:uuid.toUpperCase(),validation_status:"CONFIRMED"};
  assert.deepEqual(externalCpeAssociation([association],record), association);
  assert.equal(externalCpeAssociation([association],{...record,cpe_name_id:"other"}),null);
});
