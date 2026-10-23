import test from "node:test";
import assert from "node:assert/strict";
import {
  CVE_STATUS, EXPERIMENT_CVE_ID, EXPERIMENT_HARDWARE_ID,
  latestEffectiveStatus, currentCriterionEvidence, submissionGuard,
  advisoryOutcome, cpePartLabel, versionConstraintsText, localizedTimestamp,
} from "./cveAssessmentPresentation.js";

const installment = {
  installation_id: 4, software_asset_id: 4,
  software_name: "Phoenix Contact IL PN BK-PAC Firmware",
};
const context = ({
  hardware_cpe_confirmed = true,
  active_firmware_installations = [installment],
  criteria_evidence = {
    hardware: {state:"SATISFIED", nvd_vulnerable:false},
    firmware: {state:"UNVERIFIED", nvd_vulnerable:true, version_constraints:{}},
  },
  latest_assessment = null,
} = {}) => ({
  hardware_cpe_confirmed, active_firmware_installations,
  criteria_evidence, latest_assessment,
});
const form = ({
  software_installation_id = "4", firmware_verdict = "CONFIRMED",
  evidence_source = "INVENTORY", inventory_declared_complete = false,
  justification = "Inspección documentada",
} = {}) => ({
  software_installation_id, firmware_verdict, evidence_source,
  inventory_declared_complete, justification,
});

test("experimental scope is fixed and status labels describe only configuration 12", () => {
  assert.equal(EXPERIMENT_CVE_ID, "CVE-2021-33540");
  assert.equal(EXPERIMENT_HARDWARE_ID, 2);
  assert.match(CVE_STATUS.APPLIES, /configuraci[oó]n 12/);
  assert.match(CVE_STATUS.NOT_APPLICABLE, /configuraci[oó]n 12/);
});

test("no decision is automatically inferred from the registered installation", () => {
  const info = context();
  assert.equal(latestEffectiveStatus(info), "PENDING_REVIEW");
  assert.equal(currentCriterionEvidence(info, "firmware").state, "UNVERIFIED");
  assert.equal(advisoryOutcome(info, form({firmware_verdict:"UNKNOWN"})), "PENDING_REVIEW");
  assert.equal(advisoryOutcome(context({hardware_cpe_confirmed:false}), form()),
    "PENDING_REVIEW");
});

test("explicitly confirmed installed firmware can only preview APPLIES with confirmed hardware", () => {
  assert.equal(advisoryOutcome(context(), form()), "APPLIES");
  assert.equal(advisoryOutcome(context({active_firmware_installations:[]}), form()),
    "PENDING_REVIEW");
  assert.equal(advisoryOutcome(context(), form({software_installation_id:""})),
    "PENDING_REVIEW");
});

test("a firmware version constraint blocks a premature positive result", () => {
  const info = context({
    criteria_evidence: {
      firmware: {
        state: "UNVERIFIED",
        version_constraints: {versionEndExcluding:"1.0"},
      },
    },
  });
  assert.equal(advisoryOutcome(info, form()), "PENDING_REVIEW");
  assert.equal(versionConstraintsText(info.criteria_evidence.firmware.version_constraints),
    "Antes de: 1.0");
});

test("negative evidence is not the same as missing information", () => {
  assert.equal(advisoryOutcome(context(), form({firmware_verdict:"NOT_MATCH"})),
    "PENDING_REVIEW");
  assert.equal(advisoryOutcome(context(), form({
    firmware_verdict:"NOT_MATCH", inventory_declared_complete:true,
  })), "NOT_APPLICABLE");
  assert.equal(advisoryOutcome(context({
    active_firmware_installations:[installment,{installation_id:7}],
  }), form({firmware_verdict:"NOT_MATCH", inventory_declared_complete:true})),
  "PENDING_REVIEW");
});

test("form prevents decision against an installation not currently linked", () => {
  assert.match(submissionGuard(context(), form({software_installation_id:"99"})),
    /ya no figura como vigente/);
  assert.match(submissionGuard(context(), form({software_installation_id:""})),
    /Selecciona/);
  assert.equal(submissionGuard(context(), form({software_installation_id:""}).firmware_verdict
    ? form({software_installation_id:"",firmware_verdict:"UNKNOWN"}) : {}), "");
});

test("justification and complete inventory attestation need explicit evidence", () => {
  assert.match(submissionGuard(context(), form({justification:"  "})), /Describe/);
  assert.match(submissionGuard(context(), form({justification:"x".repeat(1001)})), /1000/);
  assert.match(submissionGuard(context(), form({inventory_declared_complete:true})),
    /solo procede/);
  assert.match(submissionGuard(context({
    active_firmware_installations:[installment,{installation_id:7}],
  }),form({firmware_verdict:"NOT_MATCH",inventory_declared_complete:true})), /otros firmwares/);
  assert.equal(submissionGuard(context(),form({
    firmware_verdict:"NOT_MATCH",inventory_declared_complete:true
  })), "");
});

test("stale previous decision is not displayed as current APPLIES", () => {
  const info = context({
    latest_assessment: {
      status:"APPLIES", effective_status:"PENDING_REVIEW", stale:true,
      criteria_evidence:{firmware:{state:"SATISFIED"}},
    },
  });
  assert.equal(latestEffectiveStatus(info), "PENDING_REVIEW");
  assert.equal(currentCriterionEvidence(info, "firmware").state, "UNVERIFIED");
  const fresh = context({
    latest_assessment: {
      effective_status:"APPLIES", stale:false,
      criteria_evidence:{firmware:{state:"SATISFIED"}},
    },
  });
  assert.equal(latestEffectiveStatus(fresh), "APPLIES");
  assert.equal(currentCriterionEvidence(fresh,"firmware").state,"SATISFIED");
});

test("platform match criteria are never advertised as proof of being safe", () => {
  assert.equal(cpePartLabel(false), "Condición de plataforma (NVD)");
  assert.equal(cpePartLabel(true), "Criterio vulnerable (NVD)");
  assert.equal(localizedTimestamp(null), "Sin fecha");
  assert.equal(localizedTimestamp("unknown"), "Fecha no disponible");
});
