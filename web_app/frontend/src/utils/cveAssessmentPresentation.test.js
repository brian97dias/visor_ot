import test from "node:test";
import assert from "node:assert/strict";
import {
  CVE_STATUS, EXPERIMENT_CVE_ID, EXPERIMENT_HARDWARE_ID,
  latestEffectiveStatus, currentCriterionEvidence, submissionGuard,
  advisoryOutcome, cpePartLabel, versionConstraintsText, localizedTimestamp,
  selectedFirmwareInstallation, proposedFirmwareDecision, experimentalDescription,
  nvdCveDetailUrl, nvdVulnerabilitiesByCpeUrl, nvdCvesApiByCpeNameUrl,
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
  assert.equal(submissionGuard(context(), form({
    software_installation_id:"", firmware_verdict:"UNKNOWN"
  })), "");
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

test("one current installation is automatically identified as evidence, not accepted as a CVE match", () => {
  const info = context();
  assert.equal(selectedFirmwareInstallation(info, "").installation_id, 4);
  const pending = proposedFirmwareDecision(info, "UNKNOWN", "", "No hay evidencia");
  assert.equal(pending.software_installation_id, 4);
  assert.equal(pending.firmware_verdict, "UNKNOWN");
  assert.equal(advisoryOutcome(info, pending), "PENDING_REVIEW");
  assert.equal(submissionGuard(info, pending), "");
});

test("multiple installed firmware candidates require an explicit selection", () => {
  const info = context({active_firmware_installations:[
    installment, {installation_id:8, software_asset_id:10},
  ]});
  assert.equal(selectedFirmwareInstallation(info, ""), null);
  assert.equal(selectedFirmwareInstallation(info, "8").installation_id, 8);
  assert.equal(selectedFirmwareInstallation(info, "99"), null);
  const unselected = proposedFirmwareDecision(info, "CONFIRMED", "", "Comprobé");
  assert.equal(unselected.software_installation_id, null);
  assert.match(submissionGuard(info, unselected), /Selecciona/);
  assert.equal(advisoryOutcome(info, unselected), "PENDING_REVIEW");
});

test("not found means no installation and forbids confirmation, while uncertainty remains recordable", () => {
  const info = context({active_firmware_installations:[]});
  assert.equal(selectedFirmwareInstallation(info, ""), null);
  const confirm = proposedFirmwareDecision(info, "CONFIRMED", "", "Comprobé");
  assert.match(submissionGuard(info, confirm), /Selecciona/);
  const pending = proposedFirmwareDecision(info, "UNKNOWN", "", "No hay instalación registrada");
  assert.equal(submissionGuard(info, pending), "");
  assert.equal(advisoryOutcome(info, pending), "PENDING_REVIEW");
});

test("negative firmware evidence does not silently declare NOT_APPLICABLE", () => {
  const info = context();
  const negative = proposedFirmwareDecision(info, "NOT_MATCH", "",
    "Inspección técnica", "DOCUMENTATION", false);
  assert.equal(negative.software_installation_id, 4);
  assert.equal(negative.evidence_source, "DOCUMENTATION");
  assert.equal(negative.inventory_declared_complete, false);
  assert.equal(advisoryOutcome(info, negative), "PENDING_REVIEW");
  const attested = proposedFirmwareDecision(info, "NOT_MATCH", "",
    "Inventario completo comprobado", "SIMULATION", true);
  assert.equal(advisoryOutcome(info, attested), "NOT_APPLICABLE");
  const notMatchWithoutCheckbox = proposedFirmwareDecision(info, "CONFIRMED", "",
    "Verificado", "DOCUMENTATION", true);
  assert.equal(notMatchWithoutCheckbox.inventory_declared_complete, false);
});

test("the specific NVD description has a clearly identified unofficial Spanish translation", () => {
  const english = "In certain devices of the Phoenix Contact AXL F BK and IL BK product families an undocumented password protected FTP access to the root directory exists.";
  const result = experimentalDescription("CVE-2021-33540", english);
  assert.match(result.text, /acceso FTP no documentado/);
  assert.match(result.label, /no oficial/);
  assert.equal(result.original, english);
  assert.equal(experimentalDescription("CVE-2021-99999", english).text, english);
  assert.equal(experimentalDescription("CVE-2021-33540", "Another text").text, "Another text");
});

test("official Spanish from stored NVD descriptions takes priority over local translation", () => {
  const english = "In certain devices of the Phoenix Contact AXL F BK and IL BK product families an undocumented password protected FTP access exists.";
  const data = [
    { lang: "en", value: english },
    { lang: "es", value: "Descripción en español procedente de NVD." },
  ];
  const result = experimentalDescription("CVE-2021-33540", english, data);
  assert.equal(result.text, "Descripción en español procedente de NVD.");
  assert.match(result.label, /oficial en español/);
  assert.equal(result.original, english);
  const onlyEn = experimentalDescription("CVE-2021-33540", english, [data[0]]);
  assert.match(onlyEn.label, /no oficial/);
  assert.equal(experimentalDescription("CVE-2021-33540", english, []).original, english);
  assert.equal(experimentalDescription("CVE-2021-33540", english, {}).original, english);
});

test("official NVD CVE title opens vulnerability detail, CPE opens separate CPE-search UI", () => {
  const cpe = "cpe:2.3:h:phoenixcontact:il_pn_bk-pac:-:*:*:*:*:*:*:*";
  assert.equal(nvdCveDetailUrl("CVE-2021-33540"),
    "https://nvd.nist.gov/vuln/detail/CVE-2021-33540");
  const searchUrl = nvdVulnerabilitiesByCpeUrl(cpe);
  assert.ok(searchUrl.startsWith("https://nvd.nist.gov/vuln/search/results?"));
  assert.equal(decodeURIComponent(searchUrl.split("&query=")[1]), cpe);
  assert.match(searchUrl, /isCpeNameSearch=true/);
  assert.equal(nvdCveDetailUrl("invalid-id"), null);
  assert.equal(nvdVulnerabilitiesByCpeUrl("cpe:2.3:h:vendor:item:*:*:*:*:*:*:*:*"), null);
  assert.equal(nvdVulnerabilitiesByCpeUrl("not a cpe"), null);
});

test("CVE view links directly to NVD CVE API using the exact CPE name", () => {
  const cpe = "cpe:2.3:h:phoenixcontact:il_pn_bk-pac:-:*:*:*:*:*:*:*";
  const url = nvdCvesApiByCpeNameUrl(cpe);
  assert.ok(url.startsWith("https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName="));
  assert.equal(url,
    "https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=" + cpe);
  assert.equal(decodeURIComponent(url.split("?cpeName=")[1]), cpe);
  assert.equal(nvdCvesApiByCpeNameUrl("not a CPE"), null);
  assert.equal(nvdCvesApiByCpeNameUrl("cpe:2.3:h:vendor:product:*:*:*:*:*:*:*:*"), null);
});

test("CVE API query preserves one cpeName parameter even with reserved delimiters", () => {
  const unusualCpe = "cpe:2.3:h:vendor:product&debug=true:-:*:*:*:*:*:*:*";
  const url = nvdCvesApiByCpeNameUrl(unusualCpe);
  assert.ok(url.includes("product%26debug%3Dtrue"));
  assert.equal(decodeURIComponent(url.split("?cpeName=")[1]), unusualCpe);
});
