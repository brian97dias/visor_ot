import test from "node:test";
import assert from "node:assert/strict";

import { matchesSoftware, softwareLabel } from "./softwareSearch.js";
import {
  buildInstalledSoftwarePayload, validateNewSoftware,
} from "./softwareRegistration.js";
import { validateSoftwareCorrection } from "./softwareCorrection.js";

const installed = {
  id: 4,
  name: "Firmware FL IL 24 BK-PAC",
  software: {
    software_type: "FIRMWARE",
    manufacturer: "Phoenix Contact",
    product: "Firmware FL IL 24 BK-PAC",
    version: "1.23",
  },
};

const emptyRegistration = () => ({
  name: "  Firmware ADAM 5000  ",
  description: "  Módulo OT  ",
  criticality: "UNDEFINED",
  impact: "",
  replacement_cost: "",
  replacement_currency: "",
  software: {
    software_type: "FIRMWARE",
    manufacturer: "  ADVANTECH  ",
    product: "  Firmware ADAM-5000  ",
    version: "",
  },
});

test("search uses name, manufacturer, product and version", () => {
  for (const text of ["fi", "Phoenix Contact", "FLIL24", "1.23", "FIRMWARE"]) {
    assert.equal(matchesSoftware(installed, text), true, text);
  }
  assert.equal(matchesSoftware(installed, "DirectLogic"), false);
  assert.equal(matchesSoftware(installed, ""), true);
});

test("option label includes its identity and version", () => {
  assert.match(softwareLabel(installed), /Firmware FL IL 24 BK-PAC/);
  assert.match(softwareLabel(installed), /1.23/);
});

test("an inline registration needs its hardware and required fields", () => {
  const form = emptyRegistration();
  assert.equal(validateNewSoftware(form, 3), null);
  assert.match(validateNewSoftware(form, null), /hardware/);
  form.name = "  ";
  assert.match(validateNewSoftware(form, 3), /nombre/);
  form.name = "Firmware";
  form.software.product = "";
  assert.match(validateNewSoftware(form, 3), /producto/);
});

test("cost and currency must be consistent", () => {
  const form = emptyRegistration();
  form.replacement_cost = "120.00";
  assert.match(validateNewSoftware(form, 3), /moneda/);
  form.replacement_currency = "USD";
  assert.equal(validateNewSoftware(form, 3), null);
  form.replacement_cost = "";
  assert.match(validateNewSoftware(form, 3), /costo/);
});

test("payload registers SOFTWARE and its first installation atomically", () => {
  const form = emptyRegistration();
  const payload = buildInstalledSoftwarePayload(form, 3);
  assert.equal(payload.hardware_asset_id, 3);
  assert.equal(payload.asset_type, "SOFTWARE");
  assert.equal(payload.name, "Firmware ADAM 5000");
  assert.equal(payload.description, "Módulo OT");
  assert.equal(payload.replacement_cost, null);
  assert.equal(payload.software.manufacturer, "ADVANTECH");
  assert.equal(payload.software.product, "Firmware ADAM-5000");
  assert.equal(payload.software.version, "");
  assert.equal("hardware" in payload, false);
  assert.equal("interface_assignment" in payload, false);
});

test("zero is preserved as a declared replacement cost", () => {
  const form = emptyRegistration();
  form.replacement_cost = "0";
  form.replacement_currency = "COP";
  const payload = buildInstalledSoftwarePayload(form, 3);
  assert.equal(payload.replacement_cost, "0");
  assert.equal(payload.replacement_currency, "COP");
});

test("software correction: missing reason is tied to the reason field", () => {
  const context = {
    changeType: "CORRECTION",
    reason: "",
    history: { active_installation_count: 1 },
    historyError: "",
    confirmShared: false,
  };
  assert.deepEqual(validateSoftwareCorrection(context), {
    field: "reason", message: "Explica el motivo de la corrección técnica.",
  });
  // Typing into a different field such as impact is not a correction reason.
  assert.deepEqual(validateSoftwareCorrection({ ...context, reason: "   " }), {
    field: "reason", message: "Explica el motivo de la corrección técnica.",
  });
  assert.equal(validateSoftwareCorrection({
    ...context, reason: "  Ajuste de nombre para correlación NVD  ",
  }), null);
});

test("software correction: preserved rules for update and shared installations", () => {
  const context = {
    changeType: "CORRECTION",
    reason: "Error de transcripción",
    history: { active_installation_count: 2 },
    historyError: "",
    confirmShared: false,
  };
  assert.match(validateSoftwareCorrection(context).message, /compartida/);
  assert.equal(validateSoftwareCorrection({ ...context, confirmShared: true }), null);
  assert.match(validateSoftwareCorrection({ ...context, history: null }).message, /Espera/);
  assert.match(validateSoftwareCorrection({
    ...context, historyError: "No disponible",
  }).message, /No se pudo consultar/);
  assert.match(validateSoftwareCorrection({
    ...context, changeType: "UPGRADE",
  }).message, /nueva variante/);
});
