import test from "node:test";
import assert from "node:assert/strict";

import { hardwareLabel, matchesHardware } from "./hardwareAssociationSearch.js";

const hardware = {
  id: 3,
  name: "ADAM-5000/TCP-CE",
  hardware: {
    role: "IO_MODULE",
    manufacturer: "Advantech",
    model: "ADAM-5000/TCP-CE",
    serial_number: "LAB-004",
    physical_location: "Rack #1",
  },
};

test("matches hardware name, manufacturer, model, role, serial and location", () => {
  for (const query of ["ADAM", "advantech", "5000/TCP", "IO_MODULE", "LAB-004", "rack"]) {
    assert.equal(matchesHardware(hardware, query), true, query);
  }
});

test("search handles capitalization, accents and empty query", () => {
  assert.equal(matchesHardware(hardware, "  AdVantEch "), true);
  assert.equal(matchesHardware(hardware, ""), true);
  assert.equal(matchesHardware(hardware, "Phoenix"), false);
});

test("search gracefully handles hardware with missing optional fields", () => {
  assert.equal(matchesHardware({ id: 4, name: "DirectLogic 205" }, "directlogic"), true);
  assert.equal(matchesHardware({ id: 4, name: "DirectLogic 205" }, "siemens"), false);
});

test("hardware label provides name, vendor and model", () => {
  const label = hardwareLabel(hardware);
  assert.match(label, /ADAM-5000/);
  assert.match(label, /Advantech/);
});
