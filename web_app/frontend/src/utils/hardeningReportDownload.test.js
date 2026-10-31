import assert from "node:assert/strict";
import test from "node:test";

import { reportFilename, reportErrorMessage } from "./hardeningReportDownload.js";

test("uses server-provided PDF filename without a path", () => {
  assert.equal(
    reportFilename('attachment; filename="VISOR_OT_diagnostico_20261031_151600.pdf"'),
    "VISOR_OT_diagnostico_20261031_151600.pdf",
  );
  assert.equal(reportFilename("attachment; filename=VISOR_OT_diagnostico.pdf"),
    "VISOR_OT_diagnostico.pdf");
});

test("rejects unsupported or dangerous filename headers", () => {
  for (const header of [
    null, "", 'attachment; filename="../../etc/passwd"',
    'attachment; filename="something.exe"',
    'attachment; filename="sub/dir/report.pdf"',
  ]) {
    assert.equal(reportFilename(header), "VISOR_OT_diagnostico.pdf");
  }
});

test("renders DRF validation and authorization errors understandably", () => {
  assert.equal(reportErrorMessage({
    inventory: ["Se requiere criticidad en el dispositivo activo."],
  }, 400), "Se requiere criticidad en el dispositivo activo.");
  assert.equal(reportErrorMessage({
    detail: "La generación del informe no acepta parámetros.",
  }, 400), "La generación del informe no acepta parámetros.");
  assert.match(reportErrorMessage(null, 401), /sesión/);
  assert.match(reportErrorMessage(null, 403), /permiso/);
  assert.match(reportErrorMessage(null, 500), /500/);
});
