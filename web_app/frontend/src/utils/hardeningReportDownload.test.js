import assert from "node:assert/strict";
import test from "node:test";

import { parseHardeningPdfResponse, reportFilename, reportErrorMessage } from "./hardeningReportDownload.js";

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

test("accepts a real binary PDF response and keeps the authenticated filename", async () => {
  const response = new Response("%PDF-1.7\nvalid fixture\n%%EOF", {
    status: 200,
    headers: {
      "Content-Type": "application/pdf",
      "Content-Disposition": 'attachment; filename="VISOR_OT_diagnostico_20261031.pdf"',
    },
  });
  const { blob, filename } = await parseHardeningPdfResponse(response);
  assert.equal(filename, "VISOR_OT_diagnostico_20261031.pdf");
  assert.match(await blob.text(), /^%PDF-/);
});

test("binary response without filename uses safe fallback", async () => {
  const response = new Response("%PDF-1.7\n%%EOF", {
    status: 200, headers: { "Content-Type": "application/pdf" },
  });
  const { filename } = await parseHardeningPdfResponse(response);
  assert.equal(filename, "VISOR_OT_diagnostico.pdf");
});

test("rejects HTML, empty bytes and non-PDF data even on HTTP 200", async () => {
  const invalid = [
    new Response("<html>Error</html>", {
      status: 200, headers: { "Content-Type": "text/html" },
    }),
    new Response("not a PDF", {
      status: 200, headers: { "Content-Type": "application/pdf" },
    }),
    new Response("", {
      status: 200, headers: { "Content-Type": "application/pdf" },
    }),
  ];
  for (const response of invalid) {
    await assert.rejects(
      parseHardeningPdfResponse(response), /PDF/,
    );
  }
});

test("shows JSON validation and unauthorized errors from HTTP responses", async () => {
  for (const [status, detail, fragment] of [
    [400, "Inventario incompleto.", "Inventario incompleto"],
    [403, "Esta operación requiere el rol de administrador o analista.", "administrador"],
  ]) {
    const response = new Response(JSON.stringify({ detail }), {
      status, headers: { "Content-Type": "application/json" },
    });
    await assert.rejects(parseHardeningPdfResponse(response),
      new RegExp(fragment));
  }
  await assert.rejects(parseHardeningPdfResponse(new Response("Bad gateway", {
    status: 502, headers: { "Content-Type": "text/html" },
  })), /502/);
});
