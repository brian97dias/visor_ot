import { useState } from "react";
import {
  createAssetCpeAssociation, updateAssetCpeAssociation,
} from "../api/vulnerabilities";

const labels = { CONFIRMED: "Confirmado", REJECTED: "Rechazado", PENDING: "Pendiente" };

export default function CandidateCpeReview({
  candidate, assetId, run, association, allowed, onReviewed,
}) {
  const [justification, setJustification] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const canDecide = allowed && run.status === "COMPLETED" && run.identity_is_current;

  async function decide(status) {
    if (busy || !canDecide) return;
    const reason = justification.trim();
    if (status !== "PENDING" && !reason) {
      setError("Explica la razón antes de confirmar o rechazar este candidato.");
      return;
    }
    setBusy(true);
    setError("");
    setMessage("");
    try {
      const payload = {
        run_id: run.id,
        cpe_name_id: candidate.cpe_name_id,
        status,
        justification: reason,
      };
      if (association) {
        await updateAssetCpeAssociation(assetId, association.id, payload);
      } else {
        await createAssetCpeAssociation(assetId, payload);
      }
      setJustification("");
      setMessage("Decisión " + labels[status].toLowerCase() + " y guardada en el historial.");
      await onReviewed();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="cpe-review-form">
      {association && (
        <p>
          Decisión actual:{" "}
          <span className="cpe-review-status" data-validation={association.validation_status}>
            {labels[association.validation_status] || association.validation_status}
          </span>
          {association.needs_review && " · Requiere nueva revisión por cambio de identidad"}
        </p>
      )}
      {canDecide ? <>
        <label htmlFor={"cpe-reason-" + candidate.cpe_name_id}>
          Justificación de la decisión (obligatoria al confirmar o rechazar)
        </label>
        <textarea id={"cpe-reason-" + candidate.cpe_name_id}
          maxLength={1000} value={justification} disabled={busy}
          placeholder="Ej. Coinciden fabricante, familia SIMATIC S7-1200 y CPU 1215C"
          onChange={event => {
            setJustification(event.target.value);
            setError("");
          }}/>
        <div className="cpe-review-actions">
          <button type="button" disabled={busy} onClick={() => decide("CONFIRMED")}>
            Confirmar CPE</button>
          <button type="button" disabled={busy} onClick={() => decide("REJECTED")}>
            Rechazar</button>
          <button type="button" disabled={busy} onClick={() => decide("PENDING")}>
            Dejar pendiente</button>
        </div>
      </> : <p className="cpe-hint">
        {!allowed ? "Solo un analista o administrador puede registrar decisiones." :
          !run.identity_is_current ? "La identidad cambió; busca nuevamente antes de validar." :
          "La búsqueda debe finalizar antes de validar los candidatos."}
      </p>}
      {error && <p className="cpe-review-form-error" role="alert">{error}</p>}
      {message && <p className="cpe-hint" role="status">{message}</p>}
    </div>
  );
}
