import { useState } from "react";
import {
  createAssetCpeAssociation, updateAssetCpeAssociation,
} from "../api/vulnerabilities";

const ACTIONS = [
  {
    status: "CONFIRMED", label: "Seleccionar CPE",
    title: "Confirmar asociación CPE", submit: "Confirmar asociación",
    tone: "confirm", explanation: "Se asociará este CPE oficial con el hardware inventariado.",
  },
  {
    status: "REJECTED", label: "Rechazar candidato",
    title: "Confirmar rechazo", submit: "Confirmar rechazo",
    tone: "reject", explanation: "El CPE quedará rechazado para este activo. La decisión se conserva.",
  },
  {
    status: "PENDING", label: "Dejar pendiente",
    title: "Guardar para revisión", submit: "Guardar pendiente",
    tone: "pending", explanation: "Se registrará como pendiente, sin confirmar su aplicabilidad.",
  },
  {
    status: "REOPENED", label: "Reabrir revisión",
    title: "Retirar decisión actual", submit: "Reabrir revisión",
    tone: "reopen", explanation: "La decisión se retirará y el CPE volverá a candidatos. El historial no se borra.",
  },
];

export default function CandidateCpeReview({
  candidate, assetId, run, association, allowed, onReviewed,
}) {
  const [editing, setEditing] = useState(false);
  const [selection, setSelection] = useState(null);
  const [justification, setJustification] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  const reviewed = Boolean(association && association.validation_status !== "REOPENED");
  const canEvaluate = allowed && Boolean(candidate) &&
    run?.status === "COMPLETED" && run.identity_is_current;
  // Re-opening withdraws an existing judgement and does not need a new NVD run.
  const canReopen = allowed && reviewed;
  const hasNewEvidence = reviewed && canEvaluate &&
    (association.source_run_id !== run.id || association.needs_review);
  const available = ACTIONS.filter(item =>
    item.status === "REOPENED" ? canReopen
      : canEvaluate && (!reviewed || association.validation_status !== item.status || hasNewEvidence)
  );
  const action = available.find(item => item.status === selection);
  const revalidating = Boolean(action && reviewed &&
    association.validation_status === action.status);

  function choose(status) {
    setSelection(status);
    setJustification("");
    setError("");
    setMessage("");
  }

  function cancel() {
    setSelection(null);
    setJustification("");
    setError("");
  }

  async function saveDecision() {
    if (!action || busy) return;
    setBusy(true);
    setError("");
    setMessage("");
    try {
      const payload = action.status === "REOPENED"
        ? { status: "REOPENED", justification: justification.trim() }
        : {
            run_id: run.id, cpe_name_id: candidate.cpe_name_id,
            status: action.status, justification: justification.trim(),
          };
      if (association) {
        await updateAssetCpeAssociation(assetId, association.id, payload);
      } else {
        await createAssetCpeAssociation(assetId, payload);
      }
      await onReviewed();
      setSelection(null);
      setJustification("");
      setEditing(false);
      setMessage("Decisión guardada en el historial.");
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return <div className="cpe-review-form">
    {reviewed && !editing && !selection && canReopen && (
      <button className="cpe-decision-button cpe-decision-edit" type="button"
        onClick={() => { setEditing(true); setMessage(""); }}>
        Cambiar decisión
      </button>
    )}
    {(!reviewed || editing) && !action && (
      <div className="cpe-review-actions" role="group" aria-label="Acciones CPE disponibles">
        {available.map(item => <button key={item.status} type="button"
          className={"cpe-decision-button cpe-decision-" + item.tone}
          disabled={busy} onClick={() => choose(item.status)}>
          {hasNewEvidence && item.status === association?.validation_status
            ? "Revalidar " + (item.status === "CONFIRMED" ? "confirmación"
              : item.status === "REJECTED" ? "rechazo" : "pendiente")
            : item.label}
        </button>)}
        {reviewed && editing && <button type="button"
          className="cpe-decision-button cpe-decision-cancel"
          onClick={() => setEditing(false)}>Cancelar edición</button>}
      </div>
    )}
    {action && <div className="cpe-review-confirmation" data-tone={action.tone}>
      <h4>{revalidating ? "Revalidar CPE con nueva evidencia" : action.title}</h4>
      <p>{revalidating
        ? "Una búsqueda nueva contiene este CPE. Confirma de nuevo su aplicabilidad; el historial anterior permanecerá."
        : action.explanation}</p>
      <label htmlFor={"cpe-reason-" + (candidate?.cpe_name_id || association?.cpe_name_id)}>
        Justificación <span className="cpe-optional">(opcional)</span>
      </label>
      <textarea
        id={"cpe-reason-" + (candidate?.cpe_name_id || association?.cpe_name_id)}
        maxLength={1000} value={justification} disabled={busy}
        placeholder="Puedes registrar la evidencia o el motivo de tu decisión."
        onChange={event => { setJustification(event.target.value); setError(""); }}
      />
      <div className="cpe-review-actions">
        <button type="button"
          className={"cpe-decision-button cpe-decision-" + action.tone}
          disabled={busy} onClick={saveDecision}>
          {busy ? "Guardando..." : action.submit}
        </button>
        <button type="button" className="cpe-decision-button cpe-decision-cancel"
          disabled={busy} onClick={cancel}>Cancelar</button>
      </div>
    </div>}
    {!allowed && <p className="cpe-hint">Solo un analista o administrador puede guardar decisiones.</p>}
    {allowed && !canEvaluate && !reviewed && <p className="cpe-hint">
      La búsqueda debe estar finalizada y corresponder a la identidad técnica actual
      antes de confirmar, rechazar o dejar pendiente.
    </p>}
    {allowed && reviewed && !canEvaluate && <p className="cpe-hint">
      Para cambiar la aplicabilidad se necesita una búsqueda vigente.
      Puedes reabrir esta revisión sin consultar NVD.
    </p>}
    {error && <p className="cpe-review-form-error" role="alert">{error}</p>}
    {message && <p className="cpe-hint" role="status">{message}</p>}
  </div>;
}
