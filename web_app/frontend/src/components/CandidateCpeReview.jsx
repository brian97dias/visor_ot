import { useState } from "react";
import {
  createAssetCpeAssociation, updateAssetCpeAssociation,
} from "../api/vulnerabilities";

const ACTIONS = [
  {
    status: "CONFIRMED",
    label: "Seleccionar CPE",
    title: "Confirmar asociación CPE",
    submit: "Confirmar asociación",
    tone: "confirm",
    explanation: "Se asociará este CPE oficial con el hardware inventariado.",
  },
  {
    status: "REJECTED",
    label: "Rechazar candidato",
    title: "Confirmar rechazo",
    submit: "Confirmar rechazo",
    tone: "reject",
    explanation: "El candidato quedará descartado para este activo, con una decisión auditable.",
  },
  {
    status: "PENDING",
    label: "Dejar pendiente",
    title: "Guardar para revisión",
    submit: "Guardar pendiente",
    tone: "pending",
    explanation: "El candidato quedará asociado como pendiente, sin considerarse confirmado.",
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
  const canDecide = allowed && Boolean(candidate) &&
    run?.status === "COMPLETED" && run.identity_is_current;
  const action = ACTIONS.find(item => item.status === selection);

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
    if (!action || busy || !canDecide) return;
    setBusy(true);
    setError("");
    setMessage("");
    try {
      const payload = {
        run_id: run.id,
        cpe_name_id: candidate.cpe_name_id,
        status: action.status,
        justification: justification.trim(), // Optional for all three decisions.
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
      if (association) setMessage("Decisión actualizada y guardada en el historial.");
      // A newly reviewed candidate moves into "Asociaciones revisadas" and
      // this component is unmounted; its textarea never remains on screen.
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="cpe-review-form">
      {!canDecide ? (
        <p className="cpe-hint">
          {!allowed ? "Solo un analista o administrador puede registrar decisiones." :
            !run?.identity_is_current ? "La identidad cambió; busca nuevamente antes de validar." :
            !candidate ? "Este CPE no está entre los candidatos de la búsqueda actual." :
            "La búsqueda debe finalizar antes de validar los candidatos."}
        </p>
      ) : <>
        {association && !editing && !selection && (
          <button className="cpe-decision-button cpe-decision-edit" type="button"
            onClick={() => { setEditing(true); setMessage(""); }}>
            Cambiar decisión
          </button>
        )}
        {(!association || editing) && !action && (
          <div className="cpe-review-actions" role="group"
            aria-label={association ? "Nueva decisión para CPE revisado" : "Revisar candidato CPE"}>
            {ACTIONS.map(item => (
              <button key={item.status} type="button"
                className={"cpe-decision-button cpe-decision-" + item.tone}
                disabled={busy} onClick={() => choose(item.status)}>
                {item.label}
              </button>
            ))}
            {association && <button type="button"
              className="cpe-decision-button cpe-decision-cancel"
              onClick={() => setEditing(false)}>Cancelar edición</button>}
          </div>
        )}
        {action && (
          <div className="cpe-review-confirmation" data-tone={action.tone}>
            <h4>{action.title}</h4>
            <p>{action.explanation}</p>
            <label htmlFor={"cpe-reason-" + candidate.cpe_name_id}>
              Justificación <span className="cpe-optional">(opcional)</span>
            </label>
            <textarea id={"cpe-reason-" + candidate.cpe_name_id}
              maxLength={1000} value={justification} disabled={busy}
              placeholder="Puedes registrar la evidencia o el motivo de tu decisión."
              onChange={event => { setJustification(event.target.value); setError(""); }}/>
            <div className="cpe-review-actions">
              <button type="button"
                className={"cpe-decision-button cpe-decision-" + action.tone}
                disabled={busy} onClick={saveDecision}>
                {busy ? "Guardando..." : action.submit}
              </button>
              <button type="button" className="cpe-decision-button cpe-decision-cancel"
                disabled={busy} onClick={cancel}>Cancelar</button>
            </div>
          </div>
        )}
      </>}
      {error && <p className="cpe-review-form-error" role="alert">{error}</p>}
      {message && <p className="cpe-hint" role="status">{message}</p>}
    </div>
  );
}
