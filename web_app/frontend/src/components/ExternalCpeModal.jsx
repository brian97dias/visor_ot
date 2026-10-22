import { useEffect, useRef, useState } from "react";
import {
  getAssetCpeAssociations, listExternalCpeVerifications,
  readExternalCpeVerification, startExternalCpeVerification,
} from "../api/vulnerabilities";
import CandidateCpeReview from "./CandidateCpeReview";
import CpeEvidence from "./CpeEvidence";
import CpeReferences from "./CpeReferences";
import {
  additionalNvdReferences, canReviewExternalCpe, externalCpeAssociation,
  externalCpeEvidence, externalCpeStatus, normalizedCpeUuid,
} from "../utils/externalCpeUi";

const POLL_MS = 5000;
const POLL_LIMIT_MS = 5 * 60 * 1000;
const PENDING = new Set(["QUEUED", "RUNNING"]);

export default function ExternalCpeModal({ asset, allowed, onClose, onReviewed }) {
  const [uuid, setUuid] = useState("");
  const [verifications, setVerifications] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [associations, setAssociations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [pollingPaused, setPollingPaused] = useState(false);
  const [error, setError] = useState("");
  const [historyError, setHistoryError] = useState("");
  const [associationError, setAssociationError] = useState("");
  const firstFocus = useRef(null);
  const dialog = useRef(null);
  const startedPolling = useRef(null);

  const selected = verifications.find(v => v.id === selectedId) || null;
  const pending = PENDING.has(selected?.status);
  const evidence = externalCpeEvidence(selected);
  const candidate = selected?.verification_status === "VERIFIED"
    ? (selected?.candidates || [])[0] || null : null;
  const existing = externalCpeAssociation(associations, candidate);
  const reviewable = canReviewExternalCpe(selected, allowed);

  useEffect(() => {
    let mounted = true;
    Promise.all([
      listExternalCpeVerifications(asset.asset_id),
      getAssetCpeAssociations(asset.asset_id),
    ]).then(([runs, links]) => {
      if (!mounted) return;
      setVerifications(runs);
      setAssociations(links);
      setSelectedId(runs[0]?.id ?? null);
    }).catch(err => {
      if (mounted) setHistoryError("No fue posible recuperar las verificaciones: " + err.message);
    }).finally(() => {
      if (mounted) setLoading(false);
    });
    return () => { mounted = false; };
  }, [asset.asset_id]);

  useEffect(() => { firstFocus.current?.focus(); }, []);

  useEffect(() => {
    function handleKeyDown(event) {
      if (event.key === "Escape" && !submitting) {
        event.preventDefault();
        onClose();
      }
      if (event.key !== "Tab" || !dialog.current) return;
      const items = [...dialog.current.querySelectorAll(
        'button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), a[href]'
      )];
      if (!items.length) return;
      const first = items[0];
      const last = items[items.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    }
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [onClose, submitting]);

  useEffect(() => {
    startedPolling.current = null;
    setPollingPaused(false);
  }, [selectedId]);

  useEffect(() => {
    if (!pending || pollingPaused || selectedId == null) return;
    if (startedPolling.current === null) startedPolling.current = Date.now();
    let active = true;
    const timer = window.setInterval(async () => {
      if (Date.now() - startedPolling.current >= POLL_LIMIT_MS) {
        if (active) setPollingPaused(true);
        return;
      }
      try {
        const latest = await readExternalCpeVerification(asset.asset_id, selectedId);
        if (active) {
          setVerifications(items => items.map(item =>
            item.id === latest.id ? latest : item
          ));
          setError("");
        }
      } catch (err) {
        if (active) {
          setError("No fue posible actualizar el estado: " + err.message);
          setPollingPaused(true);
        }
      }
    }, POLL_MS);
    return () => { active = false; window.clearInterval(timer); };
  }, [asset.asset_id, selectedId, pending, pollingPaused]);

  async function refreshSelected() {
    if (selectedId == null || refreshing) return;
    setRefreshing(true);
    setError("");
    try {
      const latest = await readExternalCpeVerification(asset.asset_id, selectedId);
      setVerifications(items => items.map(item => item.id === latest.id ? latest : item));
      startedPolling.current = Date.now();
      setPollingPaused(false);
    } catch (err) {
      setError("No se pudo consultar el estado: " + err.message);
    } finally {
      setRefreshing(false);
    }
  }

  async function refreshAssociations() {
    const links = await getAssetCpeAssociations(asset.asset_id);
    setAssociations(links);
    setAssociationError("");
    if (selectedId != null) {
      try {
        const latest = await readExternalCpeVerification(asset.asset_id, selectedId);
        setVerifications(items => items.map(item => item.id === latest.id ? latest : item));
      } catch {
        // Decision and association history are stored even if refreshing this view fails.
      }
    }
    await onReviewed?.();
  }

  async function verify(event) {
    event.preventDefault();
    const canonical = normalizedCpeUuid(uuid);
    if (!canonical) {
      setError("Ingresa un cpeNameId válido con formato UUID, por ejemplo 8-4-4-4-12.");
      return;
    }
    if (!allowed || submitting) return;
    setSubmitting(true);
    setError("");
    setHistoryError("");
    try {
      const started = await startExternalCpeVerification(asset.asset_id, canonical);
      // The request is persisted even if the subsequent read fails.
      const latest = await readExternalCpeVerification(asset.asset_id, started.run_id);
      setVerifications(items => [
        latest, ...items.filter(item => item.id !== latest.id),
      ].slice(0, 30));
      setSelectedId(latest.id);
      setUuid("");
      startedPolling.current = Date.now();
      setPollingPaused(false);
    } catch (err) {
      setError("La solicitud podría haber quedado en cola. Consulta las verificaciones guardadas. " +
        err.message);
      try {
        const stored = await listExternalCpeVerifications(asset.asset_id);
        setVerifications(stored);
        if (stored.length) setSelectedId(stored[0].id);
      } catch {
        // Keep the original error; a later opening will retrieve the saved job.
      }
    } finally {
      setSubmitting(false);
    }
  }

  function selectRun(event) {
    const id = Number(event.target.value);
    setSelectedId(Number.isSafeInteger(id) && id > 0 ? id : null);
    setError("");
    setAssociationError("");
  }

  return <div className="cpe-bulk-overlay cpe-uuid-overlay">
    <section ref={dialog} className="cpe-bulk-dialog cpe-uuid-dialog"
      role="dialog" aria-modal="true"
      aria-labelledby="cpe-uuid-title" aria-describedby="cpe-uuid-description">
      <header className="cpe-bulk-dialog-heading">
        <div>
          <span className="page-eyebrow">IDENTIFICACIÓN CPE</span>
          <h2 id="cpe-uuid-title">Agregar CPE por ID</h2>
        </div>
        <button type="button" className="cpe-bulk-close"
          aria-label="Cerrar formulario" disabled={submitting} onClick={onClose}>×</button>
      </header>
      <p id="cpe-uuid-description">
        Activo <strong>{asset.asset_name}</strong> · #{asset.asset_id} ·
        {" "}{asset.asset_type === "HARDWARE" ? "Hardware" : "Software"}.
        Verificar un UUID en NVD no confirma su asociación.
      </p>
      <form onSubmit={verify} className="cpe-uuid-form">
        <label htmlFor="external-cpe-uuid">Identificador oficial NVD (cpeNameId)</label>
        <div className="cpe-uuid-input-row">
          <input id="external-cpe-uuid" ref={firstFocus} type="text"
            inputMode="text" autoComplete="off" spellCheck="false"
            maxLength={36} value={uuid} disabled={!allowed || submitting}
            placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
            aria-describedby="cpe-uuid-help"
            onChange={e => { setUuid(e.target.value); setError(""); }}/>
          <button className="button-primary" type="submit"
            disabled={!allowed || submitting || !normalizedCpeUuid(uuid)}>
            {submitting ? "Registrando..." : "Verificar CPE"}
          </button>
        </div>
        <p id="cpe-uuid-help" className="cpe-hint">
          Introduce el UUID, no la cadena cpe:2.3. La verificación se realizará
          mediante el worker NVD, sin bloquear la aplicación.
        </p>
        {uuid.trim() && !normalizedCpeUuid(uuid) && <p className="cpe-review-form-error"
          role="status">El identificador debe tener el formato UUID 8-4-4-4-12.</p>}
      </form>
      {!allowed && <p className="cpe-warning">
        Solo los analistas y administradores pueden solicitar verificaciones o registrar decisiones.
      </p>}
      {error && <p className="error-message" role="alert">{error}</p>}
      {historyError && <p className="error-message" role="alert">{historyError}</p>}

      <section className="cpe-uuid-history" aria-label="Verificaciones guardadas">
        <h3>Verificaciones del activo</h3>
        {loading ? <p>Cargando historial...</p> : verifications.length === 0
          ? <p>Aún no hay verificaciones por UUID para este activo.</p>
          : <>
            <label htmlFor="cpe-uuid-saved">Verificación guardada</label>
            <select id="cpe-uuid-saved" value={selectedId ?? ""}
              onChange={selectRun}>
              {verifications.map(item => (
                <option key={item.id} value={item.id}>
                  #{item.id} · {item.queries?.[0]?.parameter || "UUID"} · {externalCpeStatus(item)}
                </option>
              ))}
            </select>
          </>}
      </section>

      {selected && <section className="cpe-uuid-result" aria-label="Resultado de verificación">
        <div className="cpe-uuid-result-heading">
          <h3>Resultado oficial de NVD</h3>
          <span className="cpe-uuid-status" data-status={selected.verification_status}>
            {externalCpeStatus(selected)}
          </span>
        </div>
        {pending && <div className="cpe-uuid-progress" role="status">
          <p>{selected.status === "QUEUED" ? "Esperando al worker NVD." :
            "Consultando el registro oficial en NVD."} Puedes cerrar el formulario; el trabajo seguirá guardado.</p>
          {selected.worker_active === false && <p className="cpe-warning">
            No se detecta el worker. Inicia <code>python manage.py run_cpe_worker</code>
            en la terminal del backend.
          </p>}
          {pollingPaused ? <button type="button" className="button-secondary"
              disabled={refreshing} onClick={refreshSelected}>
              {refreshing ? "Consultando..." : "Consultar estado ahora"}
            </button>
            : <p className="cpe-hint">Actualizando el estado cada cinco segundos (hasta cinco minutos).</p>}
        </div>}
        {selected.status === "FAILED" && <p className="error-message" role="alert">
          {selected.error_message || "NVD no pudo verificar el identificador solicitado."}
        </p>}
        {selected.verification_status === "NOT_FOUND" && <p className="cpe-warning">
          NVD no encontró un registro correspondiente a este UUID. No se creó ninguna asociación.
        </p>}
        {selected.verification_status === "INCOMPATIBLE_PART" && <p className="cpe-warning">
          {selected.queries?.[0]?.warning || "El tipo CPE no corresponde al activo."}
          {" "}No puede asociarse a este activo.
        </p>}
        {selected.status === "COMPLETED" && evidence && <>
          <h4>{evidence.title}</h4>
          <p className="cpe-uuid-official">Registro obtenido de la API oficial de productos CPE de NVD.</p>
          <CpeEvidence cpeName={evidence.cpe_name}
            cpeNameId={evidence.cpe_name_id}/>
          <p>Tipo CPE: <strong>{evidence.cpe_name?.split(":")[2]}</strong> ·
            {" "}{evidence.deprecated ? "Deprecado en NVD" : "No deprecado en NVD"}</p>
          <CpeReferences references={evidence.nvd_references}/>
          {additionalNvdReferences(evidence.nvd_references).length > 0 && <details className="cpe-uuid-other-refs">
            <summary>Otras referencias incluidas por NVD ({additionalNvdReferences(evidence.nvd_references).length})</summary>
            <ul>{additionalNvdReferences(evidence.nvd_references).map(item =>
              <li key={item.url}>
                <span>{item.type}: </span>
                <a href={item.url} rel="noopener noreferrer" target="_blank">
                  {new URL(item.url).hostname} ↗
                </a>
              </li>)}</ul>
            <p>Son enlaces incluidos por NVD; no acreditan por sí mismos que el CPE
              corresponda al activo.</p>
          </details>}
          {selected.verification_status === "VERIFIED" && <>
            <p className="cpe-uuid-match">{candidate?.match_reason}</p>
            {(candidate?.warnings || []).length > 0 && <div className="cpe-uuid-warnings">
              <strong>Advertencias de correspondencia</strong>
              <ul>{candidate.warnings.map((warning, index) =>
                <li key={index}>{warning}</li>)}</ul>
            </div>}
          </>}
        </>}
        {selected.status === "COMPLETED" && candidate && <>
          {!selected.identity_is_current && <p className="cpe-warning">
            La identidad del activo cambió desde la verificación. Debes verificar el UUID
            nuevamente antes de decidir.
          </p>}
          {existing && <p className="cpe-uuid-existing" role="status">
            Este CPE ya tiene una asociación: <strong>{
              existing.validation_status === "CONFIRMED" ? "Confirmado" :
              existing.validation_status === "REJECTED" ? "Rechazado" :
              existing.validation_status === "REOPENED" ? "Decisión deshecha" :
              "Pendiente histórico"
            }</strong>. Puedes cambiar la decisión desde aquí; no se creará un duplicado.
          </p>}
          {associationError && <p className="error-message" role="alert">{associationError}</p>}
          <CandidateCpeReview key={selected.id + "-" + candidate.cpe_name_id}
            candidate={candidate} assetId={asset.asset_id} run={selected}
            association={existing} allowed={reviewable} onReviewed={async () => {
              try {
                await refreshAssociations();
              } catch (err) {
                // The decision was already saved; a refresh error must not
                // encourage a duplicate POST or report that the decision failed.
                setAssociationError("La decisión se guardó, pero no se pudo actualizar el historial: " + err.message);
              }
            }}/>
        </>}
      </section>}
      <div className="cpe-bulk-dialog-actions">
        <button type="button" className="button-secondary"
          disabled={submitting} onClick={onClose}>Cerrar</button>
      </div>
    </section>
  </div>;
}
