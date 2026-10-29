import { useEffect, useRef, useState } from "react";
import { Link, useOutletContext, useParams, useSearchParams } from "react-router-dom";
import {
  listCveHardware, readCveCatalogue, readGeneralCveAssessment,
  createGeneralCveAssessment, ensureAutomaticCveAssessment,
} from "../api/vulnerabilities";
import SuccessNotice from "../components/SuccessNotice";
import CveAnalysis from "./CveAnalysis";
import {
  CVE_SEVERITY, CVE_TECHNICAL_STATE, CVE_EVALUATION_STATE,
  CVE_APPLICABILITY_SOURCE,
  selectedCveHardwareId, groupCveEvidence,
  nvdCriterionIdentityBadge, currentCveSoftwareLink,
  currentCveEvaluatedSoftware, isSavedCveLinkSelection, cveAuditJustification,
  displayNvdGroupBranches, nvdAlternativeGroupLabel,
} from "../utils/cveCataloguePresentation";
import {
  localizedTimestamp, versionConstraintsText,
} from "../utils/cveAssessmentPresentation";

const STATE = {
  APPLIES: "Aplica a esta configuración",
  APPLIES_CONDITIONAL: "Aplica condicionada",
  NOT_APPLICABLE: "No aplica a esta configuración",
  PENDING_REVIEW: "Pendiente de revisión",
};
const PLAIN = { h: "Hardware", o: "Firmware / sistema operativo", a: "Software" };


/** Human-facing evidence stays visible; the raw NVD proof is opt-in. */
function vulnerableSoftwareCriterion(tree) {
  if (tree?.kind === "CRITERION" &&
      tree.vulnerable === true && ["o", "a"].includes(tree.part)) {
    return tree;
  }
  for (const child of tree?.children || []) {
    const found = vulnerableSoftwareCriterion(child);
    if (found) return found;
  }
  return null;
}

function Criterion({ item, depth = 0, selection, onSelect, installId,
  installedSoftware = [], canDecide = false, savedLink = null,
  pendingUnlink = false, softwareAlternatives = [], onChooseSoftware }) {
  if (item.kind === "CRITERION") {
    const isSoftware = ["a", "o"].includes(item.part);
    const identityBadge = nvdCriterionIdentityBadge(item);
    const currentInstallations = (installedSoftware || []).filter(sw =>
      item.part === "a" ? sw.software_type === "APPLICATION" :
        ["FIRMWARE", "OS"].includes(sw.software_type)
    );
    const criterionKey = item.match_criteria_id || item.criteria;
    return <div className="cve-nvd-condition cve-general-criterion">
      <div className="cve-nvd-condition-summary">
        <div className="cve-nvd-condition-heading">
          <div className="cve-nvd-condition-tags">
            <h3>{PLAIN[item.part] || "Componente NVD"}</h3>
            <span className={"cve-nvd-category " + (
              item.vulnerable ? "cve-nvd-vulnerable" : "cve-nvd-platform"
            )}>{item.vulnerable ? "Componente vulnerable" : "Condición de plataforma"}</span>
          </div>
          <span className="cve-condition-state" data-state={identityBadge.state}
            title="La identidad CPE y la versión NVD se comprueban por separado.">
            {identityBadge.label}
          </span>
        </div>
        <p className="cve-nvd-product">{String(item.criteria || "").split(":")
          .slice(3, 5).join(" · ").replaceAll("_", " ") || "Criterio NVD"}</p>
      </div>

      {isSoftware && item.vulnerable && onSelect && <div className="cve-nvd-selection">
        {currentInstallations.length ? <>
          <p className="cve-nvd-association-title">
            Software registrado como instalado en este hardware
          </p>
          {currentInstallations.map(sw => {
            const isChecked = selection === criterionKey &&
              installId === String(sw.installation_id);
            const persisted = isChecked && savedLink?.installationId ===
              String(sw.installation_id) && savedLink.criterionKey === criterionKey;
            return <div className="cve-installed-software-entry" key={sw.installation_id}>
              <div className="cve-installed-software-meta">
                <div className="cve-association-name">
                  <strong>{sw.software_name}</strong>
                  <small>Software #{sw.software_asset_id} · Instalación #{sw.installation_id}
                    {" · Versión "}{sw.version || "desconocida"}</small>
                </div>
                <span className="cve-software-status is-installed">Instalado</span>
              </div>
              <label className="cve-criterion-selection cve-software-association">
                <input type="checkbox" disabled={!canDecide} checked={isChecked}
                  onChange={event => onSelect(
                    event.target.checked ? criterionKey : "",
                    event.target.checked ? String(sw.installation_id) : ""
                  )}/>
                <span>{persisted && savedLink.evidenceOnly
                  ? "Firmware identificado y utilizado para evaluar por qué no aplica"
                  : persisted
                    ? savedLink.source === "SYSTEM"
                      ? "CVE asociado automáticamente · Desmarcar para revisar"
                      : "CVE asociado por el analista · Desmarcar para revisar"
                    : "Asociar este CVE al software instalado"}</span>
              </label>
            </div>;
          })}
          {pendingUnlink && <p className="cve-cancel-pending" role="status">
            Revisión pendiente: la casilla solo cambia provisionalmente.
            Justifica la correspondencia parcial para guardar una nueva decisión;
            cancelar conserva la evaluación vigente.
          </p>}
          <p className="cve-muted">
            {savedLink?.evidenceOnly
              ? "La casilla marcada identifica la instalación evaluada; NO significa que sea vulnerable. La versión y los criterios NVD quedan en el historial."
              : "Una asociación manual no confirma por sí sola la versión vulnerable. Cambiar una decisión guardada exige justificar el cambio."}
          </p>
        </> : <p className="cve-muted">
          No hay software de este tipo instalado en el inventario de este hardware.
          Puedes registrar una correspondencia parcial sin asociar software.
        </p>}
      </div>}

      <details className="cve-nvd-proof">
        <summary>Ver evidencia técnica NVD</summary>
        <div className="cve-nvd-proof-content">
          <div className="cve-nvd-criterion">
            <span className="cve-nvd-criterion-label">
              {isSoftware ? "Criterio de software NVD" : "CPE hardware · NVD"}</span>
            <code>{item.criteria || "No indicado"}</code>
            {item.match_criteria_id && <p className="cve-criterion-id">
              ID criterio NVD: <code>{item.match_criteria_id}</code></p>}
          </div>
          {versionConstraintsText(item.bounds) && <p className="cve-general-constraints">
            Restricciones NVD: {versionConstraintsText(item.bounds)}.</p>}
          <div className="cve-technical-criterion">
            <span className="cve-technical-tag" data-result={
              item.technical_result || "INDETERMINATE"
            }>{CVE_TECHNICAL_STATE[item.technical_result] ||
              CVE_TECHNICAL_STATE.INDETERMINATE}</span>
            <p>{item.technical_reason ||
              "No hay evidencia suficiente para resolver el criterio."}</p>
            {item.technical_matched_cpe && <p>
              CPE confirmado usado: <code>{item.technical_matched_cpe}</code>
            </p>}
            {item.technical_software_asset_id && <p>
              Software #{item.technical_software_asset_id}
              {item.technical_software_installation_id &&
                " · Instalación #" + item.technical_software_installation_id}
            </p>}
            {item.technical_installed_version && <p>
              Versión comprobada: {item.technical_installed_version}</p>}
          </div>
        </div>
      </details>
      {softwareAlternatives.length > 0 && <details className="cve-nvd-other-evidence cve-nvd-software-choices">
        <summary>Otras alternativas de software para este hardware
          {" (" + softwareAlternatives.length + ")"}</summary>
        <div className="cve-nvd-other-scroll" role="region" tabIndex={0}
          aria-label="Alternativas NVD del software para el hardware confirmado">
          <p className="cve-muted">Selecciona el criterio de software que deseas evaluar.
            Esta selección no confirma una vulnerabilidad ni genera historial
            hasta que se registre una decisión.</p>
          {softwareAlternatives.map(config => {
            const software = vulnerableSoftwareCriterion(config.tree);
            const product = String(software?.criteria || "").split(":")
              .slice(3, 5).join(" · ").replaceAll("_", " ");
            return <button key={config.index} type="button"
              className="cve-nvd-software-choice"
              onClick={() => onChooseSoftware(config.index)}>
              <span><strong>{product || "Software NVD por verificar"}</strong>
                <small>Configuración NVD {config.position}</small></span>
              <span className="cve-technical-tag"
                data-result={config.technical_result}>
                {CVE_TECHNICAL_STATE[config.technical_result] ||
                  CVE_TECHNICAL_STATE.INDETERMINATE}</span>
            </button>;
          })}
        </div>
      </details>}
    </div>;
  }
  if (item.kind !== "GROUP") {
    return <p className="cpe-warning">NVD contiene una estructura que debe revisarse.</p>;
  }

  const isOr = item.operator === "OR";
  const { shown, hidden } = displayNvdGroupBranches(item, selection);
  const firstSoftware = shown.findIndex(child => Boolean(vulnerableSoftwareCriterion(child)));
  const renderChild = (child, i) =>
    <Criterion key={(child.match_criteria_id || child.criteria || "grupo") + ":" + i}
      item={child} depth={depth + 1} selection={selection}
      onSelect={onSelect} installId={installId}
      installedSoftware={installedSoftware} canDecide={canDecide}
      savedLink={savedLink} pendingUnlink={pendingUnlink}
      softwareAlternatives={i === firstSoftware ? softwareAlternatives : []}
      onChooseSoftware={onChooseSoftware}/>;

  return <div className={"cve-general-group " + (depth ? "cve-general-nested" : "")}>
    {!isOr && shown.length > 1 && depth === 0 &&
      <div className="cve-general-logic">
        <strong>Se requieren todas las condiciones</strong>
      </div>}
    {item.negate && <p className="cpe-warning">
      Negación NVD: el resultado del grupo se invierte y requiere revisión especializada.
    </p>}
    {shown.length ? shown.map((child, i) =>
      <div key={i}>
        {i > 0 && <div className="cve-nvd-plus" aria-label={"Operador " +
          (isOr ? "O" : "Y")}>{isOr ? "O" : "Y"}</div>}
        {renderChild(child, i)}
      </div>) : <p className="cve-muted">No hay criterios detallados en este grupo.</p>}
    {hidden.length > 0 && <details className="cve-nvd-other-evidence cve-nvd-other-branches">
      <summary>{nvdAlternativeGroupLabel(hidden)} ({hidden.length})</summary>
      <div className="cve-nvd-other-scroll" tabIndex={0}
        role="region" aria-label={nvdAlternativeGroupLabel(hidden)}>
        <p className="cve-muted">Opciones del operador O de NVD.
          No implican presencia en el inventario ni aplicabilidad confirmada.</p>
        {hidden.map(renderChild)}
      </div>
    </details>}
  </div>;
}

function ConfigurationReview({ context, config, onSaved, canDecide, highlight = false,
  softwareAlternatives = [], onChooseSoftware }) {
  const last = config.latest_assessment;
  const status = last?.effective_status || "PENDING_REVIEW";
  const savedPositive = currentCveSoftwareLink(config, context);
  const evaluatedLink = currentCveEvaluatedSoftware(config, context);
  const savedLink = savedPositive || evaluatedLink;
  // null means no edit; an empty draft overrides the persisted check only locally.
  const [draftLink, setDraftLink] = useState(null);
  const [reviewOpen, setReviewOpen] = useState(false);
  const [choice, setChoice] = useState("");
  const [justification, setJustification] = useState("");
  const [complete, setComplete] = useState(false);
  const [overrideAcknowledged, setOverrideAcknowledged] = useState(false);
  const [platformAcknowledged, setPlatformAcknowledged] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const justificationRef = useRef(null);
  const currentLink = draftLink === null ? savedLink : draftLink;
  const installId = currentLink?.installationId || "";
  const selectedCriterion = currentLink?.criterionKey || "";
  const pendingUnlink = choice === "CONDITIONAL" && Boolean(savedLink) &&
    draftLink !== null && !draftLink.installationId;

  useEffect(() => {
    if (pendingUnlink && justificationRef.current) {
      justificationRef.current.scrollIntoView({ behavior: "smooth", block: "center" });
      justificationRef.current.focus({ preventScroll: true });
    }
  }, [pendingUnlink]);

  const targetPart = config.software_criterion?.split(":")[2];
  const installations = (context.installed_software || []).filter(sw => {
    const compatibleType = targetPart === "o"
      ? ["FIRMWARE", "OS"].includes(sw.software_type)
      : targetPart === "a" && sw.software_type === "APPLICATION";
    return compatibleType && (!config.review_installation_id ||
      sw.installation_id === config.review_installation_id);
  });
  const selectedId = installId || (installations.length === 1 && choice === "NOT_MATCH"
    ? String(installations[0].installation_id) : "");
  const currentStatus = last && !last.stale ? last.effective_status : null;
  const lockedDecision = Boolean(currentStatus &&
    ["APPLIES", "APPLIES_CONDITIONAL", "NOT_APPLICABLE"].includes(currentStatus));
  const canReopen = canDecide && lockedDecision;
  const canReview = config.review_supported && canDecide;
  const canConditional = config.conditional_supported && canDecide &&
    ["INDETERMINATE", "EXCLUDED"].includes(config.technical_result);
  const technicalConflict = config.technical_result === "EXCLUDED";
  const unverifiedPlatform = Boolean(config.manual_platform_review_required);
  const checked = Boolean(selectedCriterion);
  const canConfirm = canReview || canConditional ||
    (reviewOpen && config.technical_result === "COMPATIBLE");
  const linkedInstallationId = checked ? installId : "";
  const eligible = (config.candidate_installation_ids || []).includes(Number(linkedInstallationId)) ||
    config.review_installation_id === Number(linkedInstallationId);
  const confirmationVerdict = linkedInstallationId &&
    ((canReview && eligible) || (technicalConflict && config.technical_override_supported))
    ? "CONFIRMED" : "CONDITIONAL";
  const positiveConflict = config.technical_result === "COMPATIBLE" &&
    ["NOT_MATCH", "CONDITIONAL"].includes(choice);
  const canDiscard = canDecide &&
    ["MATCHED", "UNSCOPED"].includes(config.hardware_scope) &&
    (config.technical_result !== "EXCLUDED" ||
      (last?.source === "ANALYST" && !last?.stale &&
        ["APPLIES", "APPLIES_CONDITIONAL"].includes(last.status))) &&
    (canReview || canConditional || config.technical_result === "COMPATIBLE");
  const noSelected = choice === "CONFIRMED" && !selectedId;
  const invalid = !justification.trim() || noSelected ||
    (choice === "NOT_MATCH" && (!complete || justification.trim().length < 20)) ||
    (positiveConflict &&
      (!overrideAcknowledged || justification.trim().length < 20)) ||
    (choice === "CONDITIONAL" && justification.trim().length < 20) ||
    (technicalConflict && ["CONFIRMED", "CONDITIONAL"].includes(choice) &&
      (!overrideAcknowledged || justification.trim().length < 20)) ||
    (unverifiedPlatform && choice === "CONDITIONAL" &&
      (!platformAcknowledged || !linkedInstallationId || justification.trim().length < 20));

  function reset() {
    setChoice(""); setDraftLink(null); setReviewOpen(false);
    setJustification(""); setComplete(false); setOverrideAcknowledged(false); setPlatformAcknowledged(false); setError("");
  }
  function beginReopen() {
    setReviewOpen(true);
    setDraftLink(null);
    setChoice("");
    setJustification(""); setComplete(false); setOverrideAcknowledged(false); setPlatformAcknowledged(false); setError("");
  }
  function updateAssociation(criterionKey, installationId) {
    if (savedLink && !criterionKey && !installationId) {
      setReviewOpen(true);
      setDraftLink({ criterionKey: "", installationId: "" });
      setChoice("CONDITIONAL");
      setJustification(""); setComplete(false);
      setOverrideAcknowledged(false); setPlatformAcknowledged(false);
      setError("");
      return;
    }
    if (isSavedCveLinkSelection(savedLink, criterionKey, installationId)) {
      // No actual change: cancel the tentative reopening and restore the
      // persisted SYSTEM/ANALYST association without an audit write.
      reset();
      return;
    }
    setDraftLink({ criterionKey, installationId });
    setReviewOpen(true);
    setChoice(""); setJustification(""); setOverrideAcknowledged(false); setPlatformAcknowledged(false); setError("");
  }
  async function submit(event) {
    event.preventDefault();
    if (invalid || saving) return;
    setSaving(true);
    setError("");
    try {
      await createGeneralCveAssessment(context.cve_id, context.hardware_asset_id, {
        configuration_index: config.index,
        configuration_fingerprint: config.fingerprint,
        inventory_fingerprint: context.inventory_fingerprint,
        verdict: choice,
        software_installation_id: choice === "UNKNOWN" ? null :
          choice === "CONDITIONAL" ? (linkedInstallationId ? Number(linkedInstallationId) : null) :
          (selectedId ? Number(selectedId) : null),
        inventory_declared_complete: choice === "NOT_MATCH" && complete,
        technical_override_acknowledged: (
          (technicalConflict && ["CONFIRMED", "CONDITIONAL"].includes(choice)) ||
          positiveConflict
        ) && overrideAcknowledged,
        platform_unverified_acknowledged: unverifiedPlatform &&
          choice === "CONDITIONAL" && platformAcknowledged,
        justification: justification.trim(),
      });
      if (choice === "UNKNOWN") {
        // Keep the pending removal visually unchecked until refreshed context arrives.
        setDraftLink({ criterionKey: "", installationId: "" });
        setChoice("");
        setJustification(""); setError("");
      } else {
        reset();
      }
      onSaved();
    } catch (err) {
      setError("No se registró la evaluación: " + err.message);
    } finally {
      setSaving(false);
    }
  }
  const showChoices = canDecide && (!lockedDecision || reviewOpen);
  return <>
    <Criterion item={config.tree} selection={selectedCriterion}
      onSelect={updateAssociation}
      installId={installId} installedSoftware={context.installed_software || []}
      canDecide={canDecide && (canConfirm || canReopen || canDiscard)}
      savedLink={savedLink} pendingUnlink={pendingUnlink}
      softwareAlternatives={softwareAlternatives}
      onChooseSoftware={onChooseSoftware}/>
    <div className="panel cve-nvd-decision">
    <div className="cve-nvd-joint-title">
      <h3>{highlight ? "Correspondencia · Configuración NVD " + config.position :
        "Revisión de evidencia adicional · Configuración " + config.position}</h3>
      <span className="cve-status-label" data-status={status}>
        {STATE[status] || status}
        {last?.source === "SYSTEM" && " · Automático"}</span>
    </div>
    <p>La correspondencia se evalúa contra la configuración NVD {config.position}
      y el hardware #{context.hardware_asset_id}. El historial registra
      confirmaciones automáticas y decisiones humanas con su justificación.</p>
    {last?.source === "ANALYST" && last.status === "PENDING_REVIEW" &&
      !last.stale && <p className="cve-muted" role="status">
        Evaluación reabierta por el analista: ya no hay una vinculación de software
        confirmada en esta decisión. La evidencia técnica NVD sigue evaluándose
        de forma independiente y puede continuar indicando coincidencia.
      </p>}
    {last?.stale && <p className="cpe-warning">
      La evaluación previa conserva su registro histórico, pero la evidencia cambió.
      Se necesita revisar nuevamente.</p>}
    {config.technical_result === "EXCLUDED" ? <div className="cve-technical-discrepancy"
      role="status">
      <strong>Configuración excluida por evidencia técnica NVD</strong>
      <p>La exclusión automática no impide una decisión distinta del analista.
        Puedes asociar el software y registrar una correspondencia manual,
        pero deberás reconocer y justificar la discrepancia. El resultado técnico
        permanecerá intacto y el CVE completo puede seguir pendiente.</p>
    </div> : !config.review_supported && <p className="cpe-warning" role="status">
      Esta configuración no permite confirmar automáticamente todas las
      condiciones NVD. {canConditional
        ? "El analista puede registrarla como Aplica condicionada, justificando qué falta verificar."
        : "La revisión permanece pendiente."}</p>}
    {unverifiedPlatform && <div className="cve-technical-discrepancy" role="status">
      Esta configuración no tiene plataforma de hardware CPE confirmada.
      Si identificas una instalación pertinente, puedes asociarla de manera
      condicionada con reconocimiento explícito y justificación del analista.
      Esto no constituye una coincidencia técnica NVD.
    </div>}
    {config.review_installation_id && config.technical_result === "COMPATIBLE" &&
      <p className="cve-muted">
        El firmware instalado satisface este criterio NVD; no se puede
        descartar mientras las evidencias sean vigentes.
      </p>}
    {pendingUnlink && <div className="cve-pending-reopen" role="status">
      <strong>Correspondencia parcial pendiente de confirmar</strong>
      <p>El resultado anterior sigue vigente. La decisión solo cambiará
        al guardar una justificación válida; cancelar la conserva.</p>
    </div>}
    {(canReopen || showChoices) && <div className="cve-nvd-actions">
      {canReopen && !reviewOpen && <button type="button"
        className="cve-nvd-action" onClick={beginReopen}>
        Reabrir evaluación</button>}
      {showChoices && <>
        {canConfirm && currentStatus !== "APPLIES" &&
          confirmationVerdict === "CONFIRMED" && <button type="button"
          className={"cve-nvd-action" + (choice === "CONFIRMED" ? " selected" : "")}
          onClick={() => { setChoice("CONFIRMED"); setReviewOpen(true); setJustification(""); }}>
          Confirmar correspondencia</button>}
        {currentStatus !== "APPLIES_CONDITIONAL" &&
          (canConditional || canConfirm || canReopen) && <button type="button"
          className={"cve-nvd-action" + (choice === "CONDITIONAL" ? " selected" : "")}
          onClick={() => {
            setChoice("CONDITIONAL"); setReviewOpen(true); setJustification("");
            if (savedLink && !draftLink) setDraftLink({criterionKey:"", installationId:""});
          }}>
          Correspondencia parcial</button>}
        {canDiscard && currentStatus !== "NOT_APPLICABLE" &&
          <button type="button" className={"cve-nvd-action" +
          (choice === "NOT_MATCH" ? " selected" : "")}
          onClick={() => {
            setChoice("NOT_MATCH"); setReviewOpen(true); setJustification("");
          }}>No corresponde</button>}
      </>}
    </div>}
    {choice === "CONDITIONAL" && <p className="cve-muted" role="status">
      Resultado previsto: Aplica condicionada.
      {linkedInstallationId
        ? " La instalación marcada quedará vinculada por decisión del analista, sin atribuirle una confirmación CPE que no existe."
        : " No se vinculará ningún software. Esto no equivale a descartar el CVE."}
    </p>}
    {!canDiscard && canDecide && !lockedDecision && <p className="cve-muted">
      La no correspondencia requiere un contexto verificable de hardware
      o software y evidencia negativa justificada.
    </p>}
    {!canDecide && <p className="cve-muted">
      El rol actual permite consultar, pero no registrar decisiones.</p>}
    {choice && showChoices &&
      <form className="cve-compact-review"
      onSubmit={submit}>
      {installations.length > 1 && choice === "NOT_MATCH" && <label>
        Instalación que deseas evaluar
        <select value={installId} onChange={event => setDraftLink({
          criterionKey: "", installationId: event.target.value,
        })}>
          <option value="">Selecciona una instalación</option>
          {installations.map(sw => <option key={sw.installation_id}
            value={sw.installation_id}>
            {sw.software_name} · Instalación #{sw.installation_id}</option>)}
        </select>
      </label>}
      {(technicalConflict && ["CONFIRMED", "CONDITIONAL"].includes(choice) ||
        positiveConflict) &&
        <div className="cve-override-attestation">
          <label><input type="checkbox" checked={overrideAcknowledged}
            onChange={event => setOverrideAcknowledged(event.target.checked)}/>
            Reconozco que esta decisión contradice el resultado técnico
            vigente de NVD y que debo justificar expresamente mi discrepancia.</label>
          <p>La decisión no modifica los criterios ni la evaluación técnica NVD.</p>
        </div>}
      {unverifiedPlatform && choice === "CONDITIONAL" &&
        <div className="cve-override-attestation">
          <label><input type="checkbox" checked={platformAcknowledged}
            onChange={event => setPlatformAcknowledged(event.target.checked)}/>
            Reconozco que esta configuración NVD no tiene una plataforma
            CPE confirmada en el hardware y solicito una vinculación
            discrecional de la instalación seleccionada.</label>
          <p>Se conservará el estado técnico pendiente y quedará registrada
            la asociación manual con su justificación.</p>
        </div>}
      <label>Justificación de la decisión
        <textarea ref={justificationRef} rows={3} required maxLength={1000}
          aria-invalid={pendingUnlink && !justification.trim()}
          value={justification}
          onChange={event => setJustification(event.target.value)}
          placeholder={choice === "UNKNOWN"
            ? "Explica por qué deseas retirar esta asociación y reabrir la evaluación..."
            : "Describe las evidencias que sustentan la correspondencia..."}/>
      </label>
      {choice === "NOT_MATCH" && <div className="cve-attestation">
        <label><input type="checkbox" checked={complete}
          onChange={event => setComplete(event.target.checked)}/>
          He revisado la integridad del inventario y dispongo de evidencia
          suficiente para descartar esta configuración NVD.</label>
        <p>Describe qué verificaste. La ausencia de una aplicación en
          el inventario no constituye por sí sola evidencia negativa.</p>
      </div>}
      <div className="cve-form-actions">
        <button type="submit" className="button-primary"
          disabled={saving || invalid}>{saving ? "Guardando..." :
          (technicalConflict && ["CONFIRMED", "CONDITIONAL"].includes(choice) ||
            positiveConflict) ? "Registrar decisión discrepante" :
            choice === "NOT_MATCH" ? "Registrar No corresponde" : "Guardar evaluación"}</button>
        <button type="button" className="button-secondary" disabled={saving}
          onClick={reset}>Cancelar</button>
      </div>
    </form>}
    {error && <p className="error-message" role="alert">{error}</p>}
    <details className="cve-general-history">
      <summary>Historial de decisiones ({config.history?.length || 0})</summary>
      {config.history?.length ? <ol className="cve-history">
        {config.history.map(item => <li key={item.id}>
          <strong>{STATE[item.status] || item.status}</strong>
          <span className="cve-muted"> · {item.source === "SYSTEM"
            ? "Automático" : "Analista"}</span>
          {item.technical_override && <p className="cve-history-warning">
            Decisión humana discrepante: NVD mantiene el resultado
            { " "}{item.technical_override.technical_result}. La vinculación
            fue autorizada expresamente por el analista.
          </p>}
          {item.stale && <p className="cve-history-warning">
            Registro histórico: evidencia no vigente.</p>}
          <p>{item.source === "SYSTEM" ? "El sistema" :
            (item.decided_by || "Usuario no disponible")} ·
            {localizedTimestamp(item.decided_at)}</p>
          <p>{cveAuditJustification(item.justification, item.source)}</p>
          {item.status === "APPLIES_CONDITIONAL" && item.conditional_evidence &&
            <p className="cve-muted">
              Componentes vulnerables NVD:
              {" "}{(item.conditional_evidence.vulnerable_criteria || [])
                .map(row => row.criteria).join("; ")}
              {" · "}{item.software_installation_id
                ? "Instalación vinculada #" + item.software_installation_id
                : "Sin software vinculado"}
            </p>}
        </li>)}
      </ol> : <p className="cve-muted">No hay decisiones registradas.</p>}
    </details>
  </div></>;
}

function CandidateReview({ context, config, canDecide, onSaved }) {
  const [open, setOpen] = useState(false);
  return <div className="cve-pending-configuration">
    <button type="button" className="cve-pending-configuration-trigger"
      aria-expanded={open} onClick={() => setOpen(value => !value)}>
      <span>Configuración NVD {config.position} · Pendiente de evidencia</span>
      <span aria-hidden="true">{open ? "▴" : "▾"}</span>
    </button>
    {open && <div className="cve-pending-configuration-content">
      <ConfigurationReview context={context} config={config}
        canDecide={canDecide} onSaved={onSaved}/>
    </div>}
  </div>;
}

export default function CveDetail() {
  const { cveId } = useParams();
  const [searchParams] = useSearchParams();
  const requestedHardware = searchParams.get("hardware");
  const { user } = useOutletContext();
  const canDecide = ["ADMIN", "ANALYST"].includes(user?.role);
  const [cve, setCve] = useState(null);
  const [hardware, setHardware] = useState([]);
  const [selectedHardware, setSelectedHardware] = useState("");
  const [context, setContext] = useState(null);
  const [loading, setLoading] = useState(true);
  const [contextLoading, setContextLoading] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [revision, setRevision] = useState(0);
  const [chosenConfiguration, setChosenConfiguration] = useState(null);

  useEffect(() => {
    setChosenConfiguration(null);
  }, [cveId, selectedHardware, context?.inventory_fingerprint]);

  useEffect(() => {
    let active = true;
    setLoading(true); setError(""); setContext(null);
    Promise.all([readCveCatalogue(cveId), listCveHardware(cveId, 1, 100)])
      .then(([info, related]) => {
        if (!active) return;
        setCve(info); setHardware(related.results);
        setSelectedHardware(selectedCveHardwareId(related.results, requestedHardware));
      })
      .catch(err => { if (active) setError(err.message); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [cveId]);

  useEffect(() => {
    if (requestedHardware && hardware.length) {
      const nextId = selectedCveHardwareId(hardware, requestedHardware);
      if (nextId && nextId !== selectedHardware) setSelectedHardware(nextId);
    }
  }, [requestedHardware, hardware, selectedHardware]);

  const isLegacy = cveId === "CVE-2021-33540" &&
    Number(selectedHardware) === 2;
  useEffect(() => {
    if (!selectedHardware || isLegacy) {
      setContext(null);
      return undefined;
    }
    let live = true;
    setContextLoading(true); setError("");
    readGeneralCveAssessment(cveId, Number(selectedHardware))
      .then(async data => {
        // Existing imported CVEs may predate automatic audit logging.
        // Synchronise their proof once through a POST; never write on GET.
        if (canDecide && data.automatic_audit_pending) {
          try {
            const synced = await ensureAutomaticCveAssessment(
              cveId, Number(selectedHardware)
            );
            data = synced.context;
          } catch (err) {
            if (live) setError("No se pudo guardar la auditoría automática: " +
              err.message);
          }
        }
        if (live) setContext(data);
      })
      .catch(err => { if (live) setError(err.message); })
      .finally(() => { if (live) setContextLoading(false); });
    return () => { live = false; };
  }, [cveId, selectedHardware, isLegacy, revision, canDecide]);

  const configs = context?.relevant_configurations || [];
  const hardwareSoftware = context?.hardware_software_configurations || [];
  const reviewPool = hardwareSoftware.length ? hardwareSoftware : configs;
  const candidates = context?.candidate_configurations || [];
  const unverifiedPlatforms = context?.unverified_platform_configurations || [];
  const { primary: suggestedPrimary } = groupCveEvidence(reviewPool);
  const primary = reviewPool.find(row => row.index === chosenConfiguration) ||
    suggestedPrimary;
  const others = reviewPool.filter(row => row.index !== primary?.index);
  const independentConfigs = hardwareSoftware.length
    ? configs.filter(row => !hardwareSoftware.some(hw => hw.index === row.index))
    : [];
  const source = cve?.description_source;
  const nvdUrl = "https://nvd.nist.gov/vuln/detail/" + encodeURIComponent(cveId);
  if (loading) return <section className="page" aria-busy="true">
    <p>Cargando análisis CVE...</p></section>;
  if (!cve) return <section className="page">
    <Link to="/vulnerabilities/cve">Análisis CVE</Link>
    <p className="error-message" role="alert">
      {error || "No se pudo cargar el CVE."}</p>
  </section>;
  if (isLegacy) return <CveAnalysis/>;
  return <section className="page cve-analysis-page cve-nvd-detail cve-general-analysis">
    <nav className="breadcrumbs" aria-label="Ruta de navegación">
      <Link to="/vulnerabilities/cve">Análisis CVE</Link><span>/</span>
      <span>{cveId}</span>
    </nav>
    {error && <p className="error-message" role="alert">{error}</p>}
    <SuccessNotice message={notice} onClose={() => setNotice("")} durationMs={30000}/>
    <header className="page-header cve-nvd-overview">
      <span className="page-eyebrow">ANÁLISIS CVE</span>
      <div className="cve-nvd-titlebar">
        <div className="cve-nvd-header-text">
          <h1><a href={nvdUrl} target="_blank" rel="noopener noreferrer">
            {cveId} ↗</a></h1>
          <p className="cve-nvd-description-heading">Descripción</p>
          <p className="cve-nvd-description">{cve.description}</p>
          <p className="cve-nvd-description-label">
            {source === "NVD_ES" ? "Descripción oficial en español · NVD" :
              source === "TRADUCCION_ORIENTATIVA" ?
                "Traducción orientativa al español (no oficial de NVD)" :
                "NVD no proporcionó una descripción oficial en español"}</p>
          <div className="cve-general-dates">
            <span>Publicado: {cve.published ?
              new Date(cve.published).toLocaleDateString("es-CO") : "Sin fecha"}</span>
            <span>Actualizado: {cve.last_modified ?
              new Date(cve.last_modified).toLocaleDateString("es-CO") : "Sin fecha"}</span>
          </div>
        </div>
        <span className="cve-nvd-severity" data-level={cve.severity}>
          {CVE_SEVERITY[cve.severity] || cve.severity}
          {cve.base_score != null && " · " + cve.base_score}</span>
      </div>
    </header>

    {!contextLoading && !context && !hardware.length &&
      <div className="panel cve-technical-summary">
        <h2>Sin hardware asociado a este CVE</h2>
        <p>Abre la identificación de vulnerabilidades desde un activo del inventario
          para evaluar sus condiciones NVD.</p>
        <Link to="/vulnerabilities/cve">Volver al análisis CVE</Link>
      </div>}

    {contextLoading ? <p className="cve-muted">Cargando condiciones del inventario...</p>
      : context && Number(context.hardware_asset_id) === Number(selectedHardware) && <>
        <div className="panel cve-technical-summary cve-hardware-applicability">
          <div className="cve-technical-summary-heading">
            <div className="cve-evaluated-hardware">
              <h2>Aplicabilidad del CVE</h2>
              <div className="cve-evaluated-hardware-identity">
                <div>
                  <h3><Link to={"/assets/" + context.hardware_asset_id}>
                    {context.hardware_name}</Link></h3>
                  <p>Hardware #{context.hardware_asset_id} · Activo evaluado</p>
                </div>
              </div>
            </div>
            <span className="cve-catalogue-evaluation-status"
              data-status={context.applicability?.status || "PENDING_REVIEW"}>
              {context.applicability?.status === "PENDING_REVIEW" &&
                (context.technical_configuration_counts?.EXCLUDED || 0) > 0
                ? "Validación parcial" :
                (CVE_EVALUATION_STATE[context.applicability?.status] ||
                  CVE_EVALUATION_STATE.PENDING_REVIEW)}
              {" · "}{CVE_APPLICABILITY_SOURCE[context.applicability?.source] ||
                CVE_APPLICABILITY_SOURCE.NONE}
            </span>
          </div>
          {context.applicability?.status === "APPLIES_CONDITIONAL" ? <p>
            El CVE se gestiona de manera condicionada por decisión del analista.
            Quedan condiciones NVD pendientes de verificar; la asociación con
            software, si existe, consta en el historial.
          </p> : context.applicability?.status === "NOT_APPLICABLE" &&
            context.applicability?.source === "SYSTEM" ? <p>
            Todas las configuraciones NVD fueron excluidas con evidencia técnica
            verificable para este hardware. El sistema conserva los criterios
            y las razones de exclusión en el historial.
          </p> : context.applicability?.status === "APPLIES" &&
            context.applicability?.source === "SYSTEM" ? <p>
            La evidencia CPE y las versiones registradas satisfacen automáticamente
            las condiciones de la configuración NVD
            {context.applicability.automatic_evidence?.configuration_position
              ? " " + context.applicability.automatic_evidence.configuration_position
              : ""}.
          </p> : context.applicability?.status === "APPLIES" ? <p>
            Existe una correspondencia confirmada para este hardware con
            evidencia documentada en el historial.
          </p> : context.applicability?.status === "NOT_APPLICABLE" ? <p>
            Las configuraciones pertinentes fueron descartadas con evidencia
            registrada y vigente. Consulta el historial para revisar las decisiones.
          </p> : context.applicability?.status === "PENDING_REVIEW" &&
            (context.technical_configuration_counts?.EXCLUDED || 0) > 0 ? <p>
            {context.technical_configuration_counts.EXCLUDED} configuración(es)
            descartada(s) técnicamente con la evidencia disponible;
            {" "}{context.technical_configuration_counts.INDETERMINATE}
            alternativa(s) siguen sin resolver. No se considera descartado el
            CVE completo. El analista puede revisar la evidencia pendiente.
          </p> : <p>
            No hay evidencia completa para confirmar ni descartar el CVE.
            La falta de software inventariado no demuestra su ausencia.
            Revisa las condiciones NVD antes de decidir.
          </p>}
        </div>
        {primary ? <>
          <section className="cve-nvd-conditions cve-general-relevant-configuration"
            aria-labelledby="cve-primary-evidence">
            <div className="cve-technical-summary-heading">
              <h2 id="cve-primary-evidence">
                Condiciones NVD · Configuración {primary.position}
              </h2>
              <span className="cve-technical-tag" data-result={primary.technical_result}>
                {CVE_TECHNICAL_STATE[primary.technical_result] ||
                  CVE_TECHNICAL_STATE.INDETERMINATE}
              </span>
            </div>
            <ConfigurationReview key={primary.index}
              context={context} config={primary}
              highlight canDecide={canDecide}
              softwareAlternatives={hardwareSoftware.length ? others : []}
              onChooseSoftware={setChosenConfiguration}
              onSaved={() => {
                setNotice("Evaluación guardada. El historial se actualizó.");
                setRevision(n => n + 1);
              }}/>
          </section>
          {independentConfigs.length > 0 && <details className="cve-nvd-other-evidence">
            <summary>Otras condiciones sin hardware confirmado
              {" (" + independentConfigs.length + ")"}</summary>
            <p className="cve-muted">Estos criterios no constituyen alternativas
              de firmware para la CPU seleccionada. Se conservan por contener
              software potencialmente pertinente o decisiones previas.</p>
            {independentConfigs.map(config => <CandidateReview
              key={context.hardware_asset_id + ":independent:" + config.index}
              context={context} config={config} canDecide={canDecide}
              onSaved={() => setRevision(n => n + 1)}/>)}
          </details>}
        </> : <div className="panel cve-technical-summary">
          {context.technical_result === "EXCLUDED"
            ? <p>Las configuraciones NVD de este CVE quedan excluidas
                técnicamente para el hardware y la evidencia disponible.
                Esto no registra automáticamente una decisión del analista.
                Las configuraciones originales se conservan para auditoría.</p>
            : <p>No existen configuraciones NVD con correspondencia demostrada
                frente a los CPE vigentes de este hardware. La aplicabilidad
                permanece por verificar; las configuraciones originales se conservan.</p>}
        
        </div>}
        {candidates.length > 0 && <details className="cve-nvd-other-evidence cve-pending-alternatives">
          <summary>Software sin condición de hardware explícita ({candidates.length})</summary>
          <p className="cve-muted">
            Estas configuraciones permanecen indeterminadas. No encontrar un
            software en el inventario no prueba su ausencia ni permite excluir
            automáticamente el CVE. Consulta sus criterios antes de decidir.
          </p>
          <div className="cve-nvd-other-scroll" tabIndex={0} role="region"
            aria-label="Configuraciones NVD pendientes de verificar">
            {candidates.map(config => <CandidateReview
              key={context.hardware_asset_id + ":candidate:" + config.index}
              context={context} config={config} canDecide={canDecide}
              onSaved={() => {
                setNotice("Evaluación guardada. El historial se actualizó.");
                setRevision(n => n + 1);
              }}/>)}
          </div>
        </details>}
        {unverifiedPlatforms.length > 0 &&
          <details className="cve-nvd-other-evidence cve-platform-uncertainties">
            <summary>Plataformas NVD sin identidad comprobada
              {" (" + unverifiedPlatforms.length + ")"}</summary>
            <p className="cve-muted">Estas configuraciones no son alternativas
              de software para el hardware confirmado. No se descartan sin
              evidencia; su estado técnico permanece pendiente.</p>
            <div className="cve-nvd-other-scroll" role="region" tabIndex={0}>
              {unverifiedPlatforms.map(config => <details key={config.index}
                className="cve-pending-configuration">
                <summary>Configuración NVD {config.position}</summary>
                <Criterion item={config.tree}
                  installedSoftware={context.installed_software || []}/>
              </details>)}
            </div>
          </details>}
      </>}
  </section>;
}
