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
  selectedCveHardwareId, groupCveEvidence, selectCveOperationalGroups,
  cveApplicabilityExplanation, cveConfigurationHighlights,
  nvdCriterionIdentityBadge, currentCveSoftwareLink,
  currentCveEvaluatedSoftware, allowedCveDecisionTransitions,
  cveHistoryDecisionDescription, cveHistorySoftwareLabel,
  isSavedCveLinkSelection, cveAuditJustification,
  operationalNvdGroupBranches, nvdAlternativeGroupLabel,
  displayedNvdSoftwareCriterion, canSelectNvdCriterionSoftware,
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

function Criterion({ item, depth = 0, selection, linkedCriterion, onSelect, installId,
  installedSoftware = [], canDecide = false, savedLink = null,
  pendingUnlink = false, softwareAlternatives = [], onChooseSoftware,
  onChooseCriterion, isAlternative = false,
}) {
  if (item.kind === "CRITERION") {
    const isSoftware = ["a", "o"].includes(item.part);
    const identityBadge = nvdCriterionIdentityBadge(item);
    const currentInstallations = installedSoftware || [];
    const criterionKey = item.match_criteria_id || item.criteria;
    const isActive = canSelectNvdCriterionSoftware(item, selection, isAlternative);
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
        {onChooseCriterion && (isAlternative || selection !== criterionKey) &&
          <button type="button" className="cve-nvd-software-choice"
            onClick={() => onChooseCriterion(criterionKey)}>
            Examinar esta alternativa NVD
          </button>}
        {isActive && <>
          <p className="cve-review-note">
            Alternativa NVD examinada: <code>{item.criteria}</code>
          </p>
          {currentInstallations.length ? <>
          <p className="cve-nvd-association-title">
            Software registrado como instalado en este hardware
          </p>
          {currentInstallations.map(sw => {
            const isChecked = linkedCriterion === criterionKey &&
              installId === String(sw.installation_id);
            const typeMatches = item.part === "a" ? sw.software_type === "APPLICATION"
              : ["FIRMWARE", "OS"].includes(sw.software_type);
            const identityProven = item.technical_identity === "MATCHED" &&
              Number(item.technical_software_installation_id) ===
                Number(sw.installation_id);
            const persisted = isChecked && savedLink?.installationId ===
              String(sw.installation_id) && savedLink.criterionKey === criterionKey;
            return <div className="cve-installed-software-entry" key={sw.installation_id}>
              <div className="cve-installed-software-meta">
                <div className="cve-association-name">
                  <strong>{sw.software_name}</strong>
                  <small>Software #{sw.software_asset_id} · Instalación #{sw.installation_id}
                    {" · Versión "}{sw.version || "desconocida"}</small>
                </div>
                <span className="cve-software-status is-installed">
                  {identityProven ? "Identidad CPE comprobada" :
                    typeMatches ? "Instalado · CPE sin comprobar" :
                      "Instalado · tipo diferente"}
                </span>
              </div>
              <label className="cve-criterion-selection cve-software-association">
                <input type="checkbox" disabled={!canDecide} checked={isChecked}
                  onChange={event => onSelect(
                    event.target.checked ? criterionKey : "",
                    event.target.checked ? String(sw.installation_id) : ""
                  )}/>
                <span>{persisted && savedLink.evidenceOnly
                  ? "Software inventariado revisado; esto no confirma vulnerabilidad"
                  : persisted
                    ? savedLink.source === "SYSTEM"
                      ? "CVE asociado automáticamente · Desmarcar para revisar"
                      : "CVE asociado por el analista · Desmarcar para revisar"
                    : "Seleccionar software para esta evaluación"}</span>
              </label>
            </div>;
          })}
          {pendingUnlink && <p className="cve-cancel-pending" role="status">
            Instalación desmarcada provisionalmente. El cambio solo se registra
            si guardas una nueva decisión.
          </p>}
          <p className="cve-muted">
            {savedLink?.evidenceOnly
              ? "Identificar una instalación evaluada no significa que sea vulnerable."
              : "La vinculación manual no confirma por sí sola la versión vulnerable."}
          </p>
        </> : <p className="cve-muted">
          No hay software inventariado en este hardware. Puedes registrar una
          evaluación sin vincular ninguna instalación.
        </p>}
        </>}
      </div>}

      <details className="cve-nvd-proof"
        open={isAlternative || isActive}>
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
  const { shown, hidden } = operationalNvdGroupBranches(item, selection);
  const firstSoftware = shown.findIndex(child => Boolean(vulnerableSoftwareCriterion(child)));
  const renderChild = (child, i, alternative = isAlternative) =>
    <Criterion key={(child.match_criteria_id || child.criteria || "grupo") + ":" + i}
      item={child} depth={depth + 1} selection={selection}
      linkedCriterion={linkedCriterion} onSelect={onSelect} installId={installId}
      installedSoftware={installedSoftware} canDecide={canDecide}
      savedLink={savedLink} pendingUnlink={pendingUnlink}
      softwareAlternatives={i === firstSoftware ? softwareAlternatives : []}
      onChooseSoftware={onChooseSoftware}
      onChooseCriterion={onChooseCriterion}
      isAlternative={alternative}/>;

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
        {hidden.map((child, i) => renderChild(child, i, true))}
      </div>
    </details>}
  </div>;
}

function ConfigurationReview({ context, config, onSaved, canDecide, highlight = false,
  softwareAlternatives = [], onChooseSoftware }) {
  const globalDecision = context?.hardware_cve_decision;
  const last = globalDecision || config.latest_assessment;
  // A hardware-wide verdict affects applicability, but its selected NVD leaf
  // only belongs to the configuration where it was recorded.
  const localDecision = globalDecision?.configuration_index === config.index
    ? globalDecision : config.latest_assessment;
  const status = last?.effective_status || "PENDING_REVIEW";
  const firmwareCriterion = vulnerableSoftwareCriterion(config.tree);
  const manuallyLinked = globalDecision &&
    globalDecision.configuration_index === config.index && !globalDecision.stale &&
    globalDecision.status === "APPLIES" &&
    globalDecision.software_installation_id && firmwareCriterion ? {
      installationId: String(globalDecision.software_installation_id),
      criterionKey: globalDecision.selected_nvd_criterion?.key ||
         firmwareCriterion.match_criteria_id || firmwareCriterion.criteria,
      source: "ANALYST",
    } : null;
  const savedPositive = globalDecision
    ? manuallyLinked : currentCveSoftwareLink(config, context);
  const evaluatedLink = globalDecision
    ? null : currentCveEvaluatedSoftware(config, context);
  const reviewed = (localDecision?.reviewed_software || [])[0];
  const reviewedLink = reviewed && localDecision?.selected_nvd_criterion ? {
    installationId: String(reviewed.installation_id ||
      reviewed.software_installation_id),
    criterionKey: localDecision.selected_nvd_criterion.key,
    source: "ANALYST", evidenceOnly: true,
  } : null;
  const savedLink = savedPositive || reviewedLink || evaluatedLink;
  // null means no edit; an empty draft overrides the persisted check only locally.
  const [draftLink, setDraftLink] = useState(null);
  const [focusedCriterion, setFocusedCriterion] = useState(
    localDecision?.selected_nvd_criterion?.key || ""
  );
  const [reviewOpen, setReviewOpen] = useState(false);
  const [choice, setChoice] = useState("");
  const [justification, setJustification] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const justificationRef = useRef(null);
  const currentLink = draftLink === null ? savedLink : draftLink;
  const installId = currentLink?.installationId || "";
  const linkedCriterion = currentLink?.criterionKey || "";
  const initialCriterion = displayedNvdSoftwareCriterion(config.tree);
  const selectedCriterion = focusedCriterion || linkedCriterion ||
    initialCriterion?.match_criteria_id || initialCriterion?.criteria || "";
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
  const checked = Boolean(linkedCriterion);
  const canConfirm = canReview || canConditional ||
    config.manual_confirm_supported || config.hardware_scope === "MATCHED" ||
    (reviewOpen && config.technical_result === "COMPATIBLE");
  const linkedInstallationId = checked ? installId : "";
  const positiveConflict = (
    config.technical_result === "COMPATIBLE" ||
    (context?.technical_result === "COMPATIBLE")
  ) && ["NOT_MATCH", "CONDITIONAL"].includes(choice);
  const canDiscard = canDecide &&
    ["MATCHED", "UNSCOPED"].includes(config.hardware_scope) &&
    (config.hardware_scope === "MATCHED" ||
      config.technical_result !== "EXCLUDED" ||
      (last?.source === "ANALYST" && !last?.stale &&
        ["APPLIES", "APPLIES_CONDITIONAL"].includes(last.status))) &&
    (canReview || canConditional || config.technical_result === "COMPATIBLE");
  // A non-empty explanation is required, but its quality cannot be judged
  // by character count. The backend still verifies hardware/software scope.
  const invalid = !justification.trim() ||
    (unverifiedPlatform && choice === "CONDITIONAL" && !linkedInstallationId);

  function reset() {
    setChoice(""); setDraftLink(null); setReviewOpen(false);
    setJustification(""); setError("");
  }
  function beginReopen() {
    setReviewOpen(true);
    setDraftLink(null);
    setChoice("");
    setJustification(""); setError("");
  }
  function updateAssociation(criterionKey, installationId) {
    if (criterionKey) setFocusedCriterion(criterionKey);
    if (savedLink && !criterionKey && !installationId) {
      setReviewOpen(true);
      setDraftLink({ criterionKey: "", installationId: "" });
      setChoice("CONDITIONAL");
      setJustification("");
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
    setChoice(""); setJustification(""); setError("");
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
          (selectedId ? Number(selectedId) : null),
        selected_nvd_criterion: selectedCriterion,
        inventory_declared_complete: false,
        technical_override_acknowledged: (
          choice === "CONFIRMED" ||
          (technicalConflict && ["CONFIRMED", "CONDITIONAL"].includes(choice)) ||
          positiveConflict ||
          (context?.technical_result === "EXCLUDED" &&
            ["CONFIRMED", "CONDITIONAL"].includes(choice))
        ),
        // The informed Save action + mandatory justification is the single
        // explicit analyst confirmation. No redundant acknowledgement checkbox.
        platform_unverified_acknowledged: unverifiedPlatform &&
          choice === "CONDITIONAL" && Boolean(linkedInstallationId),
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
  const previousCriterion = localDecision?.selected_nvd_criterion?.key || "";
  const priorReviewed = (localDecision?.reviewed_software || [])[0];
  const previousInstallation = localDecision?.software_installation_id ||
    priorReviewed?.installation_id || priorReviewed?.software_installation_id || "";
  const evidenceChanged = selectedCriterion !== previousCriterion ||
    String(selectedId || "") !== String(previousInstallation || "");
  const allowedChanges = [
    ...allowedCveDecisionTransitions(currentStatus),
    ...(evidenceChanged && currentStatus === "APPLIES" ? ["CONFIRMED"] : []),
    ...(evidenceChanged && currentStatus === "APPLIES_CONDITIONAL" ? ["CONDITIONAL"] : []),
    ...(evidenceChanged && currentStatus === "NOT_APPLICABLE" ? ["NOT_MATCH"] : []),
  ];
  const showChoices = canDecide && (!lockedDecision || reviewOpen);
  return <>
    <Criterion item={config.tree} selection={selectedCriterion}
      linkedCriterion={linkedCriterion} onSelect={updateAssociation}
      installId={installId} installedSoftware={context.installed_software || []}
      canDecide={canDecide && (canConfirm || canReopen || canDiscard)}
      savedLink={savedLink} pendingUnlink={pendingUnlink}
      softwareAlternatives={softwareAlternatives}
      onChooseSoftware={onChooseSoftware}
      onChooseCriterion={key => {
        setFocusedCriterion(key);
        // Changing NVD alternative must not silently reuse the old software link.
        setDraftLink({ criterionKey: "", installationId: "" });
        setReviewOpen(true);
        setChoice("");
        setJustification("");
        setError("");
      }}/>
    <div className="panel cve-nvd-decision">
    <div className="cve-nvd-joint-title">
      <h3>{highlight ? "Correspondencia del CVE" :
        "Correspondencia · Configuración " + config.position}</h3>
      <span className="cve-status-label" data-status={status}>
        {STATE[status] || status}
        {last?.source === "SYSTEM" && " · Automático"}</span>
    </div>
    {last?.stale && <p className="cve-review-note" role="status">
      La evidencia del inventario cambió. La decisión anterior permanece en el historial.
    </p>}
    {last?.source === "ANALYST" && last.status === "PENDING_REVIEW" &&
      !last.stale && <p className="cve-review-note" role="status">
        Revisión abierta por el analista. La evidencia técnica NVD sigue disponible.
      </p>}
    {technicalConflict && reviewOpen && !choice &&
      <p className="cve-review-note" role="status">
        NVD excluye esta configuración con la evidencia actual.
        Puedes registrar otra conclusión y explicar el motivo.
      </p>}
    {unverifiedPlatform && showChoices && !choice &&
      <p className="cve-review-note">
        La plataforma NVD no tiene una identidad CPE confirmada en este hardware.
      </p>}
    {(canReopen || showChoices) && <div className="cve-nvd-actions">
      {canReopen && !reviewOpen && <button type="button"
        className="cve-nvd-action" onClick={beginReopen}>
        Reabrir evaluación</button>}
      {showChoices && <>
        {canConfirm && allowedChanges.includes("CONFIRMED") && <button type="button"
          className={"cve-nvd-action" + (choice === "CONFIRMED" ? " selected" : "")}
          onClick={() => { setChoice("CONFIRMED"); setReviewOpen(true); setJustification(""); }}>
          Confirmar correspondencia</button>}
        {allowedChanges.includes("CONDITIONAL") &&
          (canConditional || canConfirm || canReopen) && <button type="button"
          className={"cve-nvd-action" + (choice === "CONDITIONAL" ? " selected" : "")}
          onClick={() => {
            setChoice("CONDITIONAL"); setReviewOpen(true); setJustification("");
            if (savedLink && !draftLink) setDraftLink({criterionKey:"", installationId:""});
          }}>
          Correspondencia parcial</button>}
        {canDiscard && allowedChanges.includes("NOT_MATCH") &&
          <button type="button" className={"cve-nvd-action" +
          (choice === "NOT_MATCH" ? " selected" : "")}
          onClick={() => {
            setChoice("NOT_MATCH"); setReviewOpen(true); setJustification("");
          }}>No corresponde</button>}
      </>}
    </div>}
    {choice === "CONDITIONAL" && <p className="cve-review-note" role="status">
      Correspondencia parcial: {linkedInstallationId
        ? "la instalación quedará registrada como revisada, sin considerarla vulnerable."
        : "no se vinculará ninguna instalación de software."}
    </p>}
    {!canDiscard && canDecide && !lockedDecision &&
      <p className="cve-muted">No hay evidencia suficiente para descartar
        manualmente esta configuración.</p>}
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
        <p className="cve-review-note" role="status">
          El resultado técnico NVD es diferente de esta decisión.
          Si la guardas, quedarán registrados tu criterio y su justificación;
          la evidencia automática se conservará.
        </p>}
      {unverifiedPlatform && choice === "CONDITIONAL" &&
        <p className="cve-review-note" role="status">
          La plataforma NVD no está identificada para este hardware.
          La asociación quedará condicionada a la evidencia que describas.
        </p>}
      <label>Justificación de la decisión
        <textarea ref={justificationRef} rows={3} required maxLength={1000}
          aria-invalid={pendingUnlink && !justification.trim()}
          value={justification}
          onChange={event => setJustification(event.target.value)}
          placeholder={choice === "UNKNOWN"
            ? "Explica qué necesitas revisar..."
            : choice === "CONDITIONAL"
              ? "Explica qué falta verificar o por qué no vinculas esta instalación..."
              : choice === "NOT_MATCH"
                ? "Describe la comprobación que permite descartar esta configuración..."
                : "Explica las evidencias de la correspondencia..."}/>
      </label>
      {choice === "NOT_MATCH" && <p className="cve-review-note">
        La decisión se aplicará al CVE de este hardware y se conservará
        la justificación. La evidencia NVD original no se modifica.
      </p>}
      <div className="cve-form-actions">
        <button type="submit" className="button-primary"
          disabled={saving || invalid}>{saving ? "Guardando..." :
          choice === "NOT_MATCH" ? "Guardar No corresponde" :
            choice === "CONDITIONAL" ? "Guardar correspondencia parcial" :
            choice === "CONFIRMED" ? "Confirmar correspondencia" :
            "Guardar evaluación"}</button>
        <button type="button" className="button-secondary" disabled={saving}
          onClick={reset}>Cancelar</button>
      </div>
    </form>}
    {error && <p className="error-message" role="alert">{error}</p>}
    <details className="cve-general-history">
      <summary>Historial de decisiones ({config.history?.length || 0})</summary>
      {config.history?.length ? <ol className="cve-history">
        {config.history.map(item => <li key={item.id}>
          <div className="cve-history-heading">
            <strong>{STATE[item.status] || item.status}</strong>
            <span className="cve-muted"> · {item.source === "SYSTEM"
              ? "Automático" : "Analista"}</span>
          </div>
          <p className="cve-history-byline">
            {item.source === "SYSTEM" ? "VISOR OT" :
              (item.decided_by || "Usuario no disponible")}
            {" · "}{localizedTimestamp(item.decided_at)}
          </p>
          {cveHistorySoftwareLabel(item).map(row =>
            <div className="cve-history-software" key={row.key}>
              <strong>{row.label}</strong>
              {row.detail && <small>{row.detail}</small>}
            </div>)}
          {item.status === "APPLIES_CONDITIONAL" &&
            !item.software_installation_id &&
            !cveHistorySoftwareLabel(item).length &&
            <p className="cve-muted">Sin software vinculado.</p>}
          <p className="cve-history-reason">
            {cveHistoryDecisionDescription(item)}
          </p>
          {item.selected_nvd_criterion && <p className="cve-review-note">
            Alternativa NVD revisada: <code>{item.selected_nvd_criterion.criteria}</code>
          </p>}
          {item.manual_applicability_evidence && <p className="cve-review-note">
            Confirmación manual del CVE para el hardware; no se ha verificado
            una identidad CPE de software afectado.
          </p>}
          {item.technical_override && <p className="cve-review-note">
            La conclusión del analista es diferente del resultado técnico
            NVD ({CVE_TECHNICAL_STATE[item.technical_override.technical_result] ||
              item.technical_override.technical_result}). Ambos quedan registrados.
          </p>}
          {item.stale && <p className="cve-review-note">
            Evidencia histórica: el inventario o las condiciones NVD cambiaron.
          </p>}
          {(item.justification || item.conditional_evidence) &&
            <div className="cve-nvd-history-detail">
              <p className="cve-history-evidence-label">Fundamento y evidencia de la decisión</p>
              <p>{cveAuditJustification(item.justification, item.source)}</p>
              {item.status === "APPLIES_CONDITIONAL" && item.conditional_evidence &&
                <p>Condiciones NVD relacionadas:
                  {" "}{(item.conditional_evidence.vulnerable_criteria || [])
                    .map(row => row.criteria).join("; ") || "Sin criterios adicionales"}
                </p>}
            </div>}
        </li>)}
      </ol> : <p className="cve-muted">No hay decisiones registradas.</p>}
    </details>
  </div></>;
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

  const { reviewPool, hardwareSoftware } =
    selectCveOperationalGroups(context);

  const { primary: suggestedPrimary } = groupCveEvidence(reviewPool);
  const primary = reviewPool.find(row => row.index === chosenConfiguration) ||
    suggestedPrimary;
  const others = reviewPool.filter(row => row.index !== primary?.index);
  const evidenceHighlights = cveConfigurationHighlights(primary);
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
              {CVE_EVALUATION_STATE[context.applicability?.status] ||
                  CVE_EVALUATION_STATE.PENDING_REVIEW}
              {" · "}{CVE_APPLICABILITY_SOURCE[context.applicability?.source] ||
                CVE_APPLICABILITY_SOURCE.NONE}
            </span>
          </div>
          <p className="cve-applicability-explanation">
            {cveApplicabilityExplanation(context)}
          </p>
          {evidenceHighlights.length > 0 &&
            <ul className="cve-evidence-highlights"
              aria-label="Evidencia principal de la configuración seleccionada">
              {evidenceHighlights.map(fact =>
                <li key={fact.label} data-kind={fact.kind}>{fact.label}</li>)}
            </ul>}
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
      </>}
  </section>;
}
