import { useEffect, useState } from "react";
import { Link, useOutletContext, useParams, useSearchParams } from "react-router-dom";
import {
  listCveHardware, readCveCatalogue, readGeneralCveAssessment,
  createGeneralCveAssessment, ensureAutomaticCveAssessment,
} from "../api/vulnerabilities";
import SuccessNotice from "../components/SuccessNotice";
import { getAssets } from "../api/assets";
import CveAnalysis from "./CveAnalysis";
import {
  CVE_SEVERITY, CVE_TECHNICAL_STATE, CVE_EVALUATION_STATE,
  CVE_APPLICABILITY_SOURCE,
  selectedCveHardwareId, groupCveEvidence,
  nvdCriterionIdentityBadge, cveAuditJustification,
  relevantNvdChildren,
} from "../utils/cveCataloguePresentation";
import {
  localizedTimestamp, contextualCveActionOptions, versionConstraintsText,
} from "../utils/cveAssessmentPresentation";

const STATE = {
  APPLIES: "Aplica a esta configuración",
  APPLIES_CONDITIONAL: "Aplica condicionada",
  NOT_APPLICABLE: "No aplica a esta configuración",
  PENDING_REVIEW: "Pendiente de revisión",
};
const PLAIN = { h: "Hardware", o: "Firmware / sistema operativo", a: "Software" };


/** Active software inventory; only an eligible installation can be linked. */
function SoftwareInventoryPicker({ part, softwareAssets, installedSoftware, eligibleInstallationIds,
  selectedAssetId, selectedInstallationId, onChoose, canDecide }) {
  const types = part === "a" ? ["APPLICATION"] : ["FIRMWARE", "OS"];
  const installations = (installedSoftware || []).filter(sw => types.includes(sw.software_type));
  const installedIds = new Set(installations.map(sw => sw.software_asset_id));
  const choices = [
    ...installations.map(sw => ({
      key: "installation-" + sw.installation_id, id: sw.software_asset_id,
      installationId: sw.installation_id, name: sw.software_name,
      version: sw.version, installed: true,
      eligible: eligibleInstallationIds.includes(sw.installation_id),
    })),
    ...(softwareAssets || []).filter(asset => asset.asset_type === "SOFTWARE" &&
      types.includes(asset.software?.software_type) && !installedIds.has(asset.id))
      .map(asset => ({
        key: "asset-" + asset.id, id: asset.id, installationId: null,
        name: asset.name, version: asset.software?.version, installed: false,
        eligible: false,
      })),
  ];
  const selected = choices.find(row => row.id === selectedAssetId &&
    String(row.installationId || "") === String(selectedInstallationId || ""));
  return <div className="cve-software-picker-wrapper">
    <span className="cve-software-picker-label">Software del inventario</span>
    <details className="cve-software-picker" key={selected?.key || "none"}>
      <summary>
        <span>{selected ? selected.name : "Seleccionar activo de software..."}</span>
        {selected && <span className={"cve-software-status " +
          (selected.installed ? "is-installed" : "not-installed")}>
          {selected.installed ? "Instalado" : "Sin instalar"}</span>}
      </summary>
      <div className="cve-software-picker-options">
        {choices.length ? choices.map(row =>
          <button key={row.key} type="button" disabled={!canDecide}
            className={"cve-software-option" +
              (selected?.key === row.key ? " is-selected" : "")}
            onClick={event => {
              event.currentTarget.closest("details").open = false;
              onChoose(row.id, row.eligible ? row.installationId : null);
            }}>
            <span className="cve-software-option-text">
              <strong>{row.name}</strong>
              <small>Software #{row.id} · Versión {row.version || "sin registrar"}</small>
            </span>
            <span className={"cve-software-status " +
              (row.installed ? "is-installed" : "not-installed")}>
              {row.installed ? "Instalado" : "Sin instalar"}</span>
          </button>
        ) : <p className="cve-muted">No hay activos de software disponibles de este tipo.</p>}
      </div>
    </details>
    {selected && !selected.eligible && <p className="cve-muted">
      {selected.installed
        ? "Este software está instalado, pero no tiene correspondencia CPE vigente suficiente para confirmar este criterio."
        : "Este software está inventariado, pero no consta instalado en este hardware."}
      {" "}Puedes mantener la evaluación condicionada; no se creará ninguna instalación.
    </p>}
    {selected?.eligible && <p className="cve-muted">
      Instalación #{selected.installationId} respaldada por evidencia CPE vigente.
      La evaluación de todas las condiciones NVD sigue siendo obligatoria.
    </p>}
  </div>;
}

function Criterion({ item, depth = 0, selection, onSelect, installId, onInstall, selectedAssetId, softwareAssets = [], installedSoftware = [], eligibleInstallationIds = [], canDecide = false }) {
  if (item.kind === "CRITERION") {
    const isSoftware = ["a", "o"].includes(item.part);
    const identityBadge = nvdCriterionIdentityBadge(item);
    return <details className="cve-nvd-condition cve-general-criterion">
      <summary className="cve-nvd-condition-summary">
        <div className="cve-nvd-condition-heading">
        <div className="cve-nvd-condition-tags">
          <h3>{PLAIN[item.part] || "Componente NVD"}</h3>
          <span className={"cve-nvd-category " + (
            item.vulnerable ? "cve-nvd-vulnerable" : "cve-nvd-platform"
          )}>{item.vulnerable ? "Componente vulnerable" : "Condición de plataforma"}</span>
        </div>
        <span className="cve-condition-state"
          data-state={identityBadge.state}
          title="La identidad del producto se comprueba por CPE; el rango de versión NVD se evalúa por separado.">
          {identityBadge.label}
        </span>
      </div>
        <p className="cve-nvd-product">{String(item.criteria || "").split(":")
          .slice(3, 5).join(" · ").replaceAll("_", " ") || "Criterio NVD"}</p>
      </summary>
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
        <p>{item.technical_reason || "No hay evidencia suficiente para resolver el criterio."}</p>
        {item.technical_matched_cpe && <p>
          CPE confirmado usado: <code>{item.technical_matched_cpe}</code>
        </p>}
        {item.technical_software_asset_id && <p>
          Software #{item.technical_software_asset_id}
          {item.technical_software_installation_id &&
            " · Instalación #" + item.technical_software_installation_id}
        </p>}
        {item.technical_installed_version && <p>Versión comprobada: {
          item.technical_installed_version
        }</p>}
      </div>
      {isSoftware && item.vulnerable && onSelect && <div className="cve-nvd-selection">
        <label className="cve-criterion-selection">
          <input type="checkbox" disabled={!canDecide}
            checked={selection === (item.match_criteria_id || item.criteria)}
            onChange={event => onSelect(event.target.checked
              ? (item.match_criteria_id || item.criteria) : "")}/>
          <span>He identificado este componente en el entorno OT</span>
        </label>
        {selection === (item.match_criteria_id || item.criteria) && <>
          <p className="cve-muted">Selecciona el activo del inventario correspondiente.
            Solo una instalación vigente con CPE pertinente permite vincularlo al CVE.</p>
          <SoftwareInventoryPicker part={item.part} softwareAssets={softwareAssets}
            installedSoftware={installedSoftware} eligibleInstallationIds={eligibleInstallationIds}
            selectedAssetId={selectedAssetId} selectedInstallationId={installId}
            onChoose={onInstall} canDecide={canDecide}/>
        </>}
      </div>}
    </details>;
  }
  if (item.kind !== "GROUP") {
    return <p className="cpe-warning">NVD contiene una estructura que debe revisarse.</p>;
  }
  const operator = item.operator === "AND" ? "Y" : "O";
  const { visible, alternatives } = relevantNvdChildren(item);
  // Promote a selected OR alternative for review, without changing NVD's logic.
  const hasSelected = node => node?.kind === "CRITERION"
    ? (node.match_criteria_id || node.criteria) === selection
    : (node?.children || []).some(hasSelected);
  const promoted = item.operator === "OR" && selection
    ? alternatives.find(hasSelected) : null;
  const shown = promoted ? [promoted, ...visible.filter(x => x !== promoted)] : visible;
  const otherChoices = promoted
    ? alternatives.filter(x => x !== promoted) : alternatives;
  return <div className={"cve-general-group " + (depth ? "cve-general-nested" : "")}>
    <div className="cve-general-logic">
      <strong>{operator === "Y" ? "Se requieren todas las condiciones" :
        "Se permite cualquiera de las alternativas"}</strong>
      {item.negate && <span className="cpe-warning">
        Negación NVD: el resultado del grupo se invierte (requiere revisión).</span>}
    </div>
    {shown.length ? shown.map((child, i) =>
      <div key={i}>
        {i > 0 && <div className="cve-nvd-plus" aria-label={"Operador " + operator}>
          {operator}</div>}
        <Criterion item={child} depth={depth + 1} selection={selection} onSelect={onSelect} installId={installId} onInstall={onInstall} selectedAssetId={selectedAssetId} softwareAssets={softwareAssets} installedSoftware={installedSoftware} eligibleInstallationIds={eligibleInstallationIds} canDecide={canDecide}/>
      </div>) : <p className="cve-muted">No hay criterios detallados en este grupo.</p>}
    {otherChoices.length > 0 && <details className="cve-nvd-other-evidence">
      <summary>Otras alternativas NVD ({otherChoices.length})</summary>
      {otherChoices.map((child, i) =>
        <Criterion key={i} item={child} depth={depth + 1} selection={selection} onSelect={onSelect} installId={installId} onInstall={onInstall} selectedAssetId={selectedAssetId} softwareAssets={softwareAssets} installedSoftware={installedSoftware} eligibleInstallationIds={eligibleInstallationIds} canDecide={canDecide}/>)}
    </details>}
  </div>;
}

function ConfigurationReview({ context, config, softwareAssets, onSaved, canDecide, highlight = false }) {
  const last = config.latest_assessment;
  const status = last?.effective_status || "PENDING_REVIEW";
  const [choice, setChoice] = useState("");
  const [installId, setInstallId] = useState("");
  const [softwareAssetId, setSoftwareAssetId] = useState(null);
  const [selectedCriterion, setSelectedCriterion] = useState("");
  const [justification, setJustification] = useState("");
  const [complete, setComplete] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
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
  const staleDecision = Boolean(last?.stale &&
    ["APPLIES", "APPLIES_CONDITIONAL", "NOT_APPLICABLE"].includes(last.status));
  const canReopen = staleDecision && canDecide;
  const canReview = config.review_supported && canDecide;
  const canConditional = config.conditional_supported && canDecide &&
    config.technical_result === "INDETERMINATE";
  const checked = Boolean(selectedCriterion);
  const canConfirm = canReview || canConditional;
  const hasVerifiedSoftware = checked && Boolean(installId);
  const confirmationVerdict = hasVerifiedSoftware && canReview ? "CONFIRMED" : "CONDITIONAL";
  const partialAvailable = canConditional;
  const enableConfirm = canDecide && (confirmationVerdict === "CONFIRMED" || partialAvailable);
  const confirmationLabel = confirmationVerdict === "CONFIRMED"
    ? "Confirmar correspondencia" : "Correspondencia parcial";
  const canDiscard = canReview &&
    contextualCveActionOptions(config, last).some(option => option.key === "NOT_MATCH");
  const canUndo = canReview || canReopen;
  const noSelected = choice === "CONFIRMED" && !selectedId;
  const invalid = !justification.trim() || noSelected ||
    (choice === "CONDITIONAL" && justification.trim().length < 20);

  function reset() {
    setChoice(""); setSelectedCriterion(""); setInstallId(""); setSoftwareAssetId(null);
    setJustification(""); setComplete(false); setError("");
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
          choice === "CONDITIONAL" ? (installId ? Number(installId) : null) :
          (selectedId ? Number(selectedId) : null),
        inventory_declared_complete: choice === "NOT_MATCH" && complete,
        justification: justification.trim(),
      });
      reset();
      onSaved();
    } catch (err) {
      setError("No se registró la evaluación: " + err.message);
    } finally {
      setSaving(false);
    }
  }
  return <>
    <Criterion item={config.tree} selection={selectedCriterion}
      onSelect={value => { setSelectedCriterion(value); setInstallId(""); setSoftwareAssetId(null); setChoice(""); }}
      installId={installId} selectedAssetId={softwareAssetId}
      onInstall={(assetId, installationId) => {
        setSoftwareAssetId(assetId); setInstallId(installationId ? String(installationId) : "");
        setChoice("");
      }}
      softwareAssets={softwareAssets} installedSoftware={context.installed_software || []}
      eligibleInstallationIds={[
        ...(config.candidate_installation_ids || []),
        ...(config.review_installation_id ? [config.review_installation_id] : []),
      ]}
      canDecide={canDecide}/>
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
    {last?.stale && <p className="cpe-warning">
      La evaluación previa conserva su registro histórico, pero la evidencia cambió.
      Se necesita revisar nuevamente.</p>}
    {!config.review_supported && <p className="cpe-warning" role="status">
      Esta configuración no permite confirmar automáticamente todas las
      condiciones NVD. {canConditional
        ? "El analista puede registrarla como Aplica condicionada, justificando qué falta verificar."
        : "La revisión permanece pendiente."}</p>}
    {config.review_installation_id && config.technical_result === "COMPATIBLE" &&
      <p className="cve-muted">
        El firmware instalado satisface este criterio NVD; no se puede
        descartar mientras las evidencias sean vigentes.
      </p>}
    {(canConfirm || canDiscard || canUndo) && <div className="cve-nvd-actions">
      {canConfirm && <button type="button"
        disabled={!enableConfirm}
        title={!enableConfirm ? "No hay evidencia suficiente para registrar una evaluación condicionada." : ""}
        data-action={confirmationVerdict}
        className={"cve-nvd-action" +
        (["CONFIRMED", "CONDITIONAL"].includes(choice) ? " selected" : "")}
        onClick={() => { setChoice(confirmationVerdict); setJustification(""); }}>
        {confirmationLabel}</button>}
      {canDiscard && <button type="button" className={"cve-nvd-action" +
        (choice === "NOT_MATCH" ? " selected" : "")}
        onClick={() => { setChoice("NOT_MATCH"); setJustification(""); }}>
        Descartar correspondencia</button>}
      {canUndo && last && <button type="button" className="cve-nvd-action"
        onClick={() => setChoice("UNKNOWN")}>Reabrir evaluación</button>}
    </div>}
    {choice === "CONDITIONAL" && <p className="cve-muted" role="status">
      Resultado previsto: Aplica condicionada. Se registrarán las condiciones
      pendientes sin atribuir software no instalado a este hardware.
    </p>}
    {!canDiscard && canDecide && <p className="cve-muted">
      El descarte no está habilitado para esta estructura NVD: exige evidencia
      negativa suficiente de todas las condiciones y alternativas aplicables.
    </p>}
    {!canDecide && <p className="cve-muted">
      El rol actual permite consultar, pero no registrar decisiones.</p>}
    {choice && (canReview || canConditional ||
      (canReopen && choice === "UNKNOWN")) &&
      <form className="cve-compact-review"
      onSubmit={submit}>
      {installations.length > 1 && choice === "NOT_MATCH" && <label>
        Instalación que deseas evaluar
        <select value={installId} onChange={event => setInstallId(event.target.value)}>
          <option value="">Selecciona una instalación</option>
          {installations.map(sw => <option key={sw.installation_id}
            value={sw.installation_id}>
            {sw.software_name} · Instalación #{sw.installation_id}</option>)}
        </select>
      </label>}
      <label>Justificación de la decisión
        <textarea rows={3} required maxLength={1000} value={justification}
          onChange={event => setJustification(event.target.value)}
          placeholder="Describe las evidencias que sustentan la correspondencia..."/>
      </label>
      {choice === "NOT_MATCH" && <div className="cve-attestation">
        <label><input type="checkbox" checked={complete}
          onChange={event => setComplete(event.target.checked)}/>
          He comprobado que el inventario del software instalado está completo.</label>
        {installations.length !== 1 && <p>
          Hay varias instalaciones o ninguna registrada; no puede declararse
          «No aplica» con una única comprobación.</p>}
      </div>}
      <div className="cve-form-actions">
        <button type="submit" className="button-primary"
          disabled={saving || invalid}>{saving ? "Guardando..." :
          choice === "UNKNOWN" ? "Confirmar y deshacer" : "Guardar evaluación"}</button>
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

export default function CveDetail() {
  const { cveId } = useParams();
  const [searchParams, setSearchParams] = useSearchParams();
  const requestedHardware = searchParams.get("hardware");
  const { user } = useOutletContext();
  const canDecide = ["ADMIN", "ANALYST"].includes(user?.role);
  const [cve, setCve] = useState(null);
  const [hardware, setHardware] = useState([]);
  const [selectedHardware, setSelectedHardware] = useState("");
  const [context, setContext] = useState(null);
  const [softwareAssets, setSoftwareAssets] = useState([]);
  const [softwareInventoryError, setSoftwareInventoryError] = useState("");
  useEffect(() => {
    let mounted = true;
    getAssets("ACTIVE").then(assets => {
      if (mounted) setSoftwareAssets((assets || []).filter(a => a.asset_type === "SOFTWARE"));
    }).catch(error => {
      if (mounted) setSoftwareInventoryError(error.message);
    });
    return () => { mounted = false; };
  }, []);
  const [loading, setLoading] = useState(true);
  const [contextLoading, setContextLoading] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [revision, setRevision] = useState(0);

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

  function changeHardware(id) {
    setSelectedHardware(id);
    setContext(null);
    setNotice("");
    const next = new URLSearchParams(searchParams);
    next.set("hardware", id);
    setSearchParams(next, { replace: true });
  }

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
        if (canDecide && data.applicability?.source === "SYSTEM") {
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
  const { primary, others } = groupCveEvidence(configs);
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

    <div className="cve-general-hardware-select">
      <label htmlFor="cve-hardware-choice">Hardware a evaluar</label>
      {hardware.length ? <select id="cve-hardware-choice" value={selectedHardware}
        onChange={event => changeHardware(event.target.value)}>
        {hardware.map(row => <option key={row.hardware_id} value={row.hardware_id}>
          #{row.hardware_id} · {row.hardware_name}</option>)}
      </select> : <p className="cve-muted">
        Aún no hay hardware relacionado mediante búsquedas o evaluaciones.
        Inicia una búsqueda CVE para asociar un equipo y revisar sus condiciones.</p>}
    </div>

    {contextLoading ? <p className="cve-muted">Cargando condiciones del inventario...</p>
      : context && Number(context.hardware_asset_id) === Number(selectedHardware) && <>
        <p className="cve-general-context-summary">
          Evaluación de este CVE para el hardware #{context.hardware_asset_id}.
          {" "}Se muestra la configuración NVD más pertinente para este equipo.
          {others.length > 0 && <>
            {" "}Las otras {others.length} configuraciones pertinentes permanecen
            disponibles en una sección desplegable.
          </>}
        </p>
        <div className="panel cve-technical-summary">
          <div className="cve-technical-summary-heading">
            <h2>Aplicabilidad del CVE · Este hardware</h2>
            <span className="cve-catalogue-evaluation-status"
              data-status={context.applicability?.status || "PENDING_REVIEW"}>
              {CVE_EVALUATION_STATE[context.applicability?.status] ||
                CVE_EVALUATION_STATE.PENDING_REVIEW}
              {" · "}{CVE_APPLICABILITY_SOURCE[context.applicability?.source] ||
                CVE_APPLICABILITY_SOURCE.NONE}
            </span>
          </div>
          {context.applicability?.status === "APPLIES_CONDITIONAL" ? <p>
            El analista decidió gestionar este CVE de manera condicionada.
            La relación con el hardware está acreditada, pero quedan
            condiciones por verificar. Consulta su justificación en el historial.
          </p> : context.applicability?.source === "SYSTEM" ? <p>
            Los CPE y la versión instalada satisfacen la configuración NVD
            {context.applicability.automatic_evidence?.configuration_position
              ? " " + context.applicability.automatic_evidence.configuration_position
              : ""}. El sistema registra automáticamente el motivo en el
            historial de esta configuración.
          </p> : <p>
            No hay confirmación automática con evidencia completa.
            La ausencia de software en el inventario no demuestra que
            el CVE no aplique; el análisis permanece por validar.
          </p>}
        </div>
        {primary ? <>
          <section className="cve-nvd-conditions cve-general-relevant-configuration"
            aria-labelledby="cve-primary-evidence">
            <div className="cve-technical-summary-heading">
              <h2 id="cve-primary-evidence">
                Evidencia principal · Configuración NVD {primary.position}
              </h2>
              <span className="cve-technical-tag" data-result={primary.technical_result}>
                {CVE_TECHNICAL_STATE[primary.technical_result] ||
                  CVE_TECHNICAL_STATE.INDETERMINATE}
              </span>
            </div>
            {softwareInventoryError && <p className="cve-muted" role="status">No se pudo cargar todo el inventario de software: {softwareInventoryError}</p>}
            <ConfigurationReview context={context} config={primary} softwareAssets={softwareAssets}
              highlight canDecide={canDecide}
              onSaved={() => {
                setNotice("Evaluación guardada. El historial se actualizó.");
                setRevision(n => n + 1);
              }}/>
          </section>
          {others.length > 0 && <details className="cve-nvd-other-evidence">
            <summary>Otras configuraciones pertinentes ({others.length})</summary>
            <p className="cve-muted">
              Las alternativas no son CVE adicionales. Se conserva
              su evidencia y su historial para consulta y auditoría.
            </p>
            {others.map(config => <section
              className="cve-nvd-conditions cve-general-relevant-configuration"
              key={context.hardware_asset_id + ":" + config.index}>
              <div className="cve-technical-summary-heading">
                <h2>Configuración NVD {config.position}</h2>
                <span className="cve-technical-tag" data-result={config.technical_result}>
                  {CVE_TECHNICAL_STATE[config.technical_result] ||
                    CVE_TECHNICAL_STATE.INDETERMINATE}
                </span>
              </div>
              <ConfigurationReview context={context} config={config} softwareAssets={softwareAssets}
                canDecide={canDecide}
                onSaved={() => {
                  setNotice("Evaluación guardada. El historial se actualizó.");
                  setRevision(n => n + 1);
                }}/>
            </section>)}
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
      </>}
  </section>;
}
