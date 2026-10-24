import { useEffect, useState } from "react";
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
  selectedCveHardwareId, groupCveEvidence, cveHumanReviewMessage,
} from "../utils/cveCataloguePresentation";
import {
  localizedTimestamp, contextualCveActionOptions, versionConstraintsText,
} from "../utils/cveAssessmentPresentation";

const STATE = {
  APPLIES: "Aplica a esta configuración",
  NOT_APPLICABLE: "No aplica a esta configuración",
  PENDING_REVIEW: "Pendiente de revisión",
};
const PLAIN = { h: "Hardware", o: "Firmware / sistema operativo", a: "Software" };

function Criterion({ item, depth = 0 }) {
  if (item.kind === "CRITERION") {
    const isSoftware = ["a", "o"].includes(item.part);
    return <article className="cve-nvd-condition cve-general-criterion">
      <div className="cve-nvd-condition-heading">
        <div className="cve-nvd-condition-tags">
          <h3>{PLAIN[item.part] || "Componente NVD"}</h3>
          <span className={"cve-nvd-category " + (
            item.vulnerable ? "cve-nvd-vulnerable" : "cve-nvd-platform"
          )}>{item.vulnerable ? "Componente vulnerable" : "Condición de plataforma"}</span>
        </div>
        <span className="cve-condition-state"
          data-state={item.state || "UNVERIFIED"}>
          {isSoftware
            ? (["COMPATIBLE", "EXCLUDED"].includes(item.technical_result)
              ? "Identidad contrastada" : "Identidad por verificar")
            : item.state === "SATISFIED" ? "CPE confirmado" : "Sin verificar"}
        </span>
      </div>
      <p className="cve-nvd-product">{String(item.criteria || "").split(":")
        .slice(3, 5).join(" · ").replaceAll("_", " ") || "Criterio NVD"}</p>
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
      {isSoftware && <div className="cve-nvd-found">
        <h4>Software instalado en este hardware</h4>
        {item.installed_software?.length ? item.installed_software.map(sw =>
          <div className="cve-nvd-installed" key={sw.installation_id}>
            <strong><Link to={"/assets/" + sw.software_asset_id}>
              {sw.software_name}</Link></strong>
            <p className="cve-muted">Software #{sw.software_asset_id} ·
              Instalación #{sw.installation_id} ·
              {sw.version ? " Versión " + sw.version : " Versión desconocida"}</p>
            {sw.confirmed_cpes?.length ? <p className="cve-muted">
              CPE de producto confirmado y vigente: {sw.confirmed_cpes.length}
            </p> : <p className="cve-muted">
              Sin CPE vigente confirmado para esta versión del software.
            </p>}
          </div>) : <p className="cve-muted">
            No se identificó software instalado con un CPE confirmado
            que corresponda a este criterio NVD. Esto no demuestra su ausencia.
          </p>}
      </div>}
    </article>;
  }
  if (item.kind !== "GROUP") {
    return <p className="cpe-warning">NVD contiene una estructura que debe revisarse.</p>;
  }
  const operator = item.operator === "AND" ? "Y" : "O";
  return <div className={"cve-general-group " + (depth ? "cve-general-nested" : "")}>
    <div className="cve-general-logic">
      <strong>{operator === "Y" ? "Se requieren todas las condiciones" :
        "Se permite cualquiera de las alternativas"}</strong>
      {item.negate && <span className="cpe-warning">
        Negación NVD: el resultado del grupo se invierte (requiere revisión).</span>}
    </div>
    {item.children?.length ? item.children.map((child, i) =>
      <div key={i}>
        {i > 0 && <div className="cve-nvd-plus" aria-label={"Operador " + operator}>
          {operator}</div>}
        <Criterion item={child} depth={depth + 1}/>
      </div>) : <p className="cve-muted">No hay criterios detallados en este grupo.</p>}
  </div>;
}

function ConfigurationReview({ context, config, onSaved, canDecide, highlight = false }) {
  const last = config.latest_assessment;
  const status = last?.effective_status || "PENDING_REVIEW";
  const [choice, setChoice] = useState("");
  const [installId, setInstallId] = useState("");
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
  const selectedId = installId || (installations.length === 1 ?
    String(installations[0].installation_id) : "");
  const staleDecision = Boolean(last?.stale &&
    ["APPLIES", "NOT_APPLICABLE"].includes(last.status));
  const canReopen = staleDecision && canDecide;
  const canReview = config.review_supported && canDecide;
  const options = contextualCveActionOptions(config, last);
  const noSelected = choice !== "UNKNOWN" && !selectedId;
  const invalid = !justification.trim() || noSelected;

  function reset() {
    setChoice(""); setJustification(""); setComplete(false); setError("");
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
  return <div className="panel cve-nvd-decision">
    <div className="cve-nvd-joint-title">
      <h3>{highlight ? "Registrar decisión · CVE en este hardware" :
        "Revisión de evidencia adicional · Configuración " + config.position}</h3>
      <span className="cve-status-label" data-status={status}>
        {STATE[status] || status}</span>
    </div>
    <p>La decisión se sustenta en la configuración NVD {config.position}
      para el hardware #{context.hardware_asset_id}. Su efecto en el estado
      consolidado del CVE depende de las otras alternativas de NVD.
      El historial se conserva sin modificar decisiones anteriores.</p>
    {last?.stale && <p className="cpe-warning">
      La evaluación previa conserva su registro histórico, pero la evidencia cambió.
      Se necesita revisar nuevamente.</p>}
    {!config.review_supported && <p className="cpe-warning" role="status">
      {config.review_reason} Esta configuración permanece en revisión;
      no se habilita la confirmación sin una lógica verificable.</p>}
    {config.review_installation_id && config.technical_result === "COMPATIBLE" &&
      <p className="cve-muted">
        El firmware instalado satisface este criterio NVD; no se puede
        descartar mientras las evidencias sean vigentes.
      </p>}
    {(canReview || canReopen) && <div className="cve-nvd-actions">
      {options.map(option => <button key={option.key} type="button"
        className={"cve-nvd-action" + (choice === option.key ? " selected" : "")}
        data-action={option.key}
        aria-pressed={choice === option.key}
        onClick={() => { setChoice(option.key); setJustification(""); setComplete(false); }}>
        {option.title}</button>)}
    </div>}
    {!canDecide && <p className="cve-muted">
      El rol actual permite consultar, pero no registrar decisiones.</p>}
    {choice && (canReview || (canReopen && choice === "UNKNOWN")) &&
      <form className="cve-compact-review"
      onSubmit={submit}>
      {installations.length > 1 && choice !== "UNKNOWN" && <label>
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
          {item.stale && <p className="cve-history-warning">
            Registro histórico: evidencia no vigente.</p>}
          <p>{item.decided_by || "Usuario no disponible"} ·
            {localizedTimestamp(item.decided_at)}</p>
          <p>{item.justification}</p>
        </li>)}
      </ol> : <p className="cve-muted">No hay decisiones registradas.</p>}
    </details>
  </div>;
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
          {" "}{configs.length} configuraciones pertinentes de NVD.
          {context.unrelated_configuration_count > 0 && <>
            {" "}{context.unrelated_configuration_count} alternativas sin
            correspondencia demostrada con el inventario actual se conservan
            en el registro NVD.
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
          {context.applicability?.source === "SYSTEM" ?
            <div className="cve-general-auto-proof">
              <p>VISOR OT comprobó las condiciones publicadas por NVD
                con CPE confirmados, instalación y versión vigentes.
                No significa que el equipo haya sido explotado.</p>
              <p>Configuración NVD comprobada: {
                context.applicability.automatic_evidence?.configuration_position
              }.</p>
              {(context.applicability.automatic_evidence?.criteria || []).map(
                (criterion, index) => <div key={index} className="cve-muted">
                  <code>{criterion.confirmed_cpe}</code>
                  {criterion.installed_version &&
                    <span> · Versión {criterion.installed_version}</span>}
                  {criterion.software_installation_id &&
                    <span> · Instalación #{criterion.software_installation_id}</span>}
                </div>
              )}
            </div> :
            <p>La comparación técnica no proporciona una conclusión positiva
              automática comprobable para este hardware. Si faltan datos,
              como STEP 7 u otro software externo, se requiere revisión humana.
              La ausencia de software en el inventario nunca demuestra
              por sí sola que el CVE no aplique.</p>}
        </div>
        <section className="panel cve-general-review-summary"
          aria-labelledby="cve-human-review-title">
          <div className="cve-technical-summary-heading">
            <h2 id="cve-human-review-title">Evaluación del analista · Este hardware</h2>
            <span className="cve-catalogue-evaluation-status"
              data-status={context.assessment_summary?.status || "PENDING_REVIEW"}>
              {CVE_EVALUATION_STATE[context.assessment_summary?.status] ||
                CVE_EVALUATION_STATE.PENDING_REVIEW}
            </span>
          </div>
          <p>{cveHumanReviewMessage(context.assessment_summary)}</p>
          <p>Las decisiones se vinculan a la evidencia NVD que las sustenta.
            El resultado corresponde al CVE y hardware seleccionados;
            no es necesario tomar una decisión manual por cada alternativa NVD.</p>
          {context.assessment_summary?.stale_configurations > 0 && <p
            className="cpe-warning">
            {context.assessment_summary.stale_configurations} evaluaciones
            requieren nueva revisión porque cambió la evidencia.
          </p>}
        </section>
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
            <Criterion item={primary.tree}/>
            <ConfigurationReview context={context} config={primary}
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
              <Criterion item={config.tree}/>
              <ConfigurationReview context={context} config={config}
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
