import { useEffect, useMemo, useState } from "react";
import { Link, useOutletContext, useParams } from "react-router-dom";
import {
  listCveHardware, readCveCatalogue, readGeneralCveAssessment,
  createGeneralCveAssessment,
} from "../api/vulnerabilities";
import SuccessNotice from "../components/SuccessNotice";
import CveAnalysis from "./CveAnalysis";
import { CVE_SEVERITY, CVE_TECHNICAL_STATE } from "../utils/cveCataloguePresentation";
import {
  localizedTimestamp, assessmentActionOptions, versionConstraintsText,
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
          </div>) : <p className="cve-muted">No hay software instalado vigente registrado.
            Esto no demuestra que la condición no se cumpla.</p>}
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

function ConfigurationReview({ context, config, onSaved, canDecide }) {
  const last = config.latest_assessment;
  const status = last?.effective_status || "PENDING_REVIEW";
  const [choice, setChoice] = useState("");
  const [installId, setInstallId] = useState("");
  const [justification, setJustification] = useState("");
  const [complete, setComplete] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const targetPart = config.software_criterion?.split(":")[2];
  const installations = (context.installed_software || []).filter(sw =>
    targetPart === "o" ? ["FIRMWARE", "OS"].includes(sw.software_type)
      : targetPart === "a" ? sw.software_type === "APPLICATION" : false
  );
  const selectedId = installId || (installations.length === 1 ?
    String(installations[0].installation_id) : "");
  const options = assessmentActionOptions(status);
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
        software_installation_id: selectedId ? Number(selectedId) : null,
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
      <h3>Evaluación conjunta · Configuración {config.position}</h3>
      <span className="cve-status-label" data-status={status}>
        {STATE[status] || status}</span>
    </div>
    <p>Esta decisión corresponde únicamente a esta configuración de NVD
      y al hardware #{context.hardware_asset_id}. No confirma por sí sola
      otras configuraciones del mismo CVE.</p>
    {last?.stale && <p className="cpe-warning">
      La evaluación previa conserva su registro histórico, pero la evidencia cambió.
      Se necesita revisar nuevamente.</p>}
    {!config.review_supported && <p className="cpe-warning" role="status">
      {config.review_reason} Esta configuración permanece en revisión;
      no se habilita la confirmación sin una lógica verificable.</p>}
    {config.review_supported && canDecide && <div className="cve-nvd-actions">
      {options.map(option => <button key={option.key} type="button"
        className={"cve-nvd-action" + (choice === option.key ? " selected" : "")}
        data-action={option.key}
        aria-pressed={choice === option.key}
        onClick={() => { setChoice(option.key); setJustification(""); setComplete(false); }}>
        {option.title}</button>)}
    </div>}
    {!canDecide && <p className="cve-muted">
      El rol actual permite consultar, pero no registrar decisiones.</p>}
    {choice && config.review_supported && <form className="cve-compact-review"
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
  const { user } = useOutletContext();
  const canDecide = ["ADMIN", "ANALYST"].includes(user?.role);
  const [cve, setCve] = useState(null);
  const [hardware, setHardware] = useState([]);
  const [selectedHardware, setSelectedHardware] = useState("");
  const [context, setContext] = useState(null);
  const [activeConfig, setActiveConfig] = useState(0);
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
        setSelectedHardware(String(related.results[0]?.hardware_id || ""));
      })
      .catch(err => { if (active) setError(err.message); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [cveId]);

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
      .then(data => {
        if (!live) return;
        setContext(data);
        setActiveConfig(data.configurations.find(row => row.review_supported)?.index ?? 0);
      })
      .catch(err => { if (live) setError(err.message); })
      .finally(() => { if (live) setContextLoading(false); });
    return () => { live = false; };
  }, [cveId, selectedHardware, isLegacy, revision]);

  const configs = context?.configurations || [];
  const selection = configs[activeConfig] || configs[0];
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
        onChange={event => { setSelectedHardware(event.target.value); setActiveConfig(0); }}>
        {hardware.map(row => <option key={row.hardware_id} value={row.hardware_id}>
          #{row.hardware_id} · {row.hardware_name}</option>)}
      </select> : <p className="cve-muted">
        Aún no hay hardware relacionado mediante búsquedas o evaluaciones.
        Inicia una búsqueda CVE para asociar un equipo y revisar sus condiciones.</p>}
    </div>

    {contextLoading ? <p className="cve-muted">Cargando condiciones del inventario...</p>
      : context && <>
        <div className="cve-general-configuration-selector">
          <label htmlFor="cve-configuration-choice">Configuración NVD</label>
          <select id="cve-configuration-choice" value={selection?.index ?? ""}
            onChange={event => setActiveConfig(Number(event.target.value))}>
            {configs.map(conf => <option value={conf.index} key={conf.index}>
              Configuración {conf.position}{conf.review_supported ? " · Evaluación asistida" :
                " · Revisión técnica"}</option>)}
          </select>
          <span>{configs.length} configuraciones conservadas de NVD</span>
        </div>
        <div className="panel cve-technical-summary">
          <div className="cve-technical-summary-heading">
            <h2>Resultado técnico del CVE en este hardware</h2>
            <span className="cve-technical-tag" data-result={context.technical_result}>
              {CVE_TECHNICAL_STATE[context.technical_result] ||
                CVE_TECHNICAL_STATE.INDETERMINATE}
            </span>
          </div>
          <p>Comparación automática y no una decisión del analista.
            Una configuración excluida no descarta por sí sola las demás alternativas.
            Una configuración compatible todavía requiere revisar su aplicabilidad real.</p>
        </div>
        {selection ? <section className="cve-nvd-conditions" key={
          context.hardware_asset_id + ":" + selection.index
        }>
          <div className="cve-technical-summary-heading">
            <h2>Condiciones de la configuración {selection.position}</h2>
            <span className="cve-technical-tag" data-result={selection.technical_result}>
              {CVE_TECHNICAL_STATE[selection.technical_result] ||
                CVE_TECHNICAL_STATE.INDETERMINATE}
            </span>
          </div>
          <Criterion item={selection.tree}/>
          <ConfigurationReview context={context} config={selection}
            canDecide={canDecide}
            onSaved={() => {
              setNotice("Evaluación guardada. El historial de la configuración se actualizó.");
              setRevision(n => n + 1);
            }}/>
        </section> : <p className="cpe-warning">
          NVD no ha publicado configuraciones evaluables para este CVE.
          La correspondencia queda pendiente de verificación.</p>}
      </>}
  </section>;
}
