import { useEffect, useState } from "react";
import { Link, useOutletContext } from "react-router-dom";
import {
  createExperimentalCveAssessment, getExperimentalCveAssessment,
} from "../api/vulnerabilities";
import {
  CVE_STATUS, EVIDENCE_STATE, SOURCE_LABEL, EXPERIMENT_CVE_ID,
  currentCriterionEvidence, latestEffectiveStatus, submissionGuard,
  localizedTimestamp, versionConstraintsText, selectedFirmwareInstallation,
  proposedFirmwareDecision, experimentalDescription,
} from "../utils/cveAssessmentPresentation";

const OPTIONS = [
  { key: "CONFIRMED", title: "Sí, corresponde", description: "He comprobado que es el componente indicado por NVD." },
  { key: "NOT_MATCH", title: "No corresponde", description: "He encontrado una discrepancia verificable." },
];

function TechnicalDetails({ info, hardware, firmware }) {
  return <details className="cve-raw-details">
    <summary>Ver criterios e identificadores técnicos NVD</summary>
    <div className="cve-technical-content">
      <p>Hardware · Condición de plataforma (<code>vulnerable: false</code>)</p>
      <code className="cve-code">{hardware?.criteria}</code>
      <p>ID de criterio: <code>{hardware?.match_criteria_id || "Sin identificador"}</code></p>
      <p>Firmware · Componente vulnerable (<code>vulnerable: true</code>)</p>
      <code className="cve-code">{firmware?.criteria}</code>
      <p>ID de criterio: <code>{firmware?.match_criteria_id || "Sin identificador"}</code></p>
      <details className="cve-raw-details">
        <summary>JSON original de la configuración {info.configuration_position}</summary>
        <pre>{JSON.stringify(info.configuration, null, 2)}</pre>
      </details>
    </div>
  </details>;
}

export default function CveAnalysis() {
  const { user } = useOutletContext();
  const canDecide = ["ADMIN", "ANALYST"].includes(user?.role);
  const [info, setInfo] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [selectedId, setSelectedId] = useState("");
  const [choice, setChoice] = useState("");
  const [justification, setJustification] = useState("");
  const [source, setSource] = useState("INVENTORY");
  const [complete, setComplete] = useState(false);

  useEffect(() => {
    let active = true;
    getExperimentalCveAssessment()
      .then(data => { if (active) setInfo(data); })
      .catch(err => { if (active) setError(err.message); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, []);

  function resetDecision() {
    setChoice("");
    setJustification("");
    setComplete(false);
    setSource("INVENTORY");
  }

  function chooseDecision(value) {
    // Avoid reusing a rejection justification for a later confirmation.
    if (choice !== value) {
      setJustification("");
      setSource("INVENTORY");
    }
    setChoice(value);
    setComplete(false);
    setError("");
  }

  async function refresh() {
    if (saving || refreshing) return;
    setRefreshing(true);
    setError("");
    try {
      const result = await getExperimentalCveAssessment();
      setInfo(result);
      setSelectedId("");
      resetDecision();
    } catch (err) {
      setError("No fue posible actualizar la evidencia: " + err.message);
    } finally {
      setRefreshing(false);
    }
  }

  const installations = info?.active_firmware_installations || [];
  const installed = selectedFirmwareInstallation(info, selectedId);
  const hwEvidence = currentCriterionEvidence(info, "hardware");
  const fwEvidence = currentCriterionEvidence(info, "firmware");
  const last = info?.latest_assessment;
  const status = latestEffectiveStatus(info);
  const description = experimentalDescription(info?.cve_id, info?.description);
  const versionBounds = versionConstraintsText(
    info?.criteria_evidence?.firmware?.version_constraints
  );
  const draft = proposedFirmwareDecision(info, choice, selectedId,
    justification, source, complete);
  const guard = choice ? submissionGuard(info, draft) : "";
  const allowNegativeConclusion = choice === "NOT_MATCH" && installations.length === 1;
  const hardwareConfirmed = Boolean(info?.hardware_cpe_confirmed);

  async function save(event) {
    event.preventDefault();
    if (!choice || !canDecide || saving || guard) return;
    setSaving(true);
    setError("");
    setNotice("");
    let saved;
    try {
      saved = await createExperimentalCveAssessment({
        ...draft,
        justification: draft.justification.trim(),
        inventory_fingerprint: info.inventory_fingerprint,
        configuration_fingerprint: info.configuration_fingerprint,
      });
    } catch (err) {
      setError("No se registró la evaluación: " + err.message +
        ". Si cambió el inventario, actualiza la evidencia.");
      setSaving(false);
      return;
    }
    resetDecision();
    setNotice("Decisión registrada como «" +
      (CVE_STATUS[saved.assessment.status] || saved.assessment.status) +
      "». Evaluación #" + saved.assessment.id + ".");
    try {
      const updated = await getExperimentalCveAssessment();
      setInfo(updated);
      setSelectedId("");
    } catch (err) {
      // The POST succeeded: never claim the decision failed or resubmit it.
      setError("La decisión se guardó, pero no se actualizó la vista: " +
        err.message + ". Usa «Actualizar evidencia».");
    } finally {
      setSaving(false);
    }
  }

  if (loading) return <section className="page" aria-busy="true">
    <p>Cargando análisis CVE...</p>
  </section>;

  if (!info) return <section className="page">
    <nav className="breadcrumbs" aria-label="Ruta de navegación">
      <span>Vulnerabilidades</span><span>/</span><span>Análisis CVE</span>
    </nav>
    <header className="page-header">
      <span className="page-eyebrow">ANÁLISIS CVE</span>
      <h1>{EXPERIMENT_CVE_ID}</h1>
    </header>
    <p className="error-message" role="alert">
      {error || "No fue posible cargar el registro NVD."}
    </p>
    <button className="button-secondary" type="button"
      onClick={refresh} disabled={refreshing}>
      {refreshing ? "Actualizando..." : "Reintentar"}
    </button>
  </section>;

  return <section className="page cve-analysis-page cve-compact-page">
    <nav className="breadcrumbs" aria-label="Ruta de navegación">
      <span>Vulnerabilidades</span><span>/</span><span>Análisis CVE</span>
    </nav>

    <header className="page-header cve-analysis-heading">
      <div>
        <span className="page-eyebrow">ANÁLISIS CVE · EVALUACIÓN ASISTIDA</span>
        <h1>{info.cve_id}</h1>
        <p>Hardware <Link to={"/assets/" + info.hardware_asset_id}>
          #{info.hardware_asset_id}</Link> · Configuración {info.configuration_position}</p>
      </div>
      <button className="button-secondary" type="button"
        disabled={refreshing || saving} onClick={refresh}>
        {refreshing ? "Actualizando..." : "Actualizar evidencia"}
      </button>
    </header>

    {error && <p className="error-message" role="alert">{error}</p>}
    {notice && <p className="cve-success" role="status">{notice}</p>}

    <section className="panel cve-section cve-summary" aria-label="Resumen de vulnerabilidad">
      <div className="cve-overview-line">
        <div>
          <p className="cve-translation-label">{description.label}</p>
          <p className="cve-description">{description.text}</p>
          {description.original !== description.text && <details className="cve-text-original">
            <summary>Leer descripción original de NVD (inglés)</summary>
            <p>{description.original}</p>
          </details>}
        </div>
        <div className="cve-severity" data-level={info.severity}>
          <span>Severidad NVD</span>
          <strong>{info.severity === "HIGH" ? "Alta" :
            info.severity === "CRITICAL" ? "Crítica" :
            info.severity === "MEDIUM" ? "Media" :
            info.severity === "LOW" ? "Baja" :
            info.severity || "Sin clasificar"}</strong>
          <span>{info.base_score != null ? "CVSS " + info.base_score : "Sin puntuación"}</span>
        </div>
      </div>
      <div className="cve-status-line">
        <span className="cve-status-label" data-status={status}>
          {last ? CVE_STATUS[status] : "Por verificar"}
        </span>
        <span className="cve-muted">
          {last && !last.stale
            ? "Evaluado por " + (last.decided_by || "analista") + " · " +
              localizedTimestamp(last.decided_at)
            : "Se requieren ambas condiciones (AND)"}
        </span>
      </div>
      {last?.stale && <p className="cpe-warning" role="status">
        Cambió la evidencia del inventario o la configuración NVD.
        La decisión anterior se conserva, pero necesita una nueva revisión.
      </p>}
    </section>

    <section className="cve-section" aria-labelledby="cve-conditions">
      <div className="cve-section-heading">
        <h2 id="cve-conditions">¿Qué exige NVD y qué encontró VISOR OT?</h2>
        <span className="cve-logic">AND · Ambas condiciones</span>
      </div>
      <div className="cve-condition-grid">
        <article className="cve-condition cve-condition-simple">
          <div className="cve-condition-heading">
            <h3>Hardware · Condición de plataforma</h3>
            <span className="cve-condition-state" data-state={
              hardwareConfirmed ? "SATISFIED" : "UNVERIFIED"
            }>{hardwareConfirmed ? "Confirmado" : "Sin verificar"}</span>
          </div>
          <p className="cve-condition-product">{info.hardware_name}</p>
          <p className="cve-muted">Activo #{info.hardware_asset_id} · {
            hardwareConfirmed ? "CPE confirmado y vigente" : "Sin CPE confirmado y vigente"
          }</p>
          <Link to={"/assets/" + info.hardware_asset_id + "/cpe"}>
            Revisar CPE del hardware
          </Link>
        </article>

        <article className="cve-condition cve-condition-simple">
          <div className="cve-condition-heading">
            <h3>Firmware · Componente vulnerable</h3>
            <span className="cve-condition-state" data-state={fwEvidence?.state || "UNVERIFIED"}>
              {EVIDENCE_STATE[fwEvidence?.state] || "Sin verificar"}
            </span>
          </div>
          <p className="cve-condition-product">
            {fwEvidence?.display_name || "Phoenix Contact IL PN BK-PAC Firmware"}
          </p>
          <p className="cve-muted">Criterio NVD sin un CPE oficial de diccionario identificado.</p>

          <div className="cve-evidence-in-card">
            <h4>Encontrado en el equipo</h4>
            {installations.length === 0 ? <>
              <p className="cpe-warning">No hay firmware vinculado mediante una instalación
                vigente. No se puede concluir que la condición se cumple o se descarta.</p>
              <Link to={"/assets/" + info.hardware_asset_id}>
                Revisar instalaciones en el inventario
              </Link>
            </> : <>
              {installations.length > 1 && <p className="cve-muted">
                Hay varios firmwares instalados. Selecciona cuál vas a comprobar:
              </p>}
              <div className="cve-firmware-candidates">
                {installations.map(item => <div
                  className="cve-firmware-found" key={item.installation_id}>
                  {installations.length > 1 && <label className="cve-firmware-pick">
                    <input type="radio" name="firmware-evidence"
                      checked={Number(selectedId) === item.installation_id}
                      disabled={saving}
                      onChange={() => { setSelectedId(String(item.installation_id));
                        resetDecision(); }}/>
                    Seleccionar esta instalación
                  </label>}
                  <strong><Link to={"/assets/" + item.software_asset_id}>
                    {item.software_name}</Link></strong>
                  <p className="cve-muted">Software #{item.software_asset_id} ·
                    Instalación vigente #{item.installation_id} ·
                    {" "}{item.version ? "Versión " + item.version : "Versión desconocida"}</p>
                  <small>Fuente: inventario y relación SoftwareInstallation</small>
                </div>)}
              </div>
            </>}
          </div>
          {versionBounds && <p className="cpe-warning">
            NVD restringe versiones: {versionBounds}. Estas restricciones todavía
            requieren revisión técnica antes de concluir «Aplica».
          </p>}
          {canDecide && <div className="cve-decision-in-card">
            <h4>¿El firmware instalado corresponde al componente afectado por NVD?</h4>
            <p className="cve-muted">La instalación no prueba por sí sola
              la correspondencia: tu decisión requiere evidencia y justificación.</p>
            <div className="cve-direct-actions">
              {OPTIONS.map(item => <button key={item.key} type="button"
                className={"cve-choice-button" +
                  (choice === item.key ? " selected" : "")}
                aria-pressed={choice === item.key}
                disabled={saving || !installed}
                onClick={() => chooseDecision(item.key)}>
                {item.title}
              </button>)}
              <button type="button" className="cve-unknown-button"
                aria-pressed={choice === "UNKNOWN"}
                disabled={saving}
                onClick={() => chooseDecision("UNKNOWN")}>
                No puedo verificarlo
              </button>
            </div>

            {choice && <form className="cve-compact-review" onSubmit={save}>
              <p><strong>{choice === "CONFIRMED" ? "Confirma la correspondencia" :
                choice === "NOT_MATCH" ? "Explica la discrepancia" :
                "Registra qué evidencia falta"}</strong></p>
              <label htmlFor="cve-justification">Justificación</label>
              <textarea id="cve-justification" rows={3} maxLength={1000}
                required disabled={saving} value={justification}
                placeholder="¿Qué documento, inspección o evidencia respalda la decisión?"
                onChange={e => setJustification(e.target.value)}/>
              <small>{justification.length}/1000 caracteres</small>
              {choice === "NOT_MATCH" && <div className="cve-attestation">
                <label><input type="checkbox" checked={complete}
                  disabled={saving || !allowNegativeConclusion}
                  onChange={e => setComplete(e.target.checked)}/>
                  También comprobé que el inventario de firmware instalado está completo
                  y que no hay otras instalaciones pendientes de evaluar.</label>
                <p>Sin esa comprobación, registrar una discrepancia dejará la
                  configuración «Pendiente de revisión», no «No aplica».</p>
                {installations.length > 1 && <p>
                  Hay más de un firmware vigente: esta versión no permite
                  descartar toda la configuración hasta evaluar todos.</p>}
              </div>}
              <details className="cve-evidence-origin">
                <summary>Procedencia de la comprobación: {SOURCE_LABEL[source]}</summary>
                <fieldset>
                  <legend>Indica el origen de la evidencia registrada</legend>
                  {Object.entries(SOURCE_LABEL).map(([value, label]) =>
                    <label key={value}><input type="radio" name="cve-evidence-source"
                      value={value} checked={source === value}
                      disabled={saving} onChange={() => setSource(value)}/>
                      {label}</label>)}
                </fieldset>
                <p>El inventario verifica la instalación, pero no prueba
                  automáticamente que el firmware coincida con el criterio NVD.</p>
              </details>
              {guard && <p className="cve-hint" role="status">{guard}</p>}
              <div className="cve-form-actions">
                <button type="submit" className="button-primary"
                  disabled={Boolean(guard) || saving}>
                  {saving ? "Guardando..." : "Guardar evaluación"}
                </button>
                <button type="button" className="button-secondary"
                  disabled={saving} onClick={resetDecision}>Cancelar</button>
              </div>
            </form>}
          </div>}
          {!canDecide && <p className="cve-muted">
            Tu perfil puede consultar evidencias; las decisiones requieren
            rol de analista o administrador.
          </p>}
        </article>
      </div>
      <TechnicalDetails info={info} hardware={hwEvidence} firmware={fwEvidence}/>
    </section>

    <details className="panel cve-section cve-history-fold">
      <summary>Historial de evaluaciones ({info.history?.length || 0})</summary>
      {!info.history?.length ? <p className="cve-muted">
        Todavía no hay decisiones registradas para esta configuración.
      </p> : <ol className="cve-history">
        {info.history.map(record => <li key={record.id}>
          <div className="cve-history-heading">
            <strong>Evaluación #{record.id}</strong>
            <span className="cve-status-label" data-status={record.status}>
              {CVE_STATUS[record.status] || record.status}
            </span>
          </div>
          <p>{record.decided_by || "Usuario retirado"} · {
            localizedTimestamp(record.decided_at)}</p>
          {record.stale && <p className="cve-history-warning">
            Registro histórico desactualizado; no es una decisión vigente.
          </p>}
          <p>{record.justification}</p>
          <details><summary>Ver evidencia de esta evaluación</summary>
            <pre>{JSON.stringify(record.criteria_evidence, null, 2)}</pre>
          </details>
        </li>)}
      </ol>}
    </details>
    <p className="cve-hint">Se evalúa únicamente la configuración {
      info.configuration_position}, no las demás configuraciones del CVE.</p>
  </section>;
}
