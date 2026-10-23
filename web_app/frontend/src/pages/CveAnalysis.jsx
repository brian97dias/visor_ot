import { useEffect, useState } from "react";
import { Link, useOutletContext } from "react-router-dom";
import {
  createExperimentalCveAssessment, getExperimentalCveAssessment,
} from "../api/vulnerabilities";
import {
  CVE_STATUS, EVIDENCE_STATE, VERDICT_LABEL, SOURCE_LABEL,
  EXPERIMENT_CVE_ID, currentCriterionEvidence, latestEffectiveStatus,
  submissionGuard, advisoryOutcome, cpePartLabel, localizedTimestamp,
  versionConstraintsText,
} from "../utils/cveAssessmentPresentation";

const emptyForm = () => ({
  software_installation_id: "",
  firmware_verdict: "UNKNOWN",
  evidence_source: "INVENTORY",
  inventory_declared_complete: false,
  justification: "",
});

function Condition({ name, evidence, children }) {
  const satisfied = evidence?.state || "UNVERIFIED";
  return <article className="cve-condition">
    <div className="cve-condition-heading">
      <h3>{name}</h3>
      <span className="cve-condition-state" data-state={satisfied}>
        {EVIDENCE_STATE[satisfied] || "Sin verificar"}
      </span>
    </div>
    <p className="cve-condition-caption">{cpePartLabel(evidence?.nvd_vulnerable)}</p>
    <p className="cve-condition-original">Criterio original de NVD</p>
    <code className="cve-code">{evidence?.criteria || "No disponible"}</code>
    {evidence?.match_criteria_id && <p className="cve-metadata">
      ID de criterio: <code>{evidence.match_criteria_id}</code>
    </p>}
    {children}
  </article>;
}

export default function CveAnalysis() {
  const { user } = useOutletContext();
  const canDecide = ["ANALYST", "ADMIN"].includes(user?.role);
  const [info, setInfo] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [form, setForm] = useState(emptyForm);
  const [confirming, setConfirming] = useState(false);

  useEffect(() => {
    let active = true;
    getExperimentalCveAssessment()
      .then(data => { if (active) setInfo(data); })
      .catch(err => { if (active) setError(err.message); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, []);

  async function refresh() {
    if (refreshing || saving) return;
    setRefreshing(true);
    setError("");
    try {
      const result = await getExperimentalCveAssessment();
      setInfo(result);
      setConfirming(false);
    } catch (err) {
      setError("No fue posible actualizar el análisis: " + err.message);
    } finally {
      setRefreshing(false);
    }
  }

  function updateForm(key, value) {
    setForm(current => ({
      ...current, [key]: value,
      ...((key === "firmware_verdict" || key === "software_installation_id")
        ? { inventory_declared_complete: false } : {}),
    }));
    setConfirming(false);
    setError("");
  }

  const currentStatus = latestEffectiveStatus(info);
  const latest = info?.latest_assessment;
  const hwEvidence = currentCriterionEvidence(info, "hardware");
  const fwEvidence = currentCriterionEvidence(info, "firmware");
  const installations = info?.active_firmware_installations || [];
  const firmwareSelected = installations.find(
    row => row.installation_id === Number(form.software_installation_id)
  ) || null;
  const versions = versionConstraintsText(
    info?.criteria_evidence?.firmware?.version_constraints
  );
  const guard = submissionGuard(info, form);
  const predicted = advisoryOutcome(info, form);

  async function save(event) {
    event.preventDefault();
    if (!canDecide || saving || !confirming || guard) return;
    setSaving(true);
    setError("");
    setNotice("");
    let created;
    try {
      created = await createExperimentalCveAssessment({
        firmware_verdict: form.firmware_verdict,
        software_installation_id: firmwareSelected?.installation_id ?? null,
        evidence_source: form.evidence_source,
        inventory_declared_complete: form.inventory_declared_complete,
        justification: form.justification.trim(),
        inventory_fingerprint: info.inventory_fingerprint,
        configuration_fingerprint: info.configuration_fingerprint,
      });
    } catch (err) {
      setError("No se registró la evaluación: " + err.message +
        " Si el inventario cambió, actualiza los datos antes de decidir.");
      setConfirming(false);
      setSaving(false);
      return;
    }
    setConfirming(false);
    setForm(emptyForm());
    setNotice("Evaluación #" + created.assessment.id + " registrada: " +
      (CVE_STATUS[created.assessment.status] || created.assessment.status) +
      ". La decisión se conserva en el historial de esta configuración.");
    try {
      const updated = await getExperimentalCveAssessment();
      setInfo(updated);
    } catch (err) {
      // The POST already succeeded: avoid encouraging a duplicate submission.
      setError("Se guardó la evaluación, pero no se pudo refrescar la pantalla: " +
        err.message + ". Utiliza «Actualizar evidencia».");
    } finally {
      setSaving(false);
    }
  }

  if (loading) return <section className="page" aria-busy="true">
    <p>Cargando condiciones CVE desde VISOR OT...</p>
  </section>;

  if (!info) return <section className="page cve-analysis-page">
    <nav className="breadcrumbs" aria-label="Ruta de navegación">
      <span>Vulnerabilidades</span><span>/</span><span>Análisis CVE</span>
    </nav>
    <header className="page-header">
      <span className="page-eyebrow">ANÁLISIS CVE</span>
      <h1>Evaluación asistida · {EXPERIMENT_CVE_ID}</h1>
    </header>
    <div className="error-message" role="alert">{error || "No se pudo cargar el análisis."}</div>
    <p>Para esta etapa, el backend requiere el CVE recuperado desde NVD y el hardware #2 activo.</p>
    <button className="button-secondary" type="button" onClick={refresh} disabled={refreshing}>
      {refreshing ? "Actualizando..." : "Reintentar"}
    </button>
  </section>;

  return <section className="page cve-analysis-page">
    <nav className="breadcrumbs" aria-label="Ruta de navegación">
      <span>Vulnerabilidades</span><span>/</span><span>Análisis CVE</span>
    </nav>
    <header className="page-header cve-analysis-heading">
      <div>
        <span className="page-eyebrow">ANÁLISIS CVE · EXPERIMENTO CONTROLADO</span>
        <h1>{info.cve_id}</h1>
        <p>Evaluación asistida de la <strong>configuración {info.configuration_position}</strong>,
          no de todas las configuraciones del CVE.</p>
      </div>
      <button className="button-secondary" type="button" disabled={refreshing || saving}
        onClick={refresh}>{refreshing ? "Actualizando..." : "Actualizar evidencia"}</button>
    </header>
    {error && <p className="error-message" role="alert">{error}</p>}
    {notice && <p className="cve-success" role="status">{notice}</p>}

    <section className="panel cve-section" aria-label="Identificación de vulnerabilidad">
      <div className="cve-overview-line">
        <div>
          <h2>Registro de NVD</h2>
          <p className="cve-muted">{info.description}</p>
        </div>
        <div className="cve-severity" data-level={info.severity}>
          <span>Severidad NVD</span>
          <strong>{info.severity || "Sin clasificar"}</strong>
          <span>{info.base_score != null ? "CVSS " + info.base_score : "Sin puntuación"}</span>
        </div>
      </div>
      <div className="cve-status-line">
        <span className="cve-status-label" data-status={currentStatus}>
          {CVE_STATUS[currentStatus] || currentStatus}
        </span>
        <span className="cve-muted">
          {latest && !latest.stale
            ? "Decisión #" + latest.id + " · " + localizedTimestamp(latest.decided_at)
            : "Todavía no hay una decisión vigente para la evidencia actual"}
        </span>
      </div>
      {latest?.stale && <p className="cpe-warning" role="status">
        La decisión anterior ya no coincide con la identidad del inventario o con la
        configuración recuperada de NVD. Su historial se conserva, pero la
        evaluación vigente vuelve a pendiente de revisión.
      </p>}
      <p className="cve-hint">
        «Aplica» o «No aplica» significa exclusivamente que la <strong>configuración
        {info.configuration_position}</strong> cumple o no las condiciones examinadas;
        no es una conclusión automática sobre todo {info.cve_id}.
      </p>
    </section>

    <section className="cve-section" aria-labelledby="cve-conditions-title">
      <div className="cve-section-heading">
        <h2 id="cve-conditions-title">Condiciones exigidas por NVD</h2>
        <span className="cve-logic">AND · Ambas condiciones</span>
      </div>
      <div className="cve-condition-grid">
        <Condition name="1. Plataforma de hardware" evidence={hwEvidence}>
          <p className="cve-muted">Activo evaluado: <Link to={"/assets/" + info.hardware_asset_id}>
            {info.hardware_name} · #{info.hardware_asset_id}</Link></p>
          <p className="cve-muted">{info.hardware_cpe_confirmed
            ? "CPE oficial del hardware confirmado para la identidad técnica vigente."
            : "No hay evidencia de un CPE oficial confirmado y vigente para este hardware."}</p>
          <p className="cve-note">En NVD, <code>vulnerable: false</code> significa
            condición de plataforma, no ausencia de vulnerabilidad.</p>
          <Link to={"/assets/" + info.hardware_asset_id + "/cpe"}>
            Revisar identificación CPE del hardware
          </Link>
        </Condition>
        <Condition name="2. Firmware vulnerable" evidence={fwEvidence}>
          <p className="cve-muted"><strong>{
            fwEvidence?.display_name || "Phoenix Contact IL PN BK-PAC Firmware"
          }</strong></p>
          <p className="cve-note">Este criterio <code>cpeMatch</code> no certifica
            un CPE oficial del diccionario. No se creará una asociación AssetCpe.</p>
          {versions && <p className="cpe-warning">Restricciones NVD: {versions}.
            La evaluación de rangos no está implementada: el backend mantendrá
            la condición pendiente hasta verificar estas restricciones.</p>}
          {fwEvidence?.software_asset_id && <p className="cve-muted">
            Evidencia seleccionada: <Link to={"/assets/" + fwEvidence.software_asset_id}>
              software #{fwEvidence.software_asset_id}</Link> · Origen: {
              SOURCE_LABEL[fwEvidence.source] || fwEvidence.source
            }</p>}
        </Condition>
      </div>
      <details className="cve-raw-details">
        <summary>Ver estructura original de la configuración NVD</summary>
        <pre>{JSON.stringify(info.configuration, null, 2)}</pre>
      </details>
    </section>

    <section className="panel cve-section" aria-labelledby="cve-install-title">
      <h2 id="cve-install-title">Firmware instalado en el hardware</h2>
      <p className="cve-muted">Estas relaciones proceden de <code>SoftwareInstallation</code>
        y están activas en el inventario. La instalación no equivale a confirmar
        que el firmware cumple el criterio NVD.</p>
      {info.software_asset_4 && <p className="cve-asset-4">
        Software experimental <Link to="/assets/4">#{info.software_asset_4.id} · {
          info.software_asset_4.name}</Link>:
        {" "}<strong>{info.software_asset_4.installed_on_hardware
          ? "Instalación vigente encontrada"
          : "Sin instalación vigente con el hardware #2"}</strong>
      </p>}
      {installations.length === 0
        ? <div className="cpe-warning">
            No hay instalaciones vigentes de firmware registradas para este hardware.
            No se puede concluir «No aplica» ni confirmar el firmware sin evidencia.
            <p><Link to={"/assets/" + info.hardware_asset_id}>
              Gestionar instalaciones desde el detalle del hardware
            </Link></p>
          </div>
        : <div className="cve-install-list">
            {installations.map(item => <div className="cve-install-item" key={item.installation_id}>
              <div><strong><Link to={"/assets/" + item.software_asset_id}>
                {item.software_name}</Link></strong>
                <p>{item.manufacturer} · {item.product} ·
                  {" "}{item.version ? "Versión " + item.version : "Versión no registrada"}</p>
              </div>
              <span className="cve-install-tag">Instalación #{item.installation_id} · Vigente</span>
            </div>)}
          </div>}
    </section>

    <section className="panel cve-section" aria-labelledby="cve-decision-title">
      <h2 id="cve-decision-title">Evaluación del analista</h2>
      <p className="cve-muted">La selección es manual. VISOR OT no confirmará una
        vulnerabilidad por compartir fabricante, modelo o nombre de firmware.</p>
      {!canDecide ? <p className="cve-note">
        Tu rol permite consultar la evaluación y el historial, pero solo un
        analista o administrador puede registrar decisiones.
      </p> : <form className="cve-decision-form" onSubmit={save}>
        <div className="cve-fields">
          <div className="cve-field">
            <label htmlFor="cve-installed-software">Instalación usada como evidencia</label>
            <select id="cve-installed-software" value={form.software_installation_id}
              disabled={saving || confirming}
              onChange={e => updateForm("software_installation_id", e.target.value)}>
              <option value="">Sin instalación seleccionada</option>
              {installations.map(item => <option key={item.installation_id}
                value={item.installation_id}>
                #{item.installation_id} · {item.software_name} · {
                  item.version || "Sin versión"} (activo #{item.software_asset_id})
              </option>)}
            </select>
          </div>
          <div className="cve-field">
            <label htmlFor="cve-verdict">Conclusión sobre el firmware</label>
            <select id="cve-verdict" value={form.firmware_verdict}
              disabled={saving || confirming}
              onChange={e => updateForm("firmware_verdict", e.target.value)}>
              {Object.entries(VERDICT_LABEL).map(([key, label]) =>
                <option key={key} value={key}>{label}</option>)}
            </select>
          </div>
          <div className="cve-field">
            <label htmlFor="cve-evidence-source">Procedencia de la evidencia</label>
            <select id="cve-evidence-source" value={form.evidence_source}
              disabled={saving || confirming}
              onChange={e => updateForm("evidence_source", e.target.value)}>
              {Object.entries(SOURCE_LABEL).map(([key, label]) =>
                <option key={key} value={key}>{label}</option>)}
            </select>
          </div>
        </div>
        {form.firmware_verdict === "NOT_MATCH" && <div className="cve-attestation">
          <label><input type="checkbox" checked={form.inventory_declared_complete}
            disabled={saving || confirming || installations.length !== 1}
            onChange={e => updateForm("inventory_declared_complete", e.target.checked)}/>
            He verificado que el inventario de firmware instalado es completo y
            que no existen otras instalaciones de firmware sin evaluar.</label>
          <p>Sin esta declaración y evidencia negativa suficiente, el resultado
            permanecerá pendiente. Si hay varios firmwares, esta primera versión
            no permite descartar la configuración completa.</p>
        </div>}
        <div className="cve-field">
          <label htmlFor="cve-justification">Justificación de la decisión</label>
          <textarea id="cve-justification" value={form.justification}
            onChange={e => updateForm("justification", e.target.value)}
            maxLength={1000} rows={3}
            disabled={saving || confirming} required
            placeholder="Describe cómo comprobaste la correspondencia, discrepancia o incertidumbre..."/>
          <span className="cve-muted">{form.justification.length}/1000 caracteres</span>
        </div>
        <div className="cve-preview">
          <span>Estado previsto de esta configuración</span>
          <strong data-status={predicted}>{CVE_STATUS[predicted]}</strong>
          <p>Vista orientativa. El backend vuelve a comprobar las condiciones
            y la vigencia del inventario al guardar.</p>
        </div>
        {guard && !confirming && <p className="cve-hint" role="status">{guard}</p>}
        {!confirming
          ? <button className="button-primary" type="button"
              disabled={saving || Boolean(guard)}
              onClick={() => setConfirming(true)}>Revisar y registrar decisión</button>
          : <div className="cve-confirm-step">
            <h3>Confirmar registro</h3>
            <p>Vas a guardar una nueva evaluación auditada. No se modificarán
              los CPE ni las instalaciones del inventario.</p>
            <p><strong>{VERDICT_LABEL[form.firmware_verdict]}</strong> ·
              {" "}{firmwareSelected
                ? "Instalación #" + firmwareSelected.installation_id
                : "Sin instalación seleccionada"} ·
              {" "}{SOURCE_LABEL[form.evidence_source]}</p>
            <p className="cve-muted">Justificación: {form.justification}</p>
            <div className="cve-form-actions">
              <button type="submit" className="button-primary" disabled={saving || Boolean(guard)}>
                {saving ? "Registrando..." : "Confirmar y guardar evaluación"}
              </button>
              <button type="button" className="button-secondary"
                disabled={saving} onClick={() => setConfirming(false)}>Editar decisión</button>
            </div>
          </div>}
      </form>}
    </section>

    <section className="panel cve-section" aria-labelledby="cve-history-title">
      <h2 id="cve-history-title">Historial de evaluaciones</h2>
      {!info.history?.length ? <p className="cve-muted">
        Todavía no hay decisiones registradas para esta configuración.
      </p> : <ol className="cve-history">
        {info.history.map(record => <li key={record.id}>
          <div className="cve-history-heading">
            <strong>Evaluación #{record.id}</strong>
            <span className="cve-status-label" data-status={
              record.stale ? "PENDING_REVIEW" : record.effective_status
            }>{CVE_STATUS[record.effective_status] || record.effective_status}</span>
          </div>
          <p>{record.decided_by || "Usuario retirado"} · {
            localizedTimestamp(record.decided_at)}</p>
          {record.stale && <p className="cve-history-warning">
            Evidencia histórica: requiere nueva revisión del inventario o la configuración.
          </p>}
          <p>{record.justification}</p>
          <details><summary>Ver evidencia registrada</summary>
            <p>Configuración examinada: índice {
              record.configuration_index + 1}</p>
            <pre>{JSON.stringify(record.criteria_evidence, null, 2)}</pre>
          </details>
        </li>)}
      </ol>}
      <p className="cve-hint">El historial es de solo lectura y conserva las
        condiciones evaluadas. Una nueva decisión añade otro registro.</p>
    </section>
  </section>;
}
