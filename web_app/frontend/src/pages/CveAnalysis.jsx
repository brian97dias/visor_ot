import { useEffect, useState } from "react";
import { Link, useOutletContext } from "react-router-dom";
import SuccessNotice from "../components/SuccessNotice";
import {
  createExperimentalCveAssessment, getExperimentalCveAssessment,
} from "../api/vulnerabilities";
import {
  CVE_STATUS, EVIDENCE_STATE, EXPERIMENT_CVE_ID,
  currentCriterionEvidence, latestEffectiveStatus, submissionGuard,
  localizedTimestamp, versionConstraintsText, selectedFirmwareInstallation,
  proposedFirmwareDecision, assessmentActionOptions, experimentalDescription,
  nvdCveDetailUrl, nvdCvesApiByCpeNameUrl,
} from "../utils/cveAssessmentPresentation";

const severityLabel = {
  CRITICAL: "Crítica", HIGH: "Alta", MEDIUM: "Media", LOW: "Baja",
};

function CriterionId({ criterion }) {
  return criterion?.match_criteria_id
    ? <p className="cve-criterion-id">ID del criterio NVD: <code>{criterion.match_criteria_id}</code></p>
    : null;
}

export default function CveAnalysis() {
  const { user } = useOutletContext();
  const canDecide = ["ADMIN", "ANALYST"].includes(user?.role);
  const [info, setInfo] = useState(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [selectedId, setSelectedId] = useState("");
  const [choice, setChoice] = useState("");
  const [justification, setJustification] = useState("");
  const [complete, setComplete] = useState(false);

  useEffect(() => {
    let active = true;
    // Every visit reads the current inventory, active installation and NVD
    // configuration through Django; no manual refresh button is needed.
    getExperimentalCveAssessment()
      .then(data => { if (active) setInfo(data); })
      .catch(err => { if (active) setError(err.message); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, []);

  function clearDecision() {
    setChoice("");
    setJustification("");
    setComplete(false);
  }

  function chooseDecision(next) {
    if (choice !== next) {
      setJustification("");
    }
    setChoice(next);
    setComplete(false);
    setError("");
  }

  const installations = info?.active_firmware_installations || [];
  const installed = selectedFirmwareInstallation(info, selectedId);
  const hardware = currentCriterionEvidence(info, "hardware");
  const firmware = currentCriterionEvidence(info, "firmware");
  const last = info?.latest_assessment;
  const status = latestEffectiveStatus(info);
  const actionOptions = assessmentActionOptions(status);
  const isUndo = choice === "UNKNOWN";
  const isCurrentPositive = status === "APPLIES";
  const description = experimentalDescription(
    info?.cve_id, info?.description, info?.descriptions
  );
  const versionBounds = versionConstraintsText(
    info?.criteria_evidence?.firmware?.version_constraints
  );
  // For undo, retain the previously evaluated installation when it is still current.
  // Unknown without an installation remains valid if the asset was changed/unlinked.
  const preferredInstallationId = isUndo
    ? (selectedId || String(last?.software_installation_id || ""))
    : selectedId;
  const draft = proposedFirmwareDecision(
    info, choice, preferredInstallationId, justification, complete
  );
  const guard = choice ? submissionGuard(info, draft) : "";
  const hardwareConfirmed = Boolean(info?.hardware_cpe_confirmed);
  const canAttestInventory = choice === "NOT_MATCH" && installations.length === 1;
  const cveApiUrl = nvdCvesApiByCpeNameUrl(hardware?.criteria);
  const cveDetailUrl = nvdCveDetailUrl(info?.cve_id);

  async function save(event) {
    event.preventDefault();
    if (!choice || !canDecide || saving || guard) return;
    setSaving(true);
    setError("");
    setNotice("");
    let created;
    try {
      created = await createExperimentalCveAssessment({
        ...draft,
        justification: draft.justification.trim(),
        inventory_fingerprint: info.inventory_fingerprint,
        configuration_fingerprint: info.configuration_fingerprint,
      });
    } catch (err) {
      setError("No se registró la evaluación: " + err.message +
        ". Si el inventario cambió, recarga la página antes de decidir.");
      setSaving(false);
      return;
    }
    clearDecision();
    setNotice(choice === "UNKNOWN"
      ? "Evaluación #" + created.assessment.id +
        ": correspondencia deshecha. El CVE queda pendiente de revisión."
      : "Evaluación #" + created.assessment.id + ": " +
        (CVE_STATUS[created.assessment.status] || created.assessment.status) +
        ". Decisión guardada en el historial.");
    try {
      // Read fresh evidence and append-only history after successful POST.
      const updated = await getExperimentalCveAssessment();
      setInfo(updated);
      setSelectedId("");
    } catch (err) {
      // Never suggest re-submitting: POST already committed the decision.
      setError("La evaluación se guardó, pero no pudimos actualizar el historial: " +
        err.message + ". Vuelve a abrir esta pantalla.");
    } finally {
      setSaving(false);
    }
  }

  if (loading) return <section className="page" aria-busy="true">
    <p>Cargando análisis CVE...</p>
  </section>;

  if (!info) return <section className="page cve-analysis-page">
    <h1>{EXPERIMENT_CVE_ID}</h1>
    <p className="error-message" role="alert">
      {error || "No se pudo consultar la evaluación del hardware #2."}
    </p>
    <p>Vuelve a abrir Análisis CVE o recarga la página para consultar los datos actuales.</p>
  </section>;

  return <section className="page cve-analysis-page cve-nvd-detail">
    <nav className="breadcrumbs" aria-label="Ruta de navegación">
      <span>Vulnerabilidades</span><span>/</span>
      <Link to="/vulnerabilities/cpe">Identificación CPE</Link><span>/</span>
      <span>Análisis CVE</span>
    </nav>
    {error && <p className="error-message" role="alert">{error}</p>}
    <SuccessNotice message={notice} onClose={() => setNotice("")} durationMs={30000} />

    <header className="page-header cve-nvd-overview" aria-label="Resumen CVE">
      <span className="page-eyebrow">ANÁLISIS CVE</span>
      <div className="cve-nvd-titlebar">
        <div className="cve-nvd-header-text">
          <h1>
            {cveDetailUrl
              ? <a href={cveDetailUrl} target="_blank" rel="noopener noreferrer"
                  title="Abrir ficha oficial del CVE en NVD">
                  {info.cve_id}<span aria-hidden="true" className="cve-external-mark"> ↗</span>
                </a>
              : info.cve_id}
          </h1>
          {cveApiUrl && <div className="cve-nvd-api-link">
            <a href={cveApiUrl} target="_blank" rel="noopener noreferrer"
              title="Abrir respuesta JSON de NVD para este CPE">
              Búsqueda de CVE por CPE name · API NVD <span aria-hidden="true">↗</span>
            </a>
          </div>}
          <p className="cve-nvd-description-heading">Descripción</p>
          <p className="cve-nvd-description">{description.text}</p>
          <p className="cve-nvd-description-label">{description.label}</p>
          <p className="cve-nvd-meta">
            Evaluación del hardware <Link to={"/assets/" + info.hardware_asset_id}>
              #{info.hardware_asset_id}</Link> · Configuración {info.configuration_position}
          </p>
        </div>
        <div className="cve-nvd-badges" aria-label="Severidad y estado">
          <span className="cve-nvd-severity" data-level={info.severity}>
            {severityLabel[info.severity] || info.severity || "Sin clasificar"}
            {info.base_score != null ? " · " + info.base_score : ""}
          </span>
          <span className="cve-status-label" data-status={status}>
            {last ? CVE_STATUS[status] : "Por verificar"}
          </span>
        </div>
      </div>
      {last?.stale && <p className="cpe-warning" role="status">
        La evidencia del inventario o la configuración NVD cambió.
        La última evaluación se conserva en el historial, pero requiere revisión.
      </p>}
    </header>

    <section className="cve-nvd-conditions" aria-labelledby="cve-conditions-title">
      <h2 id="cve-conditions-title">Se requieren ambas condiciones</h2>

      <article className="cve-nvd-condition cve-nvd-hardware">
        <div className="cve-nvd-condition-heading">
          <div className="cve-nvd-condition-tags">
            <h3>Hardware</h3>
            <span className="cve-nvd-category cve-nvd-platform">Condición de plataforma</span>
          </div>
          <span className="cve-condition-state" data-state={
            hardwareConfirmed ? "SATISFIED" : "UNVERIFIED"
          }>{hardwareConfirmed ? "Confirmado" : "Sin verificar"}</span>
        </div>
        <p className="cve-nvd-product">{info.hardware_name}</p>
        <p className="cve-muted">Activo #{info.hardware_asset_id} · {
          hardwareConfirmed ? "CPE confirmado y vigente" : "CPE no confirmado"
        }</p>
        <div className="cve-nvd-criterion">
          <span className="cve-nvd-criterion-label">CPE de hardware · NVD</span>
          {cveApiUrl
            ? <a href={cveApiUrl} target="_blank" rel="noopener noreferrer"
                title="Consultar la API de CVE de NVD filtrada por este CPE">
                <code>{hardware?.criteria}</code> <span aria-hidden="true">↗</span>
              </a>
            : <code>{hardware?.criteria || "CPE no disponible"}</code>}
          <CriterionId criterion={hardware}/>
          {cveApiUrl && <p className="cve-nvd-source-note">
            La consulta abre la respuesta JSON de CVE por CPE name en NVD;
            no confirma por sí misma que la vulnerabilidad aplique al activo.
          </p>}
        </div>
      </article>

      <div className="cve-nvd-plus" aria-label="Y: ambas condiciones deben cumplirse">+</div>

      <article className="cve-nvd-condition cve-nvd-firmware">
        <div className="cve-nvd-condition-heading">
          <div className="cve-nvd-condition-tags">
            <h3>Firmware</h3>
            <span className="cve-nvd-category cve-nvd-vulnerable">Componente vulnerable</span>
          </div>
          <span className="cve-condition-state" data-state={firmware?.state || "UNVERIFIED"}>
            {EVIDENCE_STATE[firmware?.state] === "Condición satisfecha"
              ? "Confirmado" : EVIDENCE_STATE[firmware?.state] === "Condición descartada"
                ? "Descartado" : "Sin verificar"}
          </span>
        </div>
        <p className="cve-nvd-product">
          {firmware?.display_name || "Phoenix Contact IL PN BK-PAC Firmware"}
        </p>
        <p className="cve-muted">Criterio NVD sin un CPE oficial de diccionario identificado.</p>

        <div className="cve-nvd-criterion cve-nvd-firmware-criterion">
          <span className="cve-nvd-criterion-label">Criterio de firmware · NVD</span>
          <code>{firmware?.criteria || "No disponible"}</code>
          <CriterionId criterion={firmware}/>
        </div>

        <div className="cve-nvd-found">
          <h4>Firmware instalado en el hardware #{info.hardware_asset_id}</h4>
          {installations.length === 0 ? <>
            <p className="cve-muted">No hay instalaciones vigentes de firmware registradas.
              No es evidencia de que esta configuración no aplique.</p>
            <Link to={"/assets/" + info.hardware_asset_id}>
              Consultar instalaciones en el inventario
            </Link>
          </> : <>
            {installations.length > 1 && <p className="cve-muted">
              Hay varias instalaciones vigentes. Selecciona cuál deseas verificar.
            </p>}
            {installations.map(item => <div className="cve-nvd-installed" key={item.installation_id}>
              {installations.length > 1 && <label className="cve-firmware-pick">
                <input type="radio" name="firmware-evidence"
                  disabled={saving} checked={Number(selectedId) === item.installation_id}
                  onChange={() => { setSelectedId(String(item.installation_id)); clearDecision(); }}/>
                Seleccionar esta instalación
              </label>}
              <strong><Link to={"/assets/" + item.software_asset_id}>
                {item.software_name}</Link></strong>
              <p className="cve-muted">Software #{item.software_asset_id} · Instalación vigente
                #{item.installation_id} · {item.version
                  ? "Versión " + item.version : "Versión desconocida"}</p>
            </div>)}
          </>}
        </div>

        {versionBounds && <p className="cpe-warning">
          NVD especifica restricciones de versión: {versionBounds}.
          Hasta comprobarlas, el backend conserva la evaluación pendiente.
        </p>}

      </article>

      <div className="panel cve-nvd-decision" aria-labelledby="cve-joint-decision-title">
        <div className="cve-nvd-joint-title">
          <h3 id="cve-joint-decision-title">Evaluación conjunta · Hardware + Firmware</h3>
          <span className="cve-status-label" data-status={status}>{CVE_STATUS[status]}</span>
        </div>
        <p>La evaluación corresponde a la configuración {info.configuration_position} de NVD
          para el hardware <strong>#{info.hardware_asset_id} · {info.hardware_name}</strong>,
          junto con su firmware instalado. No confirma un CVE solo por el nombre del firmware.</p>
        <div className="cve-joint-criteria" aria-label="Condiciones de la configuración">
          <span>Hardware: {hardwareConfirmed ? "CPE confirmado" : "CPE sin verificar"}</span>
          <span>+</span>
          <span>Firmware: {EVIDENCE_STATE[firmware?.state] || "Sin verificar"}</span>
        </div>
        {last && !last.stale && last.software_installation_id && <p className="cve-muted">
          Instalación evaluada #{last.software_installation_id}
          {installations.find(item => item.installation_id === last.software_installation_id)
            ? " · Firmware instalado en el hardware #" + info.hardware_asset_id : ""}
        </p>}
        {isCurrentPositive && <p className="cve-joint-explanation">
          Esta configuración está confirmada. Puedes deshacer la correspondencia;
          el historial de la decisión original se conservará.
        </p>}
        <div className="cve-nvd-actions">
          {canDecide && actionOptions.map(action => <button type="button" key={action.key}
            className={"cve-nvd-action" + (choice === action.key ? " selected" : "")}
            data-action={action.key}
            aria-pressed={choice === action.key}
            disabled={saving || (action.key !== "UNKNOWN" && !installed)}
            onClick={() => chooseDecision(action.key)}>
            {action.title}
          </button>)}
        </div>
          {choice && <form className="cve-compact-review" onSubmit={save}>
            <label htmlFor="cve-justification">Justificación de la decisión</label>
            <textarea id="cve-justification" maxLength={1000} rows={3}
              value={justification} disabled={saving} required
              placeholder={choice === "UNKNOWN"
                ? "Explica por qué deshaces la correspondencia..."
                : choice === "CONFIRMED"
                  ? "Explica por qué el firmware corresponde al criterio de NVD..."
                  : "Explica por qué el firmware no corresponde al criterio de NVD..."}
              onChange={event => setJustification(event.target.value)}/>
            <small>{justification.length}/1000 caracteres</small>

            {choice === "NOT_MATCH" && <div className="cve-attestation">
              <label><input type="checkbox" checked={complete}
                disabled={saving || !canAttestInventory}
                onChange={event => setComplete(event.target.checked)}/>
                También verifiqué que el inventario de firmware instalado está completo
                y no existen otras instalaciones pendientes de evaluar.
              </label>
              <p>Sin esta comprobación, registrar una discrepancia conserva
                el estado «Pendiente de revisión»; no significa «No aplica».</p>
              {installations.length > 1 && <p>Hay varios firmwares vigentes.
                No se puede descartar toda la configuración con una sola decisión.</p>}
            </div>}
            {guard && <p className="cve-hint" role="status">{guard}</p>}
            <div className="cve-form-actions">
              <button type="submit" className="button-primary"
                disabled={saving || Boolean(guard)}>{
                  saving ? "Guardando..." : isUndo ? "Confirmar y deshacer" : "Guardar evaluación"}</button>
              <button type="button" className="button-secondary"
                disabled={saving} onClick={clearDecision}>Cancelar</button>
            </div>
          </form>}
        {!canDecide && <p className="cve-muted">
          Este rol puede consultar la evaluación. Solo el analista o
          administrador puede registrar una decisión.</p>}
    </section>

    <details className="panel cve-section cve-history-fold">
      <summary>Historial de evaluaciones ({info.history?.length || 0})</summary>
      {!info.history?.length
        ? <p className="cve-muted">Aún no se han registrado evaluaciones.</p>
        : <ol className="cve-history">
          {info.history.map(record => <li key={record.id}>
            <div className="cve-history-heading">
              <strong>Evaluación #{record.id}</strong>
              <span className="cve-status-label" data-status={record.status}>
                {CVE_STATUS[record.status] || record.status}</span>
            </div>
            <p>Decidido por: {record.decided_by || "Usuario no disponible"} · {
              localizedTimestamp(record.decided_at)}</p>
            {record.stale && <p className="cve-history-warning">
              Evaluación histórica desactualizada: no representa el estado actual.
            </p>}
            <p>{record.justification}</p>
            <details className="cve-nvd-history-detail">
              <summary>Ver criterios evaluados</summary>
              <p>Hardware: {record.criteria_evidence?.hardware?.criteria || "No registrado"}</p>
              <p>Firmware: {record.criteria_evidence?.firmware?.criteria || "No registrado"}</p>
              <p>Instalación: {record.software_installation_id ?? "No seleccionada"}</p>
            </details>
          </li>)}
        </ol>}
    </details>
    <p className="cve-hint cve-nvd-scope">Esta evaluación corresponde únicamente
      a la configuración {info.configuration_position}, no a todas las configuraciones
      de {info.cve_id}.</p>
  </section>;
}
