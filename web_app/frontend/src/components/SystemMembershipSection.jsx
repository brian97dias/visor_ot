import { useEffect, useState } from "react";
import { Link, useLocation } from "react-router-dom";

import { getAssets } from "../api/assets";
import { getSystems, getSystemHardware, addHardwareToSystem, unlinkHardwareFromSystem,
  getHardwareSystems, addSystemToHardware, unlinkSystemFromHardware } from "../api/systems";
import { canManageSystems } from "../utils/systemUi";
import { navigationFromLocation } from "../utils/returnNavigation";
import SuccessNotice from "./SuccessNotice";

function prettyDate(value) {
  return value ? new Date(value).toLocaleString("es-CO") : "Sin registrar";
}

/**
 * Reciprocal SystemMembership view: one mutation service on the backend.
 * Embedded inside the Hardware edit form; all mutation actions are type=button.
 * Membership changes persist immediately, independently from the Hardware form.
 */
export default function SystemMembershipSection({
  system = null, asset = null, user, embedded = false, onMembershipsChange,
}) {
  const mode = system ? "system" : "hardware";
  const id = system ? system.id : asset.id;
  const location = useLocation();
  const navigationState = navigationFromLocation(location);
  const manageable = canManageSystems(user) &&
    (system ? system.status === "ACTIVE" : asset.inventory_status === "ACTIVE");
  const [data, setData] = useState({ results: [], history: [] });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [revision, setRevision] = useState(0);
  const [showChooser, setShowChooser] = useState(false);
  const [available, setAvailable] = useState([]);
  const [choicesLoading, setChoicesLoading] = useState(false);
  const [selectedId, setSelectedId] = useState("");
  const [busy, setBusy] = useState(false);
  const [pendingUnlink, setPendingUnlink] = useState(null);
  const [showHistory, setShowHistory] = useState(false);

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError("");
    const fetcher = mode === "system" ? getSystemHardware : getHardwareSystems;
    fetcher(id).then(result => { if (active) setData(result); })
      .catch(err => { if (active) setError(err.message); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [mode, id, revision]);

  useEffect(() => {
    if (!showChooser || !manageable) return;
    let active = true;
    setChoicesLoading(true);
    const promise = mode === "system" ? getAssets("ACTIVE") : getSystems("ACTIVE");
    promise.then(items => {
      if (!active) return;
      setAvailable(mode === "system" ?
        items.filter(item => item.asset_type === "HARDWARE") : items);
    })
      .catch(err => { if (active) setError(err.message); })
      .finally(() => { if (active) setChoicesLoading(false); });
    return () => { active = false; };
  }, [showChooser, manageable, mode, revision]);

  const currentIds = new Set(data.results.map(row =>
    mode === "system" ? row.hardware_asset_id : row.system_id));
  const choices = available.filter(item => !currentIds.has(item.id));

  async function associate() {
    if (!manageable || busy || !selectedId) return;
    setBusy(true); setError(""); setNotice("");
    try {
      if (mode === "system") await addHardwareToSystem(id, Number(selectedId));
      else await addSystemToHardware(id, Number(selectedId));
      setShowChooser(false); setSelectedId("");
      setRevision(n => n + 1);
      onMembershipsChange?.();
      setNotice("Asociación guardada. La pertenencia al sistema está vigente.");
    } catch (err) { setError(err.message); }
    finally { setBusy(false); }
  }

  async function unlink() {
    if (!pendingUnlink || busy || !manageable) return;
    setBusy(true); setError(""); setNotice("");
    try {
      if (mode === "system") await unlinkHardwareFromSystem(id, pendingUnlink.id);
      else await unlinkSystemFromHardware(id, pendingUnlink.id);
      setPendingUnlink(null);
      setRevision(n => n + 1);
      onMembershipsChange?.();
      setNotice("Asociación desvinculada. Se conserva el historial.");
    } catch (err) { setError(err.message); }
    finally { setBusy(false); }
  }

  function linkedLabel(row) {
    return mode === "system" ? row.hardware_name : row.system_name;
  }
  function linkedPath(row) {
    return mode === "system" ? "/assets/" + row.hardware_asset_id
      : "/assets/systems/" + row.system_id;
  }
  function relatedStatus(row) {
    return mode === "system" ? row.hardware_status : row.system_status;
  }

  return <section className={embedded ? "assets-form-section" : "panel assets-detail-section"}>
    <div className={embedded ? "interface-section-header" : "panel-header"}>
      <div>
        <h2>{mode === "system" ? "Hardware participante" : "Sistemas OT"}</h2>
        <p className="interface-hint">{mode === "system" ?
          "Dispositivos que participan en este sistema operacional." :
          "Sistemas operacionales de los que forma parte este hardware."}</p>
      </div>
      {manageable && <button type="button" className="button-secondary"
        disabled={busy} onClick={() => {
          setShowChooser(value => !value);
          setSelectedId("");
        }}>
        {showChooser ? "Cerrar selector" :
          mode === "system" ? "Asociar hardware" : "Asociar sistema"}
      </button>}
    </div>
    {embedded && manageable && <p className="interface-hint">
      Los cambios de asociación se guardan inmediatamente, por separado de «Guardar cambios».
    </p>}
    <SuccessNotice message={notice} onClose={() => setNotice("")}/>
    {error && <div className="error-message interface-panel-padding" role="alert">{error}</div>}
    {loading ? <p className="interface-panel-padding interface-hint">
      Cargando sistemas y hardware...
    </p> : data.results.length ? <div className="table-container">
      <table className="data-table">
        <thead><tr>
          <th>{mode === "system" ? "Hardware" : "Sistema OT"}</th>
          <th>{mode === "system" ? "Modelo / rol" : "Estado"}</th>
          <th>Vinculado por / fecha</th>
          <th>Acciones</th>
        </tr></thead>
        <tbody>{data.results.map(row => <tr key={row.id}>
          <td>
            <Link className="entity-link" to={linkedPath(row)} state={navigationState}>
              {linkedLabel(row)}
            </Link>
            {relatedStatus(row) === "ARCHIVED" &&
              <small className="interface-hint">Archivado (se conserva la relación)</small>}
          </td>
          <td>{mode === "system" ?
            ([row.manufacturer, row.model, row.hardware_role].filter(Boolean).join(" · ") ||
              "Sin registrar") : "Activo"}</td>
          <td>{row.registered_by} · {prettyDate(row.registered_at)}</td>
          <td>{manageable && <button className="button-secondary" type="button"
            disabled={busy} onClick={() => setPendingUnlink(row)}>Desvincular</button>}</td>
        </tr>)}</tbody>
      </table>
    </div> : <p className="interface-panel-padding interface-hint">
      {mode === "system" ? "Este sistema no tiene hardware participante todavía." :
        "Este hardware no pertenece a ningún sistema OT actualmente."}
    </p>}

    {showChooser && manageable && <div className="interface-panel-padding software-install-editor">
      <div className="assets-field">
        <label htmlFor={"membership-select-" + mode + "-" + id}>
          {mode === "system" ? "Hardware disponible" : "Sistema OT disponible"}
        </label>
        <select id={"membership-select-" + mode + "-" + id} value={selectedId}
          disabled={busy || choicesLoading} onChange={e => setSelectedId(e.target.value)}>
          <option value="">Selecciona un registro...</option>
          {choices.map(row => <option key={row.id} value={row.id}>
            {row.name}{mode === "system" && row.hardware?.role ?
              " · " + row.hardware.role : ""}
          </option>)}
        </select>
      </div>
      {choicesLoading && <p className="interface-hint">Cargando opciones...</p>}
      {!choicesLoading && !choices.length &&
        <p className="interface-hint">No hay registros activos disponibles para asociar.</p>}
      <div className="table-actions interface-panel-actions">
        <button type="button" className="button-secondary" disabled={busy}
          onClick={() => {setShowChooser(false); setSelectedId("");}}>Cancelar</button>
        <button type="button" className="button-primary" disabled={busy || !selectedId}
          onClick={associate}>{busy ? "Guardando..." : "Confirmar asociación"}</button>
      </div>
    </div>}

    {pendingUnlink && manageable && <div className="interface-panel-padding software-install-editor">
      <p>¿Desvincular <strong>{linkedLabel(pendingUnlink)}</strong>?
        El historial de pertenencia se conservará.</p>
      <div className="table-actions interface-panel-actions">
        <button type="button" className="button-secondary" disabled={busy}
          onClick={() => setPendingUnlink(null)}>Cancelar</button>
        <button type="button" className="button-primary" disabled={busy}
          onClick={unlink}>Confirmar desvinculación</button>
      </div>
    </div>}

    {data.history.length > 0 && <div className="interface-panel-padding">
      <button type="button" className="button-secondary"
        aria-expanded={showHistory} onClick={() => setShowHistory(x => !x)}>
        {showHistory ? "Ocultar historial" : "Ver historial"} ({data.history.length})
      </button>
      {showHistory && <div className="table-container">
        <table className="data-table">
          <thead><tr><th>Registro</th><th>Asociación</th><th>Desvinculación</th></tr></thead>
          <tbody>{data.history.map(row => <tr key={row.id}>
            <td><Link className="entity-link" to={linkedPath(row)} state={navigationState}>
              {linkedLabel(row)}</Link></td>
            <td>{row.registered_by} · {prettyDate(row.registered_at)}</td>
            <td>{row.unlinked_by || "Sin registrar"} · {prettyDate(row.unlinked_at)}</td>
          </tr>)}</tbody>
        </table>
      </div>}
    </div>}
  </section>;
}
