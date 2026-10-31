import { useMemo, useState } from "react";
import { Link, useOutletContext } from "react-router-dom";
import { confirmAssetsExcel, previewAssetsExcel } from "../api/assets";
import { getSystems } from "../api/systems";
import { canCreateAssets } from "../utils/assetPermissions";

const LABELS = {CREATE:"Nuevo", UPDATE:"Con diferencias", SAME:"Sin cambios",
  REVIEW:"Posible duplicado", ERROR:"Requiere corrección"};
const COLUMNS = {nombre_activo:"Nombre", descripcion:"Descripción", fabricante:"Fabricante",
  modelo:"Modelo", rol:"Rol", numero_serie:"Serie", ubicacion_fisica:"Ubicación",
  criticidad:"Criticidad", impacto_indisponibilidad:"Impacto",
  costo_reposicion:"Costo", moneda:"Moneda", tipo_software:"Tipo de software",
  producto:"Producto", version:"Versión"};
const TECH = new Set(["tipo_software","fabricante","producto","version"]);
const stringify = (value) => value == null || value === "" ? "Sin registrar" : String(value);

export default function AssetImport() {
  const { user } = useOutletContext();
  const [file, setFile] = useState(null);
  const [preview, setPreview] = useState(null);
  const [actions, setActions] = useState({});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);
  const [systems, setSystems] = useState([]);
  const selected = useMemo(() => Object.values(actions)
    .filter((item) => item.action !== "SKIP").length, [actions]);

  function modify(key, changes) {
    setActions((old) => ({ ...old, [key]: { ...old[key], ...changes } }));
  }
  async function analyze() {
    if (!file || busy) return;
    setBusy(true);
    setError("");
    setResult(null);
    try {
      const [data, availableSystems] = await Promise.all([
        previewAssetsExcel(file), getSystems("ACTIVE"),
      ]);
      setSystems(availableSystems);
      setPreview(data);
      setActions(Object.fromEntries(data.rows.map((row) => [row.key, {
        action: row.status === "CREATE" ? "CREATE" : "SKIP",
        fields: [], correction_reason: "", confirm_shared_correction: false,
        system_ids: [],
      }])));
    } catch (err) {
      setPreview(null);
      setError(err.message);
    } finally { setBusy(false); }
  }
  async function confirm() {
    if (!preview || busy) return;
    const invalid = preview.rows.find((row) => {
      const choice = actions[row.key];
      if (choice.action === "CREATE" && row.sheet === "Hardware") {
        return !choice.system_ids?.length || choice.system_ids.some(
          id => !systems.some(system => system.id === id)
        );
      }
      return choice.action === "UPDATE" && (!choice.fields.length ||
        (row.sheet === "Software" && choice.fields.some((f) => TECH.has(f)) &&
          !choice.correction_reason.trim()));
    });
    if (invalid) {
      setError("Revisa los campos, el motivo de corrección y los sistemas OT activos de " +
        invalid.key + ".");
      return;
    }
    setBusy(true);
    setError("");
    try {
      const data = await confirmAssetsExcel(file, preview.token, actions);
      setResult(data);
      setPreview(null);
      setActions({});
    } catch (err) { setError(err.message); }
    finally { setBusy(false); }
  }

  if (!canCreateAssets(user)) return (
    <section className="page">
      No tienes permiso para importar activos. <Link to="/assets">Volver</Link>
    </section>
  );
  return (
    <section className="page">
      <header className="page-header assets-page-heading">
        <div><span className="page-eyebrow">ACTIVOS</span>
          <h1>Importar Excel</h1><p>Revisa cada fila antes de guardar cambios.</p></div>
        <Link className="button-secondary" to="/assets">Volver al inventario</Link>
      </header>
      <div className="panel">
        <div className="panel-header"><h2>Seleccionar Excel</h2></div>
        <div className="interface-panel-padding">
          <p className="interface-hint">Se requieren las hojas Hardware y Software, con
            los encabezados exportados por Visor OT. Máximo 2 MB y 500 filas.
            Los campos vacíos no borran datos y no se importan instalaciones ni interfaces.</p>
          <input type="file" accept=".xlsx" aria-label="Excel de inventario"
            disabled={busy} onChange={(event) => {
              setFile(event.target.files?.[0] || null);
              setPreview(null); setResult(null); setActions({}); setError("");
            }} />
          <div className="table-actions interface-panel-actions">
            <button type="button" className="button-primary"
              disabled={!file || busy} onClick={analyze}>
              {busy ? "Analizando..." : "Previsualizar Excel"}
            </button>
          </div>
        </div>
      </div>
      {error && <div role="alert" className="error-message">{error}</div>}
      {result && <div className="panel">
        <div className="interface-panel-padding">
          <h2>Importación finalizada · #{result.import_id}</h2>
          <p>Creados: {result.created.length}. Actualizados: {result.updated.length}.
            Omitidos: {result.skipped.length}.</p>
          <Link to="/assets" className="button-primary">Consultar inventario</Link>
        </div>
      </div>}
      {preview && <>
        <div className="panel">
          <div className="panel-header">
            <h2>Previsualización (no se ha guardado nada)</h2>
          </div>
          <div className="interface-panel-padding">
            <div className="asset-import-summary">
              {Object.entries(LABELS).map(([key, name]) => (
                <span key={key}><strong>{preview.summary[key]}</strong> {name}</span>
              ))}
            </div>
            <p className="interface-hint">Los existentes se omiten por defecto;
              debes aprobar individualmente los campos que quieras actualizar.
              Las coincidencias ambiguas necesitan resolución en el Excel.</p>
          </div>
        </div>
        {preview.rows.map((row) => {
          const choice = actions[row.key];
          const differences = Object.entries(row.fields || {});
          const needsReason = row.sheet === "Software" &&
            choice.fields.some((field) => TECH.has(field));
          return <div className="panel asset-import-row" key={row.key}>
            <div className="panel-header">
              <div><h3>{row.name || "Sin nombre"}</h3>
                <p>{row.sheet}, fila {row.row},
                  {row.id_visor_ot ? " ID #" + row.id_visor_ot : " nuevo registro"}</p></div>
              <strong>{LABELS[row.status]}</strong>
            </div>
            <div className="interface-panel-padding">
              {row.messages.map((message,i) => (
                <p key={i} className="asset-import-warning">{message}</p>
              ))}
              {row.status === "UPDATE" && differences.length > 0 && (
                <div className="table-container">
                  <table className="data-table">
                    <thead><tr><th>Aplicar</th><th>Campo</th><th>Actual</th><th>Excel</th></tr></thead>
                    <tbody>{differences.map(([field, change]) => (
                      <tr key={field}>
                        <td><input type="checkbox" disabled={busy || choice.action !== "UPDATE"}
                          aria-label={"Actualizar " + field}
                          checked={choice.fields.includes(field)}
                          onChange={(event) => modify(row.key, {
                            fields: event.target.checked ? [...choice.fields, field] :
                              choice.fields.filter((value) => value !== field),
                          })}/></td>
                        <td>{COLUMNS[field] || field}</td>
                        <td>{stringify(change.current)}</td>
                        <td>{stringify(change.incoming)}</td>
                      </tr>
                    ))}</tbody>
                  </table>
                </div>
              )}
              <label className="asset-import-action">
                Acción
                <select value={choice.action} disabled={busy}
                  onChange={(event)=>modify(row.key, {action:event.target.value, fields:[]})}>
                  <option value="SKIP">Omitir</option>
                  {row.status === "CREATE" && <option value="CREATE">Crear nuevo</option>}
                  {row.status === "UPDATE" && <option value="UPDATE">Actualizar campos elegidos</option>}
                </select>
              </label>
              {row.status === "CREATE" && row.sheet === "Hardware" &&
                choice.action === "CREATE" && <div className="asset-import-correction">
                  <p className="interface-hint">Sistemas OT activos asociados al hardware *</p>
                  {systems.length === 0 &&
                    <p className="asset-import-warning">
                      No hay sistemas OT activos. <Link to="/assets/systems/new">
                      Registra un sistema antes de importar hardware.</Link>
                    </p>}
                  {systems.map(system => <label className="system-initial-choice"
                    key={system.id}>
                    <input type="checkbox" disabled={busy}
                      checked={(choice.system_ids || []).includes(system.id)}
                      onChange={event => modify(row.key, {
                        system_ids: event.target.checked
                          ? [...(choice.system_ids || []), system.id]
                          : (choice.system_ids || []).filter(id => id !== system.id),
                      })}/>
                    {system.name}
                  </label>)}
                </div>}
              {choice.action === "UPDATE" && needsReason && <div className="asset-import-correction">
                <label htmlFor={"reason-" + row.key}>Motivo de corrección técnica *</label>
                <textarea id={"reason-" + row.key} rows={2}
                  value={choice.correction_reason} disabled={busy}
                  onChange={(event) => modify(row.key,{correction_reason:event.target.value})}/>
                <label className="software-correction-confirm">
                  <input type="checkbox" disabled={busy} checked={choice.confirm_shared_correction}
                    onChange={(event) => modify(row.key,{
                      confirm_shared_correction:event.target.checked
                    })}/>
                  Confirmo la corrección si el software está instalado en varios hardware.
                </label>
              </div>}
            </div>
          </div>;
        })}
        <div className="panel"><div className="interface-panel-padding">
          <p>{selected} registros seleccionados para crear o actualizar. Los demás se omitirán.</p>
          <p className="interface-hint">La confirmación volverá a validar el archivo y el inventario.</p>
          <div className="table-actions interface-panel-actions">
            <Link className="button-secondary" to="/assets">Cancelar</Link>
            <button type="button" className="button-primary" disabled={busy || !selected}
              onClick={confirm}>{busy ? "Guardando..." : "Confirmar importación"}</button>
          </div>
        </div></div>
      </>}
    </section>
  );
}
