import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { SYSTEM_CRITICALITY_LABELS, systemFormValues, systemPayload } from "../utils/systemUi";

export default function SystemForm({system,saving,error,onSave,back,onDirtyChange}) {
  const [values,setValues]=useState(()=>systemFormValues(system));
  const dirty=JSON.stringify(values)!==JSON.stringify(systemFormValues(system));
  useEffect(()=>{onDirtyChange?.(dirty);},[dirty,onDirtyChange]);

  function update(name,value) {setValues(current=>({...current,[name]:value}));}
  function confirmBack(event) {
    if (saving || (dirty&&!window.confirm("Tienes cambios sin guardar. ¿Deseas descartarlos?")))
      event.preventDefault();
  }
  function submit(event) {
    event.preventDefault();
    if (saving) return;
    const payload=systemPayload(values);
    if (!payload.name || !["LOW", "MEDIUM", "HIGH"].includes(payload.criticality)) return;
    onSave(payload);
  }
  return <section className="panel">
    <form className="assets-form" onSubmit={submit}>
      <div className="assets-form-section">
        <h2>Información general</h2>
        <div className="assets-form-grid">
          <div className="assets-field assets-full-row">
            <label htmlFor="sys-name">Nombre del sistema *</label>
            <input id="sys-name" required maxLength={200} disabled={saving}
              placeholder="Ej. Entorno experimental 4SICS Geek Lounge"
              value={values.name} onChange={e=>update("name",e.target.value)}/>
          </div>
          <div className="assets-field assets-full-row">
            <label htmlFor="sys-description">Descripción / función operacional</label>
            <textarea id="sys-description" rows={4} disabled={saving}
              value={values.description} onChange={e=>update("description",e.target.value)}
              placeholder="Describe qué función cumple el sistema..."/>
          </div>
        </div>
      </div>
      <div className="assets-form-section">
        <h2>Valoración operacional</h2>
        <div className="assets-form-grid">
          <div className="assets-field">
            <label htmlFor="sys-criticality">Criticidad *</label>
            <select id="sys-criticality" value={values.criticality} disabled={saving}
              onChange={e=>update("criticality",e.target.value)}>
              {Object.entries(SYSTEM_CRITICALITY_LABELS).map(([value,label])=>
                <option key={value} value={value}
                  disabled={!system && value === "UNDEFINED"}>
                  {!system && value === "UNDEFINED" ? "Selecciona criticidad *" : label}
                </option>)}
            </select>
            <small>La criticidad debe ser Baja, Media o Alta.
              Los sistemas históricos sin definir se pueden regularizar desde la edición.</small>
          </div>
          <div className="assets-field">
            <label htmlFor="sys-justification">Justificación de criticidad</label>
            <textarea id="sys-justification" rows={3} disabled={saving}
              value={values.criticality_justification}
              onChange={e=>update("criticality_justification",e.target.value)}/>
          </div>
          <div className="assets-field assets-full-row">
            <label htmlFor="sys-impact">Impacto de indisponibilidad</label>
            <textarea id="sys-impact" rows={3} disabled={saving}
              value={values.impact} onChange={e=>update("impact",e.target.value)}/>
          </div>
        </div>
      </div>
      {error&&<div className="error-message assets-form-error" role="alert">{error}</div>}
      <div className="assets-form-actions">
        <Link className="button-secondary" to={back.to} state={back.state}
          onClick={confirmBack}>Cancelar</Link>
        <button className="button-primary" type="submit"
          disabled={saving || !values.name.trim() ||
            !["LOW", "MEDIUM", "HIGH"].includes(values.criticality)}>
          {saving?"Guardando...":"Guardar sistema"}
        </button>
      </div>
    </form>
  </section>;
}
