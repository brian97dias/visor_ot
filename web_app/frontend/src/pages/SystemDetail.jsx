import { useEffect, useState } from "react";
import { Link, useLocation, useNavigate, useOutletContext, useParams } from "react-router-dom";
import { getSystem, archiveSystem, restoreSystem } from "../api/systems";
import { canManageSystems, SYSTEM_CRITICALITY_LABELS, SYSTEM_STATUS_LABELS } from "../utils/systemUi";
import { getBackNavigation, navigationFromLocation } from "../utils/returnNavigation";
import ConfirmSystemStatusModal from "../components/ConfirmSystemStatusModal";
import SuccessNotice from "../components/SuccessNotice";

function Field({label,value,wide=false}) {
  return <div className={wide?"assets-full-row":undefined}>
    <span>{label}</span>
    <strong>{value===null||value===undefined||value===""?"Sin registrar":value}</strong>
  </div>;
}
function formatDate(value) {
  if(!value)return "Sin registrar";
  const date=new Date(value);
  return Number.isNaN(date.getTime())?value:date.toLocaleString("es-CO");
}

export default function SystemDetail() {
  const {systemId}=useParams();
  const {user}=useOutletContext();
  const location=useLocation();
  const navigate=useNavigate();
  const back=getBackNavigation(location,"/assets/systems");
  const ctx=navigationFromLocation(location);
  const [system,setSystem]=useState(null);
  const [loading,setLoading]=useState(true);
  const [error,setError]=useState("");
  const [notice,setNotice]=useState(location.state?.notice||"");
  const [busy,setBusy]=useState(false);
  const [confirm,setConfirm]=useState(false);

  useEffect(()=>{
    let active=true;
    setLoading(true);setError("");
    getSystem(systemId).then(data=>{if(active)setSystem(data);})
      .catch(e=>{if(active)setError(e.message);})
      .finally(()=>{if(active)setLoading(false);});
    return ()=>{active=false;};
  },[systemId]);
  useEffect(()=>{
    if(!location.state?.notice)return;
    setNotice(location.state.notice);
    const rest={...location.state};
    delete rest.notice;
    navigate(location.pathname+location.search,{replace:true,state:rest});
  },[location.state,location.pathname,location.search,navigate]);

  async function changeStatus(){
    if(!system||busy)return;
    setBusy(true);setError("");
    try {
      const updated=system.status==="ARCHIVED"?
        await restoreSystem(system.id):await archiveSystem(system.id);
      setSystem(updated);
      setNotice(updated.status==="ARCHIVED"?
        "Sistema archivado correctamente.":"Sistema restaurado correctamente.");
    }catch(e){setError(e.message);}
    finally{setBusy(false);setConfirm(false);}
  }
  if(loading)return <section className="page">Cargando sistema...</section>;
  if(!system)return <section className="page">
    <div className="error-message">{error||"Sistema no encontrado."}</div>
    <Link to={back.to} state={back.state}>Volver</Link>
  </section>;

  return <section className="page">
    <div className="breadcrumbs">
      <span>Activos</span><span>/</span><Link to="/assets/systems">Sistemas</Link>
      <span>/</span><span>#{system.id}</span>
    </div>
    <Link className="button-secondary assets-back-link" to={back.to}
      state={back.state}>← Volver</Link>
    <header className="page-header assets-page-heading">
      <div><span className="page-eyebrow">SISTEMA OT #{system.id}</span>
        <h1>{system.name}</h1><p>Información y valoración operacional del sistema.</p>
      </div>
      {canManageSystems(user)&&<div className="table-actions assets-detail-actions">
        {system.status==="ACTIVE"&&
          <Link className="button-primary assets-primary-link"
            to={"/assets/systems/"+system.id+"/edit"} state={ctx}>Editar sistema</Link>}
        <button type="button" className="button-secondary assets-archive-button"
          disabled={busy} onClick={()=>setConfirm(true)}>
          {system.status==="ARCHIVED"?"Restaurar sistema":"Archivar sistema"}
        </button>
      </div>}
    </header>
    <SuccessNotice message={notice} onClose={()=>setNotice("")}/>
    {error&&<div className="error-message" role="alert">{error}</div>}
    <section className="panel assets-detail-section">
      <div className="panel-header"><h2>Información general</h2></div>
      <div className="assets-detail-grid">
        <Field label="Estado" value={SYSTEM_STATUS_LABELS[system.status]||system.status}/>
        <Field label="Criticidad" value={SYSTEM_CRITICALITY_LABELS[system.criticality]||system.criticality}/>
        <Field label="Descripción / función operacional" value={system.description} wide/>
        <Field label="Justificación de criticidad" value={system.criticality_justification} wide/>
        <Field label="Impacto de indisponibilidad" value={system.impact} wide/>
      </div>
    </section>
    <section className="panel assets-detail-section">
      <div className="panel-header"><h2>Registro y auditoría</h2></div>
      <div className="assets-detail-grid">
        <Field label="Creado por" value={system.created_by}/>
        <Field label="Creado el" value={formatDate(system.created_at)}/>
        <Field label="Última edición por" value={system.updated_by}/>
        <Field label="Actualizado el" value={formatDate(system.updated_at)}/>
        {system.status==="ARCHIVED"&&<>
          <Field label="Archivado por" value={system.archived_by}/>
          <Field label="Archivado el" value={formatDate(system.archived_at)}/>
        </>}
      </div>
    </section>
    {confirm&&<ConfirmSystemStatusModal system={system} busy={busy}
      onCancel={()=>setConfirm(false)} onConfirm={changeStatus}/>}
  </section>;
}
