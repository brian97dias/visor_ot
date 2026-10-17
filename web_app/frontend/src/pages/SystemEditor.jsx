import { useEffect, useState } from "react";
import { Link, useLocation, useNavigate, useOutletContext, useParams } from "react-router-dom";

import { createSystem, getSystem, updateSystem } from "../api/systems";
import SystemForm from "../components/SystemForm";
import { canManageSystems } from "../utils/systemUi";
import { getBackNavigation } from "../utils/returnNavigation";

/** Respect inventory->detail->editor and list->editor entry paths. */
function savedDetailContext(location,id) {
  const back=getBackNavigation(location,"/assets/systems/"+id);
  return back.to.split(/[?#]/)[0]==="/assets/systems/"+id
    ? back.state||{returnTo:"/assets/systems"}
    : {returnTo:back.to,returnState:back.state};
}

export default function SystemEditor() {
  const {systemId}=useParams();
  const editing=Boolean(systemId);
  const {user}=useOutletContext();
  const location=useLocation();
  const navigate=useNavigate();
  const allowed=canManageSystems(user);
  const back=getBackNavigation(location, editing?"/assets/systems/"+systemId:"/assets/systems");
  const [system,setSystem]=useState(null);
  const [loading,setLoading]=useState(editing);
  const [saving,setSaving]=useState(false);
  const [dirty,setDirty]=useState(false);
  const [error,setError]=useState("");

  useEffect(()=>{
    if (!editing || !allowed) return;
    let active=true;
    setLoading(true);setError("");
    getSystem(systemId).then(data=>{if(active)setSystem(data);})
      .catch(e=>{if(active)setError(e.message);})
      .finally(()=>{if(active)setLoading(false);});
    return ()=>{active=false;};
  },[editing,systemId,allowed]);

  useEffect(()=>{
    const handler=e=>{if(dirty){e.preventDefault();e.returnValue="";}};
    window.addEventListener("beforeunload",handler);
    return ()=>window.removeEventListener("beforeunload",handler);
  },[dirty]);

  function confirmBack(event) {
    if(saving||(dirty&&!window.confirm("Tienes cambios sin guardar. ¿Deseas descartarlos?")))
      event.preventDefault();
  }
  async function save(values) {
    setSaving(true);setError("");
    try {
      const result=editing?await updateSystem(systemId,values):await createSystem(values);
      const context=editing?savedDetailContext(location,result.id)
        :{returnTo:back.to,returnState:back.state};
      navigate("/assets/systems/"+result.id,{
        replace:true,state:{...context,notice:editing?
          "Sistema actualizado correctamente.":"Sistema registrado correctamente."},
      });
    } catch(e) {setError(e.message);}
    finally {setSaving(false);}
  }

  if(!allowed)return <section className="page">
    <div className="error-message">No tienes permisos para administrar sistemas OT.</div>
    <Link to={back.to} state={back.state}>Volver</Link>
  </section>;
  if(editing&&(loading||!system))return <section className="page">
    {loading?"Cargando sistema...":<div className="error-message">{error||"Sistema no encontrado."}</div>}
    {!loading&&<Link to={back.to} state={back.state}>Volver</Link>}
  </section>;
  if(editing&&system.status==="ARCHIVED")return <section className="page">
    <div className="error-message">El sistema está archivado. Restáuralo antes de editarlo.</div>
    <Link to={"/assets/systems/"+systemId} state={savedDetailContext(location,systemId)}>Ver sistema</Link>
  </section>;

  return <section className="page">
    <div className="breadcrumbs">
      <span>Activos</span><span>/</span><Link to="/assets/systems">Sistemas</Link>
      <span>/</span><span>{editing?"Editar sistema":"Nuevo sistema"}</span>
    </div>
    <Link className="button-secondary assets-back-link" to={back.to} state={back.state}
      onClick={confirmBack}>← Volver</Link>
    <header className="page-header">
      <span className="page-eyebrow">SISTEMAS OT</span>
      <h1>{editing?"Editar sistema":"Nuevo sistema"}</h1>
      <p>{editing?"Actualiza los datos operacionales del sistema.":
        "Registra un sistema OT, aunque todavía no tenga hardware asociado."}</p>
    </header>
    <SystemForm key={editing?systemId:"new"} system={editing?system:null}
      saving={saving} error={error} onSave={save}
      onDirtyChange={setDirty} back={back}/>
  </section>;
}
