import { useEffect, useMemo, useState } from "react";
import { Link, useLocation, useOutletContext, useSearchParams } from "react-router-dom";
import { getSystems } from "../api/systems";
import { navigationFromLocation } from "../utils/returnNavigation";
import { readPage, updateListParams } from "../utils/listUrlState";
import { canManageSystems, filterSystems,
  SYSTEM_STATUS_LABELS, SYSTEM_CRITICALITY_LABELS } from "../utils/systemUi";

const PAGE_SIZE = 15;

export default function Systems() {
  const {user}=useOutletContext();
  const location=useLocation();
  const ctx=navigationFromLocation(location);
  const [params,setParams]=useSearchParams();
  const status=["ACTIVE","ARCHIVED","ALL"].includes(params.get("status"))?params.get("status"):"ACTIVE";
  const criticality=Object.hasOwn(SYSTEM_CRITICALITY_LABELS,params.get("criticality"))
    ?params.get("criticality"):"ALL";
  const search=params.get("q")||"";
  const [rows,setRows]=useState([]);
  const [loading,setLoading]=useState(true);
  const [error,setError]=useState("");
  function change(name,value,defaultValue="") {
    setParams(updateListParams(params,name,value,{defaultValue}),{replace:name==="q"});
  }
  useEffect(()=>{
    let active=true;
    setLoading(true);setError("");
    getSystems(status).then(data=>{if(active)setRows(data);})
      .catch(e=>{if(active)setError(e.message);})
      .finally(()=>{if(active)setLoading(false);});
    return ()=>{active=false;};
  },[status]);
  const filtered=useMemo(()=>filterSystems(rows,{search,criticality}),[rows,search,criticality]);
  const pages=Math.max(1,Math.ceil(filtered.length/PAGE_SIZE));
  const page=Math.min(readPage(params.get("page")),pages);
  const visible=filtered.slice((page-1)*PAGE_SIZE,page*PAGE_SIZE);

  return <section className="page">
    <header className="page-header assets-page-heading">
      <div><span className="page-eyebrow">ACTIVOS</span>
        <h1>Sistemas OT</h1>
        <p>Registro y contextualización de sistemas operacionales.</p>
      </div>
      {canManageSystems(user) &&
        <Link className="button-primary assets-primary-link" to="/assets/systems/new"
          state={ctx}>Registrar sistema</Link>}
    </header>
    {error&&<div className="error-message" role="alert">{error}</div>}
    <div className="panel">
      <div className="panel-header">
        <div><h2>Sistemas registrados</h2>
          <p>Consulta sistemas operacionales y su valoración registrada.</p>
        </div>
        <span className="record-count">{rows.length} registros en esta vista</span>
      </div>
      <div className="table-toolbar assets-toolbar">
        <div className="search-box">
          <input type="search" aria-label="Buscar sistemas"
            placeholder="Buscar nombre o descripción..."
            value={search} onChange={e=>change("q",e.target.value)}/>
        </div>
        <select className="table-filter-select" aria-label="Filtrar criticidad"
          value={criticality} onChange={e=>change("criticality",e.target.value,"ALL")}>
          <option value="ALL">Todas las criticidades</option>
          {Object.entries(SYSTEM_CRITICALITY_LABELS).map(([id,label])=>
            <option key={id} value={id}>{label}</option>)}
        </select>
        <select className="table-filter-select" aria-label="Filtrar estado de sistemas"
          value={status} onChange={e=>change("status",e.target.value,"ACTIVE")}>
          <option value="ACTIVE">Activos</option><option value="ARCHIVED">Archivados</option>
          <option value="ALL">Todos los estados</option>
        </select>
        <span className="filtered-count">{filtered.length} resultados</span>
      </div>
      {loading?<div className="empty-state">Cargando sistemas...</div>:
        !error&&filtered.length===0?<div className="empty-state">
          <strong>No se encontraron sistemas.</strong>
          <p>{rows.length===0?"Todavía no hay sistemas en esta vista.":"Prueba otros filtros."}</p>
        </div>:!error&&<div className="table-container">
          <table className="data-table">
            <thead><tr><th>Sistema</th><th>Criticidad</th><th>Estado</th><th>Acciones</th></tr></thead>
            <tbody>{visible.map(item=><tr key={item.id}>
              <td><strong>{item.name}</strong><small className="interface-hint">Sistema #{item.id}</small></td>
              <td>{SYSTEM_CRITICALITY_LABELS[item.criticality]||item.criticality}</td>
              <td>{SYSTEM_STATUS_LABELS[item.status]||item.status}</td>
              <td><div className="table-actions">
                <Link className="button-secondary" to={"/assets/systems/"+item.id} state={ctx}>Ver</Link>
                {canManageSystems(user)&&item.status==="ACTIVE"&&
                  <Link className="button-secondary" to={"/assets/systems/"+item.id+"/edit"} state={ctx}>Editar</Link>}
              </div></td>
            </tr>)}</tbody>
          </table>
        </div>}
      {!loading&&!error&&<div className="pagination">
        <span>Página {page} de {pages}</span>
        <div className="pagination-actions">
          <button type="button" disabled={page<=1} onClick={()=>change("page",page-1,"1")}>Anterior</button>
          <button type="button" disabled={page>=pages} onClick={()=>change("page",page+1,"1")}>Siguiente</button>
        </div>
      </div>}
    </div>
  </section>;
}
