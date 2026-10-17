import { useEffect, useState } from "react";
import { Link, useLocation, useOutletContext, useSearchParams } from "react-router-dom";

import { createInterface, getInterfaces } from "../api/interfaces";
import { canCreateAssets } from "../utils/assetPermissions";
import SuccessNotice from "../components/SuccessNotice";
import { readPage, updateListParams } from "../utils/listUrlState";
import { navigationFromLocation } from "../utils/returnNavigation";

export default function Interfaces() {
  const { user } = useOutletContext();
  const canManage = canCreateAssets(user);
  const location = useLocation();
  const [params, setParams] = useSearchParams();
  const navigationState = navigationFromLocation(location);
  const query = params.get("q") || "";
  const [search,setSearch] = useState(() => query.trim());
  const matchMode = params.get("match") === "EXACT_IP" ? "EXACT_IP" : "PARTIAL";
  const identification = ["IDENTIFIED","UNIDENTIFIED"].includes(params.get("identification"))
    ? params.get("identification") : "ALL";
  const evidence = ["ALL","NO_ACTIVE"].includes(params.get("evidence")) ? params.get("evidence") : "ACTIVE";
  const page = readPage(params.get("page"));
  function changeFilter(name,value,defaultValue="") {
    setParams(updateListParams(params,name,value,{defaultValue}),{replace:name==="q"});
  }
  const [response, setResponse] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [showForm, setShowForm] = useState(false);
  const [mac, setMac] = useState("");
  const [declaredIp, setDeclaredIp] = useState("");
  const [saving, setSaving] = useState(false);
  const [revision, setRevision] = useState(0);

  useEffect(() => {
    const handle = setTimeout(() => setSearch(query.trim()), 350);
    return () => clearTimeout(handle);
  }, [query]);


  useEffect(() => {
    let active = true;
    setLoading(true);
    setError("");
    getInterfaces({ page, search, matchMode, identification, evidence })
      .then((data) => { if (active) setResponse(data); })
      .catch((err) => { if (active) setError(err.message); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [page, search, matchMode, identification, evidence, revision]);

  async function register(event) {
    event.preventDefault();
    if (!mac.trim() && !declaredIp.trim()) {
      setError("Indica al menos una MAC o IP.");
      return;
    }
    setSaving(true);
    setError("");
    setNotice("");
    try {
      const result = await createInterface({
        mac: mac.trim() || null, declared_ip: declaredIp.trim() || null,
      });
      setNotice("Interfaz #" + result.id + " registrada correctamente.");
      // A manual interface has no PCAP evidence yet and is intentionally
      // excluded from the default ACTIVE filter. Make the new record visible.
      const identity = result.mac || result.declared_ip;
      const next = new URLSearchParams(params);
      next.set("evidence","ALL");
      next.delete("match");
      next.delete("identification");
      next.set("q",identity);
      next.delete("page");
      setParams(next);
      setSearch(identity.trim());
      setShowForm(false);
      setMac("");
      setDeclaredIp("");
      setRevision((value) => value + 1);
    } catch (err) {
      setError(err.message);
    } finally {
      setSaving(false);
    }
  }

  const records = response?.results || [];
  const summary = response?.summary || {};
  const count = response?.count || 0;
  const shownPage = response?.page || 1;
  const pages = Math.max(1, Math.ceil(count / (response?.page_size || 25)));

  return (
    <section className="page">
      <header className="page-header assets-page-heading">
        <div>
          <span className="page-eyebrow">ACTIVOS</span>
          <h1>Interfaces</h1>
          <p>Inventario consolidado de interfaces de red observadas y declaradas.</p>
        </div>
        {canManage && <button className="button-primary" type="button"
          onClick={() => setShowForm((current) => !current)}>
          {showForm ? "Cerrar registro" : "Registrar interfaz"}
        </button>}
      </header>

      <SuccessNotice message={notice} onClose={() => setNotice("")} />
      {error && <div className="error-message">{error}</div>}

      {canManage && showForm && (
        <form className="panel interface-register-form" onSubmit={register}>
          <h2>Registrar interfaz manualmente</h2>
          <p className="interface-hint">MAC y/o IP declarada. No se asignará hardware automáticamente.</p>
          <div className="interface-form-fields">
            <label>MAC
              <input value={mac} maxLength={17} disabled={saving}
                placeholder="00:11:22:33:44:55"
                onChange={(event) => setMac(event.target.value)} />
            </label>
            <label>IP declarada
              <input value={declaredIp} disabled={saving}
                placeholder="192.168.88.15"
                onChange={(event) => setDeclaredIp(event.target.value)} />
            </label>
          </div>
          <div className="table-actions">
            <button type="button" className="button-secondary" disabled={saving}
              onClick={() => setShowForm(false)}>Cancelar</button>
            <button className="button-primary" type="submit" disabled={saving}>
              {saving ? "Registrando..." : "Guardar interfaz"}
            </button>
          </div>
        </form>
      )}

      <div className="interface-stat-grid">
        <div className="interface-stat"><span>Total</span><strong>{summary.total ?? "—"}</strong></div>
        <div className="interface-stat"><span>Identificadas</span><strong>{summary.identified ?? "—"}</strong></div>
        <div className="interface-stat"><span>Sin identificar</span><strong>{summary.unidentified ?? "—"}</strong></div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <div><h2>Interfaces registradas</h2><p>MAC, IP conocidas y su relación con hardware.</p></div>
          <span className="record-count">{count} coincidencias</span>
        </div>
        <div className="table-toolbar">
          <div className="search-box">
            <input type="search" value={query}
              aria-label="Buscar MAC o IP"
              placeholder={matchMode === "EXACT_IP" ? "Escribe la IP completa..." : "Buscar MAC o IP..."}
              onChange={(event) => changeFilter("q",event.target.value)} />
          </div>
          <select className="table-filter-select"
            value={matchMode} aria-label="Tipo de coincidencia de interfaces"
            onChange={(event) => changeFilter("match",event.target.value,"PARTIAL")}>
            <option value="PARTIAL">Coincidencia parcial</option>
            <option value="EXACT_IP">IP exacta</option>
          </select>
          <select className="table-filter-select" value={identification}
            aria-label="Estado de identificación" onChange={(event) => changeFilter("identification",event.target.value,"ALL")}>
            <option value="ALL">Todas las identificaciones</option>
            <option value="IDENTIFIED">Identificadas</option>
            <option value="UNIDENTIFIED">Sin identificar</option>
          </select>
          <select className="table-filter-select" value={evidence}
            aria-label="Estado de evidencia" onChange={(event) => changeFilter("evidence",event.target.value,"ACTIVE")}>
            <option value="ALL">Toda la evidencia</option>
            <option value="ACTIVE">Evidencia activa</option>
            <option value="NO_ACTIVE">Sin evidencia activa</option>
          </select>
        </div>

        {loading ? <div className="empty-state">Cargando interfaces...</div> :
          !error && records.length === 0 ? (
            <div className="empty-state">No se encontraron interfaces con estos filtros.</div>
          ) : !error && (
            <div className="table-container">
              <table className="data-table">
                <thead><tr><th>MAC</th><th>IP conocida</th><th>Activo relacionado</th><th>Identificación</th><th>Evidencia</th><th>Acciones</th></tr></thead>
                <tbody>{records.map((item) => (
                  <tr key={item.id}>
                    <td className="mono-value">{item.mac || "Sin MAC"}</td>
                    <td>{[...new Set([...(item.observed_ips || []),
                      item.declared_ip].filter(Boolean))].join(", ") || "Sin IP"}
                      {item.declared_ip && <small className="interface-hint"> IP declarada</small>}
                    </td>
                    <td>{item.hardware?.asset_name || "Sin asociar"}
                      {item.hardware && <small className="interface-hint">{item.hardware.role}</small>}
                    </td>
                    <td>{item.is_identified ? "Identificada" : "No identificada"}</td>
                    <td>{item.has_active_evidence ? "Activa" : "Solo histórica / ninguna"}</td>
                    <td><Link className="button-secondary" to={"/assets/interfaces/" + item.id} state={navigationState}>Ver detalle</Link></td>
                  </tr>
                ))}</tbody>
              </table>
            </div>
          )}
        <div className="pagination">
          <span>Página {shownPage} de {pages}</span>
          <div className="pagination-actions">
            <button type="button" disabled={loading || shownPage <= 1}
              onClick={() => changeFilter("page",shownPage-1,"1")}>Anterior</button>
            <button type="button" disabled={loading || shownPage >= pages}
              onClick={() => changeFilter("page",shownPage+1,"1")}>Siguiente</button>
          </div>
        </div>
      </div>
    </section>
  );
}
