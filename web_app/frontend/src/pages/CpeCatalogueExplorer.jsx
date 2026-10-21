import { useEffect, useRef, useState } from "react";
import { Link, useLocation, useOutletContext, useParams } from "react-router-dom";
import { getAsset } from "../api/assets";
import {
  getAssetCpeAssociations, getCpeCatalogueSnapshots, browseCpeCatalogue,
  selectCpeCatalogueEvidence,
} from "../api/vulnerabilities";
import CandidateCpeReview from "../components/CandidateCpeReview";
import CpeEvidence from "../components/CpeEvidence";
import CpeReferences from "../components/CpeReferences";
import {
  CATALOGUE_VIEWS, CPE_TYPES, DEFAULT_FILTERS,
  classificationLabel, isReviewableCatalogueRow,
  preferredCatalogueSnapshot, statusLabel, toCatalogueQuery,
} from "../utils/cpeCatalogueExplorer";

const INITIAL_PAGE = [0];
const EMPTY_DATA = {items:[], next_after:null, coverage_complete:false};

export default function CpeCatalogueExplorer() {
  const { assetId } = useParams();
  const { user } = useOutletContext();
  const location = useLocation();
  const overviewQuery = typeof location.state?.cpeOverviewSearch === "string" &&
    location.state.cpeOverviewSearch.startsWith("?")
    ? location.state.cpeOverviewSearch : "";
  const [asset, setAsset] = useState(null);
  const [snapshots, setSnapshots] = useState([]);
  const [snapshotId, setSnapshotId] = useState(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState("");
  const [filters, setFilters] = useState(DEFAULT_FILTERS);
  const [draftFilters, setDraftFilters] = useState(DEFAULT_FILTERS);
  const [cursors, setCursors] = useState(INITIAL_PAGE);
  const [result, setResult] = useState(null);
  const [browsing, setBrowsing] = useState(false);
  const [browseError, setBrowseError] = useState("");
  const [selectionBusy, setSelectionBusy] = useState(false);
  const selectionRef = useRef(null);
  const [selectionError, setSelectionError] = useState("");
  const [selectedRun, setSelectedRun] = useState(null);
  const [associations, setAssociations] = useState([]);
  const [associationError, setAssociationError] = useState("");
  const canReview = ["ADMIN","ANALYST"].includes(user?.role);
  const activeHardware = asset?.asset_type === "HARDWARE" &&
    asset?.inventory_status === "ACTIVE";
  const selectedItem = selectedRun?.candidates?.[0];
  useEffect(() => {
    if (selectedRun) selectionRef.current?.scrollIntoView({behavior:"smooth", block:"start"});
  }, [selectedRun]);
  const selectedAssociation = associations.find(association =>
    association.cpe_name_id?.toLowerCase() === selectedItem?.cpe_name_id?.toLowerCase()
  );

  useEffect(() => {
    let active = true;
    setLoading(true);
    setLoadError("");
    Promise.all([
      getAsset(assetId), getCpeCatalogueSnapshots(assetId),
      getAssetCpeAssociations(assetId),
    ]).then(([hardware, data, linked]) => {
      if (!active) return;
      setAsset(hardware);
      setSnapshots(data.snapshots || []);
      setSnapshotId(preferredCatalogueSnapshot(data.snapshots, hardware.hardware?.manufacturer));
      setAssociations(linked);
    }).catch(err => { if(active) setLoadError(err.message); })
      .finally(() => { if(active) setLoading(false); });
    return () => { active = false; };
  }, [assetId]);

  const cursor = cursors[cursors.length - 1];
  useEffect(() => {
    if (snapshotId == null || !asset) return;
    let active = true;
    setBrowsing(true);
    setBrowseError("");
    browseCpeCatalogue(assetId, snapshotId, toCatalogueQuery(filters, cursor))
      .then(data => { if (active) setResult(data); })
      .catch(err => { if (active) { setResult(null); setBrowseError(err.message); } })
      .finally(() => { if (active) setBrowsing(false); });
    return () => { active = false; };
  }, [assetId, asset, snapshotId, filters, cursor]);

  function changeSnapshot(event) {
    setSnapshotId(Number(event.target.value));
    setCursors(INITIAL_PAGE);
    setResult(null);
    setSelectedRun(null);
    setSelectionError("");
  }
  function submitFilters(event) {
    event.preventDefault();
    setFilters({...draftFilters, q: draftFilters.q.trim()});
    setCursors(INITIAL_PAGE);
    setResult(null);
    setSelectedRun(null);
  }
  function resetFilters() {
    setDraftFilters(DEFAULT_FILTERS);
    setFilters(DEFAULT_FILTERS);
    setCursors(INITIAL_PAGE);
    setResult(null);
    setSelectedRun(null);
  }
  async function selectProduct(item) {
    if (!isReviewableCatalogueRow(item, result?.page?.coverage_complete,
        canReview && activeHardware) || selectionBusy) return;
    setSelectionBusy(true);
    setSelectionError("");
    setSelectedRun(null);
    try {
      const data = await selectCpeCatalogueEvidence(assetId, snapshotId, item.evidence_id);
      setSelectedRun(data.run);
    } catch (err) {
      setSelectionError(err.message);
    } finally {
      setSelectionBusy(false);
    }
  }
  async function refreshAssociations() {
    try {
      setAssociations(await getAssetCpeAssociations(assetId));
      setAssociationError("");
    } catch (err) {
      setAssociationError(err.message);
    }
  }

  if (loading) return <section className="page">Cargando catálogo CPE...</section>;
  if (!asset) return <section className="page">
    <p className="error-message" role="alert">{loadError || "No se pudo abrir el hardware."}</p>
    <Link to="/vulnerabilities/cpe">Volver a Identificación CPE</Link>
  </section>;

  const page = result?.page || EMPTY_DATA;
  const summary = result?.summary;
  const snapshot = snapshots.find(row => row.id === snapshotId);
  return <section className="page cpe-catalogue-explorer">
    <nav className="breadcrumbs" aria-label="Ruta de navegación">
      <span>Vulnerabilidades</span><span>/</span>
      <Link to={"/vulnerabilities/cpe" + overviewQuery}>Identificación CPE</Link>
      <span>/</span>
      <Link to={"/assets/" + assetId + "/cpe"} state={location.state}>{asset.name}</Link>
      <span>/</span><span>Explorador del catálogo</span>
    </nav>
    <Link className="button-secondary assets-back-link"
      to={"/assets/" + assetId + "/cpe"} state={location.state}>
      ← Volver al descubrimiento de candidatos
    </Link>
    <header className="page-header">
      <span className="page-eyebrow">CATÁLOGO NVD COMPARTIDO</span>
      <h1>Explorador de productos CPE</h1>
      <p>{asset.hardware?.manufacturer} · {asset.hardware?.model}
        {asset.hardware?.cpu_model ? " · CPU " + asset.hardware.cpu_model : ""}</p>
    </header>
    <p className="cpe-catalogue-intro">
      Aquí se muestran los productos ya recuperados y guardados en PostgreSQL.
      Explorar y filtrar no consulta NVD. Una sugerencia automática no es una
      asociación confirmada; solamente el analista puede registrarla.
    </p>
    {loadError && <p className="error-message" role="alert">{loadError}</p>}
    <section className="panel cpe-catalogue-controls">
      <h2>Fuente de productos</h2>
      {snapshots.length === 0 ? <p>No hay recuperaciones guardadas. Encola una desde
        el backend con <code>python manage.py enqueue_cpe_catalogue</code> y ejecuta
        <code>python manage.py run_cpe_worker</code>.</p> : <>
        <label htmlFor="catalogue-snapshot">Recuperación de NVD</label>
        <select id="catalogue-snapshot" value={snapshotId ?? ""} onChange={changeSnapshot}>
          {snapshots.map(row => <option key={row.id} value={row.id}>
            #{row.id} · {row.parameter} · {row.stored_products} productos · {statusLabel(row.status)}
          </option>)}
        </select>
        {snapshot && <p className="cpe-catalogue-subtle">
          {snapshot.strategy} · {snapshot.stored_products} productos almacenados
          {snapshot.expected_total != null ? " / " + snapshot.expected_total + " informados por NVD" : ""}
          {" · "}{statusLabel(snapshot.status)}
        </p>}
      </>}
    </section>
    {snapshotId != null && <>
      <section className="panel cpe-catalogue-controls">
        <h2>Filtrar el catálogo</h2>
        <form onSubmit={submitFilters} className="cpe-catalogue-filters">
          <div className="cpe-catalogue-field cpe-catalogue-wide">
            <label htmlFor="catalogue-search">Producto, CPE o UUID</label>
            <input id="catalogue-search" type="search" maxLength={120}
              placeholder="Ej. FL IL 24, 1783, CPU 1215C..."
              value={draftFilters.q}
              onChange={event => setDraftFilters(f => ({...f, q:event.target.value}))}/>
          </div>
          <div className="cpe-catalogue-field">
            <label htmlFor="catalogue-view">Mostrar</label>
            <select id="catalogue-view" value={draftFilters.view}
              onChange={event => setDraftFilters(f => ({...f, view:event.target.value}))}>
              {CATALOGUE_VIEWS.map(x=><option key={x.value} value={x.value}>{x.label}</option>)}
            </select>
          </div>
          <div className="cpe-catalogue-field">
            <label htmlFor="catalogue-type">Tipo CPE</label>
            <select id="catalogue-type" value={draftFilters.cpe_type}
              onChange={event => setDraftFilters(f => ({...f, cpe_type:event.target.value}))}>
              {CPE_TYPES.map(x=><option key={x.value} value={x.value}>{x.label}</option>)}
            </select>
          </div>
          <div className="cpe-catalogue-field">
            <label htmlFor="catalogue-deprecated">Estado NVD</label>
            <select id="catalogue-deprecated" value={draftFilters.deprecated}
              onChange={event => setDraftFilters(f => ({...f, deprecated:event.target.value}))}>
              <option value="ALL">Todos</option><option value="NO">No deprecados</option>
              <option value="YES">Deprecados</option>
            </select>
          </div>
          <div className="cpe-catalogue-actions">
            <button className="button-primary" type="submit" disabled={browsing}>Aplicar filtros</button>
            <button className="button-secondary" type="button" onClick={resetFilters}
              disabled={browsing}>Limpiar</button>
          </div>
        </form>
      </section>
      {browseError && <p className="error-message" role="alert">{browseError}</p>}
      {!browsing && summary && <section className="cpe-catalogue-stats" aria-label="Resumen de productos almacenados">
        <div><strong>{summary.examined}</strong><span>Almacenados en recuperación</span></div>
        <div><strong>{summary.candidate_count}</strong><span>Candidatos sugeridos</span></div>
        <div><strong>{summary.excluded_count}</strong><span>Productos no sugeridos</span></div>
        <div><strong>{summary.pertinent_count}</strong><span>Coincidencias técnicas suficientes</span></div>
      </section>}
      {!browsing && !page.coverage_complete && <p className="cpe-warning" role="status">
        Recuperación incompleta o fallida. Solo se presentan los registros guardados.
        No puedes concluir que un CPE no existe ni seleccionar evidencia para validación.
      </p>}
      {browsing ? <div className="panel cpe-copy">Consultando productos almacenados...</div>
        : <section className="panel cpe-catalogue-results">
          <div className="panel-header">
            <h2>Productos recuperados</h2>
            <span className="record-count">{page.items.length} en esta página</span>
          </div>
          {page.items.length === 0 ? <p className="cpe-copy">
            Ningún producto almacenado coincide con estos filtros. Si la recuperación
            está incompleta, aún podrían existir productos sin recuperar.
          </p> : <div className="cpe-catalogue-product-list">
            {page.items.map(item => <article key={item.evidence_id} className="cpe-catalogue-product">
              <div className="cpe-catalogue-product-heading">
                <h3>{item.title}</h3>
                <span className="cpe-catalogue-classification" data-classification={item.classification}>
                  {classificationLabel(item.classification)}
                </span>
              </div>
              <p className="cpe-catalogue-subtle">
                {item.cpe_type === "h" ? "Hardware" :
                 item.cpe_type === "o" ? "Sistema operativo" :
                 item.cpe_type === "a" ? "Aplicación" : "Tipo " + item.cpe_type}
                {" · "}{item.deprecated ? "Deprecado en NVD" : "No deprecado"}
                {" · "}Evidencia #{item.evidence_id}
              </p>
              <details className="cpe-catalogue-evidence">
                <summary>Identificador oficial, coincidencia y referencias</summary>
                <CpeEvidence cpeName={item.cpe_name} cpeNameId={item.cpe_name_id}/>
                <p>{item.match_reason}</p>
                <p className="cpe-catalogue-subtle">
                  Clasificación: {item.match_level || "No disponible"} ·
                  {" "}{item.source_strategy}
                </p>
                <CpeReferences references={item.nvd_references} />
              </details>
              {item.classification !== "CANDIDATE" && item.cpe_type === "h" &&
                <p className="cpe-catalogue-caution">
                  Este producto no cumple las reglas de sugerencia automática.
                  Si decides revisarlo, contrasta su identidad técnica antes de asociarlo.
                </p>}
              {canReview && activeHardware && item.cpe_type === "h" && <>
                <button type="button" className="button-secondary"
                  disabled={!isReviewableCatalogueRow(item, page.coverage_complete, canReview) || selectionBusy}
                  onClick={() => selectProduct(item)}>
                  {selectionBusy ? "Preparando..." : "Seleccionar para revisión"}
                </button>
              </>}
            </article>)}
          </div>}
          <div className="pagination-footer cpe-catalogue-pagination">
            <span>Página {cursors.length} · {page.items.length} resultados de esta página</span>
            <div className="pagination-actions">
              <button type="button" disabled={cursors.length < 2 || browsing}
                onClick={() => {setCursors(curr=>curr.slice(0,-1));setSelectedRun(null);}}>
                Anterior</button>
              <button type="button" disabled={page.next_after == null || browsing}
                onClick={() => {setCursors(curr=>[...curr,page.next_after]);setSelectedRun(null);}}>
                Siguiente</button>
            </div>
          </div>
        </section>}
      {selectionError && <p className="error-message" role="alert">{selectionError}</p>}
      {associationError && <p className="error-message" role="alert">{associationError}</p>}
      {selectedRun && selectedItem && <section ref={selectionRef} className="panel cpe-catalogue-selection"
        aria-label="Revisión de evidencia seleccionada">
        <div className="panel-header">
          <h2>Revisión del CPE seleccionado</h2>
          <button type="button" className="button-secondary" onClick={() => setSelectedRun(null)}>
            Cerrar</button>
        </div>
        <p>La evidencia #{selectedItem.source_evidence_id} del snapshot
          #{selectedItem.source_snapshot_id} quedó vinculada a la búsqueda
          #{selectedRun.id}. La decisión sigue pendiente hasta que la confirmes o rechaces.</p>
        <h3>{selectedItem.title}</h3>
        <CpeEvidence cpeName={selectedItem.cpe_name} cpeNameId={selectedItem.cpe_name_id}/>
        <CpeReferences references={selectedItem.nvd_references}/>
        <p>{selectedItem.match_reason}</p>
        {selectedAssociation && <p className="cpe-catalogue-subtle">
          Decisión existente: {selectedAssociation.validation_status}.
          Puedes cambiarla o revalidarla sin eliminar su historial.
        </p>}
        <CandidateCpeReview key={selectedRun.id + "-" + selectedItem.cpe_name_id}
          candidate={selectedItem} assetId={assetId} run={selectedRun}
          association={selectedAssociation} allowed={canReview && activeHardware}
          onReviewed={refreshAssociations}/>
      </section>}
      <p className="cpe-catalogue-subtle">
        El catálogo contiene los registros oficiales recuperados, no decisiones.
        Las asociaciones solo se registran mediante revisión explícita y quedan auditadas.
      </p>
    </>}
  </section>;
}
