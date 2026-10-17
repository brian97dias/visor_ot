import { useEffect, useState } from "react";
import { Link, useLocation, useNavigate, useParams } from "react-router-dom";

import { getIngestion } from "../api/ingestion";
import { getBackNavigation } from "../utils/returnNavigation";
import ObservationBrowser from "../components/ObservationBrowser";
import CommunicationObservationModal from "../components/CommunicationObservationModal";

export default function IngestionDetail() {
  const { ingestionId } = useParams();
  const navigate = useNavigate();
  const location = useLocation();
  const back = getBackNavigation(location, "/passive-analysis?tab=observations");
  const [ingestion, setIngestion] = useState(null);
  const [activeTab, setActiveTab] = useState("interfaces");
  const [selectedCommunication, setSelectedCommunication] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    getIngestion(ingestionId)
      .then((data) => { if (active) setIngestion(data); })
      .catch((err) => { if (active) setError(err.message); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [ingestionId]);

  if (loading) return <section className="page"><p>Cargando importación...</p></section>;
  if (error || !ingestion) {
    return (
      <section className="page">
        <div className="error-message">{error || "Importación no disponible."}</div>
        <button className="button-secondary"
          onClick={() => navigate(back.to,{state:back.state})}>Volver</button>
      </section>
    );
  }

  return (
    <section className="page">
      <div className="breadcrumbs">
        <span>Red</span><span>/</span>
        <Link to="/passive-analysis">Análisis pasivo</Link><span>/</span>
        <Link to="/passive-analysis?tab=observations">Observaciones importadas</Link>
        <span>/</span><span>#{ingestion.id}</span>
      </div>

      <Link className="button-secondary assets-back-link" to={back.to} state={back.state}>← Volver</Link>
      <header className="analysis-detail-header">
        <div className="analysis-title-row">
          <h1>{ingestion.filename}</h1>
          <span className={ingestion.status === "ACTIVE"
            ? "status status-analyzed" : "status status-excluded"}>
            {ingestion.status === "ACTIVE" ? "Activa" : "Excluida"}
          </span>
        </div>
        <p>Observaciones persistidas en Visor OT.</p>
      </header>

      <div className="analysis-metadata">
        <div><span>Ruta</span><strong>{ingestion.relative_path}</strong></div>
        <div><span>PCAP ID</span><strong>{ingestion.pcap_id}</strong></div>
        <div><span>Schema</span><strong>{ingestion.schema_version}</strong></div>
        <div><span>Importado</span><strong>{new Date(ingestion.imported_at).toLocaleString("es-CO")}</strong></div>
        <div><span>Usuario</span><strong>{ingestion.imported_by}</strong></div>
        <div><span>Estado</span><strong>{ingestion.status === "ACTIVE" ? "Activa" : "Excluida"}</strong></div>
      </div>

      <div className="analysis-summary">
        <div className="summary-card"><span>Interfaces</span>
          <strong>{ingestion.interfaces_detected.toLocaleString("es-CO")}</strong>
        </div>
        <div className="summary-card"><span>Comunicaciones</span>
          <strong>{ingestion.communications_detected.toLocaleString("es-CO")}</strong>
        </div>
      </div>

      <div className="analysis-tabs">
        <button className={activeTab === "interfaces" ? "analysis-tab active" : "analysis-tab"}
          onClick={() => setActiveTab("interfaces")}>Interfaces</button>
        <button className={activeTab === "communications" ? "analysis-tab active" : "analysis-tab"}
          onClick={() => setActiveTab("communications")}>Comunicaciones</button>
      </div>

      <ObservationBrowser source="ingestion" id={ingestionId} kind={activeTab}
        onSelect={setSelectedCommunication} />

      <CommunicationObservationModal communication={selectedCommunication}
        onClose={() => setSelectedCommunication(null)} />
    </section>
  );
}
