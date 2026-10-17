import { useState } from "react";
import { Link, useLocation, useNavigate, useParams } from "react-router-dom";
import { getBackNavigation } from "../utils/returnNavigation";

import ObservationBrowser from "../components/ObservationBrowser";
import CommunicationObservationModal from "../components/CommunicationObservationModal";

export default function AnalysisDetail() {
  const { pcapId } = useParams();
  const navigate = useNavigate();
  const location = useLocation();
  const back = getBackNavigation(location, "/passive-analysis");
  const [overview, setOverview] = useState(null);
  const [activeTab, setActiveTab] = useState("interfaces");
  const [selectedCommunication, setSelectedCommunication] = useState(null);

  return (
    <section className="page">
      <div className="breadcrumbs">
        <button onClick={() => navigate(back.to,{state:back.state})}>
          Red / Análisis pasivo
        </button>
        <span>/</span>
        <span>{overview?.capture?.filename || pcapId}</span>
      </div>

      <Link className="button-secondary assets-back-link" to={back.to} state={back.state}>← Volver</Link>
      <header className="analysis-detail-header">
        <div className="analysis-title-row">
          <h1>{overview?.capture?.filename || "Cargando análisis..."}</h1>
          <span className="status status-analyzed">Analizado</span>
        </div>
        <p>Resultado generado por el Passive Analyzer.</p>
      </header>

      <div className="analysis-metadata">
        <div><span>Ruta</span><strong>{overview?.capture?.relative_path || "Cargando..."}</strong></div>
        <div><span>PCAP ID</span><strong>{pcapId}</strong></div>
        <div><span>Schema</span><strong>{overview?.schema_version || "Cargando..."}</strong></div>
      </div>

      <div className="analysis-summary">
        <div className="summary-card"><span>Interfaces</span>
          <strong>{overview ? overview.interfaces_detected.toLocaleString("es-CO") : "..."}</strong></div>
        <div className="summary-card"><span>Comunicaciones</span>
          <strong>{overview ? overview.communications_detected.toLocaleString("es-CO") : "..."}</strong></div>
      </div>

      <div className="analysis-tabs">
        <button className={activeTab === "interfaces" ? "analysis-tab active" : "analysis-tab"}
          onClick={() => setActiveTab("interfaces")}>Interfaces</button>
        <button className={activeTab === "communications" ? "analysis-tab active" : "analysis-tab"}
          onClick={() => setActiveTab("communications")}>Comunicaciones</button>
      </div>

      <ObservationBrowser source="analysis" id={pcapId} kind={activeTab}
        onSelect={setSelectedCommunication} onMetadata={setOverview} />

      <CommunicationObservationModal communication={selectedCommunication}
        onClose={() => setSelectedCommunication(null)} />
    </section>
  );
}
