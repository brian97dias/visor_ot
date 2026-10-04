import {
    useEffect,
    useState,
} from "react";

import {
    Link,
    useParams,
} from "react-router-dom";

import {
    getIngestion,
} from "../api/ingestion";

import {
    CommunicationModal,
    CommunicationsTable,
    InterfacesTable,
} from "./AnalysisDetail";


function IngestionDetail() {

    const { ingestionId } =
        useParams();

    const navigate =
        useNavigate();


    const [
        ingestion,
        setIngestion,
    ] = useState(null);

    const [
        activeTab,
        setActiveTab,
    ] = useState("interfaces");

    const [
        selectedCommunication,
        setSelectedCommunication,
    ] = useState(null);

    const [
        loading,
        setLoading,
    ] = useState(true);

    const [
        error,
        setError,
    ] = useState("");


    useEffect(() => {

        async function loadIngestion() {

            try {

                const data =
                    await getIngestion(
                        ingestionId
                    );

                setIngestion(
                    data
                );


            } catch (error) {

                setError(
                    error.message
                );


            } finally {

                setLoading(false);

            }

        }


        loadIngestion();

    }, [ingestionId]);


    if (loading) {

        return (
            <section className="page">
                <p>
                    Cargando importación...
                </p>
            </section>
        );

    }


    if (error) {

        return (
            <section className="page">

                <div className="error-message">
                    {error}
                </div>

                <button
                    className="button-secondary"
                    onClick={() =>
                        navigate(
                            "/passive-analysis?tab=observations"
                        )
                    }
                >
                    Volver
                </button>

            </section>
        );

    }


    return (
        <section className="page">

            <div className="breadcrumbs">

                <span>
                    Red
                </span>

                <span>/</span>


                <Link
                    to="/passive-analysis"
                >
                    Análisis pasivo
                </Link>

                <span>/</span>


                <Link
                    to="/passive-analysis?tab=observations"
                >
                    Observaciones importadas
                </Link>

                <span>/</span>


                <span>
                    #{ingestion.id}
                </span>

            </div>


            <header className="analysis-detail-header">

                <div>

                    <div className="analysis-title-row">

                        <h1>
                            {
                                ingestion.filename
                            }
                        </h1>


                        <span
                            className={
                                ingestion.status === "ACTIVE"
                                    ? "status status-analyzed"
                                    : "status status-excluded"
                            }
                        >
                            {
                                ingestion.status === "ACTIVE"
                                    ? "Activa"
                                    : "Excluida"
                            }
                        </span>

                    </div>


                    <p>
                        Observaciones persistidas
                        en Visual OT.
                    </p>

                </div>

            </header>


            <div className="analysis-metadata">

                <div>
                    <span>
                        Ruta
                    </span>

                    <strong>
                        {
                            ingestion.relative_path
                        }
                    </strong>
                </div>


                <div>
                    <span>
                        PCAP ID
                    </span>

                    <strong>
                        {
                            ingestion.pcap_id
                        }
                    </strong>
                </div>


                <div>
                    <span>
                        Schema
                    </span>

                    <strong>
                        {
                            ingestion.schema_version
                        }
                    </strong>
                </div>


                <div>
                    <span>
                        Importado
                    </span>

                    <strong>
                        {
                            new Date(
                                ingestion.imported_at
                            )
                            .toLocaleString(
                                "es-CO"
                            )
                        }
                    </strong>
                </div>


                <div>
                    <span>
                        Usuario
                    </span>

                    <strong>
                        {
                            ingestion.imported_by
                        }
                    </strong>
                </div>


                <div>
                    <span>
                        Estado
                    </span>

                    <strong>
                        {
                            ingestion.status === "ACTIVE"
                                ? "Activa"
                                : "Excluida"
                        }
                    </strong>
                </div>

            </div>


            <div className="analysis-summary">

                <div className="summary-card">

                    <span>
                        Interfaces
                    </span>

                    <strong>
                        {
                            ingestion.interfaces.length
                        }
                    </strong>

                </div>


                <div className="summary-card">

                    <span>
                        Comunicaciones
                    </span>

                    <strong>
                        {
                            ingestion.communications.length
                        }
                    </strong>

                </div>

            </div>


            <div className="analysis-tabs">

                <button
                    className={
                        activeTab === "interfaces"
                            ? "analysis-tab active"
                            : "analysis-tab"
                    }
                    onClick={() =>
                        setActiveTab(
                            "interfaces"
                        )
                    }
                >
                    Interfaces
                </button>


                <button
                    className={
                        activeTab === "communications"
                            ? "analysis-tab active"
                            : "analysis-tab"
                    }
                    onClick={() =>
                        setActiveTab(
                            "communications"
                        )
                    }
                >
                    Comunicaciones
                </button>

            </div>


            {
                activeTab === "interfaces"
                && (
                    <InterfacesTable
                        interfaces={
                            ingestion.interfaces
                        }
                    />
                )
            }


            {
                activeTab === "communications"
                && (
                    <CommunicationsTable
                        communications={
                            ingestion.communications
                        }
                        onSelect={
                            setSelectedCommunication
                        }
                    />
                )
            }


            {
                selectedCommunication
                && (
                    <CommunicationModal
                        communication={
                            selectedCommunication
                        }
                        onClose={() =>
                            setSelectedCommunication(
                                null
                            )
                        }
                    />
                )
            }

        </section>
    );
}


export default IngestionDetail;