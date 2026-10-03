import {
    useEffect,
    useState,
} from "react";

import {
    useNavigate,
    useParams,
} from "react-router-dom";

import {
    getPcapAnalysis,
} from "../api/ingestion";


function AnalysisDetail() {

    const { pcapId } =
        useParams();

    const navigate =
        useNavigate();


    const [analysis, setAnalysis] =
        useState(null);

    const [activeTab, setActiveTab] =
        useState("interfaces");

    const [
        selectedCommunication,
        setSelectedCommunication,
    ] = useState(null);

    const [loading, setLoading] =
        useState(true);

    const [error, setError] =
        useState("");


    useEffect(() => {

        async function loadAnalysis() {

            try {

                const data =
                    await getPcapAnalysis(
                        pcapId
                    );

                setAnalysis(
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


        loadAnalysis();

    }, [pcapId]);


    if (loading) {

        return (
            <section className="page">
                <p>
                    Cargando análisis...
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
                            "/passive-analysis"
                        )
                    }
                >
                    Volver
                </button>

            </section>
        );

    }


    const {
        capture,
        interfaces,
        communications,
        schema_version,
    } = analysis;


    return (
        <section className="page">

            <div className="breadcrumbs">

                <button
                    onClick={() =>
                        navigate(
                            "/passive-analysis"
                        )
                    }
                >
                    Red / Análisis pasivo
                </button>

                <span>/</span>

                <span>
                    {capture.filename}
                </span>

            </div>


            <header className="analysis-detail-header">

                <div>

                    <div className="analysis-title-row">

                        <h1>
                            {capture.filename}
                        </h1>

                        <span className="status status-analyzed">
                            Analizado
                        </span>

                    </div>


                    <p>
                        Resultado generado por
                        el Passive Analyzer.
                    </p>

                </div>

            </header>


            <div className="analysis-metadata">

                <div>
                    <span>Ruta</span>

                    <strong>
                        {capture.relative_path}
                    </strong>
                </div>


                <div>
                    <span>PCAP ID</span>

                    <strong>
                        {capture.pcap_id}
                    </strong>
                </div>


                <div>
                    <span>Schema</span>

                    <strong>
                        {schema_version}
                    </strong>
                </div>

            </div>


            <div className="analysis-summary">

                <div className="summary-card">

                    <span>
                        Interfaces
                    </span>

                    <strong>
                        {interfaces.length}
                    </strong>

                </div>


                <div className="summary-card">

                    <span>
                        Comunicaciones
                    </span>

                    <strong>
                        {communications.length}
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
                            interfaces
                        }
                    />
                )
            }


            {
                activeTab === "communications"
                && (
                    <CommunicationsTable
                        communications={
                            communications
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


export function InterfacesTable({
    interfaces,
}) {

    return (
        <div className="panel">

            <div className="panel-header">

                <div>
                    <h2>
                        Interfaces observadas
                    </h2>

                    <p>
                        Interfaces detectadas
                        en la captura.
                    </p>
                </div>

                <span className="record-count">
                    {interfaces.length}
                </span>

            </div>


            <div className="table-container">

                <table className="data-table">

                    <thead>
                        <tr>
                            <th>MAC</th>
                            <th>IP observadas</th>
                            <th>Primera observación</th>
                            <th>Última observación</th>
                        </tr>
                    </thead>


                    <tbody>

                        {interfaces.map(
                            (networkInterface) => (

                                <tr
                                    key={
                                        networkInterface.mac
                                    }
                                >

                                    <td>
                                        <span className="mono-value">
                                            {
                                                networkInterface.mac
                                            }
                                        </span>
                                    </td>


                                    <td>

                                        {
                                            networkInterface.ips.length
                                            === 0
                                                ? (
                                                    <span className="muted-value">
                                                        Sin IP observada
                                                    </span>
                                                )
                                                : (
                                                    <div className="ip-list">

                                                        {
                                                            networkInterface.ips.map(
                                                                (ip) => (
                                                                    <span
                                                                        key={ip}
                                                                        className="ip-badge"
                                                                    >
                                                                        {ip}
                                                                    </span>
                                                                )
                                                            )
                                                        }

                                                    </div>
                                                )
                                        }

                                    </td>


                                    <td>
                                        {
                                            networkInterface.first_seen
                                        }
                                    </td>


                                    <td>
                                        {
                                            networkInterface.last_seen
                                        }
                                    </td>

                                </tr>

                            )
                        )}

                    </tbody>

                </table>

            </div>

        </div>
    );
}


export function CommunicationsTable({
    communications,
    onSelect,
}) {

    return (
        <div className="panel">

            <div className="panel-header">

                <div>
                    <h2>
                        Comunicaciones observadas
                    </h2>

                    <p>
                        Flujos inferidos a partir
                        del tráfico capturado.
                    </p>
                </div>

                <span className="record-count">
                    {communications.length}
                </span>

            </div>


            <div className="table-container">

                <table className="data-table">

                    <thead>
                        <tr>
                            <th>Origen</th>
                            <th>Destino</th>
                            <th>Transporte</th>
                            <th>Puerto</th>
                            <th>Servicio</th>
                            <th>Paquetes</th>
                            <th>Primera observación</th>
                            <th>Última observación</th>
                            <th></th>
                        </tr>
                    </thead>


                    <tbody>

                        {communications.map(
                            (
                                communication,
                                index
                            ) => (

                                <tr key={index}>

                                    <td>
                                        {
                                            communication.client_ip
                                        }
                                    </td>


                                    <td>
                                        {
                                            communication.server_ip
                                        }
                                    </td>


                                    <td>
                                        {
                                            communication.transport_protocol
                                        }
                                    </td>


                                    <td>
                                        {
                                            communication.service_port
                                        }
                                    </td>


                                    <td>
                                        {
                                            communication.service
                                            || `Puerto ${communication.service_port}`
                                        }
                                    </td>


                                    <td>
                                        {
                                            communication.packet_count
                                                .toLocaleString(
                                                    "es-CO"
                                                )
                                        }
                                    </td>


                                    <td>
                                        {
                                            communication.first_seen
                                        }
                                    </td>


                                    <td>
                                        {
                                            communication.last_seen
                                        }
                                    </td>


                                    <td>

                                        <button
                                            className="button-secondary"
                                            onClick={() =>
                                                onSelect(
                                                    communication
                                                )
                                            }
                                        >
                                            Detalle
                                        </button>

                                    </td>

                                </tr>

                            )
                        )}

                    </tbody>

                </table>

            </div>

        </div>
    );
}


export function CommunicationModal({
    communication,
    onClose,
}) {

    const formatMacs = (
        macs
    ) => {

        if (
            !macs
            || macs.length === 0
        ) {
            return "No disponible";
        }

        return macs.join(", ");
    };


    const roleSourceLabels = {
        known_service_port:
            "Puerto de servicio conocido",

        tcp_syn:
            "Inicio de conexión TCP (SYN)",
    };


    const networkScopeLabels = {
        unknown:
            "Desconocido",

        local_segment:
            "Segmento local",

        external_public:
            "Externo público",
    };


    return (
        <div
            className="modal-backdrop"
            onClick={onClose}
        >

            <div
                className="communication-modal"
                onClick={
                    (event) =>
                        event.stopPropagation()
                }
            >

                <div className="modal-header">

                    <div>
                        <span>
                            Comunicación observada
                        </span>

                        <h2>
                            {
                                communication.client_ip
                            }
                            {" → "}
                            {
                                communication.server_ip
                            }
                        </h2>
                    </div>


                    <button
                        className="modal-close"
                        onClick={onClose}
                    >
                        ×
                    </button>

                </div>


                <div className="communication-detail">

                    <DetailRow
                        label="Transporte"
                        value={
                            communication.transport_protocol
                        }
                    />

                    <DetailRow
                        label="Puerto servicio"
                        value={
                            communication.service_port
                        }
                    />

                    <DetailRow
                        label="Servicio"
                        value={
                            communication.service
                            || "No identificado"
                        }
                    />

                    <DetailRow
                        label="Paquetes"
                        value={
                            communication.packet_count
                                .toLocaleString(
                                    "es-CO"
                                )
                        }
                    />

                    <DetailRow
                        label="Primera vez"
                        value={
                            communication.first_seen
                        }
                    />

                    <DetailRow
                        label="Última vez"
                        value={
                            communication.last_seen
                        }
                    />

                    <DetailRow
                        label="Alcance"
                        value={
                            networkScopeLabels[
                                communication.network_scope
                            ]
                            || communication.network_scope
                            || "No disponible"
                        }
                    />

                    <DetailRow
                        label="Rol inferido por"
                        value={
                            roleSourceLabels[
                                communication.role_source
                            ]
                            || communication.role_source
                            || "No disponible"
                        }
                    />

                    <DetailRow
                        label="MAC cliente"
                        value={
                            formatMacs(
                                communication.client_macs
                            )
                        }
                    />

                    <DetailRow
                        label="MAC servidor"
                        value={
                            formatMacs(
                                communication.server_macs
                            )
                        }
                    />

                </div>

            </div>

        </div>
    );
}


function DetailRow({
    label,
    value,
}) {

    return (
        <div className="detail-row">

            <span>
                {label}
            </span>

            <strong>
                {value}
            </strong>

        </div>
    );
}


export default AnalysisDetail;