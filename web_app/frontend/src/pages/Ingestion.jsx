import { useEffect, useState } from "react";

import { getPcaps } from "../api/ingestion";


function Ingestion() {
    const [pcaps, setPcaps] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");


    useEffect(() => {
        async function loadPcaps() {
            const accessToken =
                sessionStorage.getItem("access_token");

            try {
                const pcapData =
                    await getPcaps(accessToken);

                setPcaps(pcapData);

            } catch (error) {
                setError(error.message);

            } finally {
                setLoading(false);
            }
        }

        loadPcaps();
    }, []);


    if (loading) {
        return (
            <section className="page">
                <p>Cargando PCAPs...</p>
            </section>
        );
    }


    return (
        <section className="page">

            <header className="page-header">

                <div>
                    <span className="page-eyebrow">
                        RED
                    </span>

                    <h1>
                        Ingesta
                    </h1>

                    <p>
                        Capturas disponibles en el
                        Passive Analyzer.
                    </p>
                </div>

            </header>


            {error && (
                <div className="error-message">
                    {error}
                </div>
            )}


            <div className="panel">

                <div className="panel-header">

                    <div>
                        <h2>PCAPs</h2>

                        <p>
                            Capturas disponibles para
                            análisis e importación de
                            observaciones.
                        </p>
                    </div>


                    <span className="record-count">
                        {pcaps.length} capturas
                    </span>

                </div>


                {pcaps.length === 0 ? (

                    <div className="empty-state">
                        No hay capturas PCAP disponibles.
                    </div>

                ) : (

                    <div className="table-container">

                        <table className="data-table">

                            <thead>
                                <tr>
                                    <th>Nombre</th>
                                    <th>Estado</th>
                                    <th>Acciones</th>
                                </tr>
                            </thead>


                            <tbody>

                                {pcaps.map((pcap) => (

                                    <tr key={pcap.id}>

                                        <td>
                                            <div className="pcap-name">
                                                {pcap.filename}
                                            </div>

                                            <div className="pcap-path">
                                                {pcap.relative_path}
                                            </div>
                                        </td>


                                        <td>
                                            <span
                                                className={
                                                    pcap.status === "ANALYZED"
                                                        ? "status status-analyzed"
                                                        : "status status-pending"
                                                }
                                            >
                                                {
                                                    pcap.status === "ANALYZED"
                                                        ? "Analizado"
                                                        : "Pendiente"
                                                }
                                            </span>
                                        </td>


                                        <td>
                                            <div className="table-actions">

                                                {pcap.status === "ANALYZED" && (
                                                    <button
                                                        className="button-secondary"
                                                        disabled
                                                    >
                                                        Importar observaciones
                                                    </button>
                                                )}


                                                <button
                                                    className="button-primary"
                                                    disabled
                                                >
                                                    {
                                                        pcap.status === "ANALYZED"
                                                            ? "Reanalizar"
                                                            : "Analizar PCAP"
                                                    }
                                                </button>

                                            </div>
                                        </td>

                                    </tr>

                                ))}

                            </tbody>

                        </table>

                    </div>

                )}

            </div>

        </section>
    );
}

export default Ingestion;