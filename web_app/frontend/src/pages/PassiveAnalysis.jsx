import { useEffect, useMemo, useState } from "react";

import { analyzePcap, getPcaps } from "../api/ingestion";

const PAGE_SIZE = 15;

function PassiveAnalysis() {
  const [analyzingPcaps, setAnalyzingPcaps] = useState(new Set());

  const handleAnalyze = async (pcap) => {
    setError("");

    setAnalyzingPcaps((current) => {
      const updated = new Set(current);

      updated.add(pcap.id);

      return updated;
    });

    try {
      await analyzePcap(pcap.id);

      /*
       * No cambiamos manualmente:
       *
       * PENDING -> ANALYZED
       *
       * Volvemos a consultar el catálogo
       * para que el Passive Analyzer sea
       * la fuente de verdad.
       */

      const updatedPcaps = await getPcaps();

      setPcaps(updatedPcaps);
    } catch (error) {
      setError(error.message);
    } finally {
      setAnalyzingPcaps((current) => {
        const updated = new Set(current);

        updated.delete(pcap.id);

        return updated;
      });
    }
  };

  const [pcaps, setPcaps] = useState([]);

  const [activeTab, setActiveTab] = useState("pcaps");

  const [search, setSearch] = useState("");

  const [currentPage, setCurrentPage] = useState(1);

  const [loading, setLoading] = useState(true);

  const [error, setError] = useState("");

  useEffect(() => {
    async function loadPcaps() {
      try {
        const pcapData = await getPcaps();

        setPcaps(pcapData);
      } catch (error) {
        setError(error.message);
      } finally {
        setLoading(false);
      }
    }

    loadPcaps();
  }, []);

  useEffect(() => {
    setCurrentPage(1);
  }, [search]);

  const filteredPcaps = useMemo(() => {
    const normalizedSearch = search.trim().toLowerCase();

    if (!normalizedSearch) {
      return pcaps;
    }

    return pcaps.filter((pcap) => {
      const searchableText = [pcap.filename, pcap.relative_path, pcap.status]
        .join(" ")
        .toLowerCase();

      return searchableText.includes(normalizedSearch);
    });
  }, [pcaps, search]);

  const totalPages = Math.max(1, Math.ceil(filteredPcaps.length / PAGE_SIZE));

  const paginatedPcaps = useMemo(() => {
    const start = (currentPage - 1) * PAGE_SIZE;

    const end = start + PAGE_SIZE;

    return filteredPcaps.slice(start, end);
  }, [filteredPcaps, currentPage]);

  const changeTab = (tab) => {
    setActiveTab(tab);
    setCurrentPage(1);
    setSearch("");
  };

  const goToPreviousPage = () => {
    setCurrentPage((page) => Math.max(1, page - 1));
  };

  const goToNextPage = () => {
    setCurrentPage((page) => Math.min(totalPages, page + 1));
  };

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
          <span className="page-eyebrow">RED</span>

          <h1>Análisis pasivo</h1>

          <p>
            Gestión de capturas, análisis e importación de observaciones de red.
          </p>
        </div>
      </header>

      {error && <div className="error-message">{error}</div>}

      <div className="analysis-tabs">
        <button
          className={
            activeTab === "pcaps" ? "analysis-tab active" : "analysis-tab"
          }
          onClick={() => changeTab("pcaps")}
        >
          PCAP disponibles
        </button>

        <button
          className={
            activeTab === "observations"
              ? "analysis-tab active"
              : "analysis-tab"
          }
          onClick={() => changeTab("observations")}
        >
          Observaciones importadas
        </button>
      </div>

      {activeTab === "pcaps" && (
        <div className="panel">
          <div className="panel-header">
            <div>
              <h2>PCAP disponibles</h2>

              <p>Capturas disponibles en el Passive Analyzer.</p>
            </div>

            <span className="record-count">{pcaps.length} capturas</span>
          </div>

          <div className="table-toolbar">
            <div className="search-box">
              <input
                type="search"
                placeholder={"Buscar por nombre o ruta..."}
                value={search}
                onChange={(event) => setSearch(event.target.value)}
              />
            </div>

            <span className="filtered-count">
              {filteredPcaps.length} resultados
            </span>
          </div>

          {filteredPcaps.length === 0 ? (
            <div className="empty-state">
              No se encontraron capturas que coincidan con la búsqueda.
            </div>
          ) : (
            <>
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
                    {paginatedPcaps.map((pcap) => (
                      <tr key={pcap.id}>
                        <td>
                          <div className="pcap-name">{pcap.filename}</div>

                          <div className="pcap-path">{pcap.relative_path}</div>
                        </td>

                        <td>
                          <span
                            className={
                              pcap.status === "ANALYZED"
                                ? "status status-analyzed"
                                : "status status-pending"
                            }
                          >
                            {pcap.status === "ANALYZED"
                              ? "Analizado"
                              : "Pendiente"}
                          </span>
                        </td>

                        <td>
                          <div className="table-actions">
                            {pcap.status === "ANALYZED" && (
                              <>
                                <button className="button-secondary" disabled>
                                  Ver análisis
                                </button>

                                <button className="button-secondary" disabled>
                                  Importar
                                </button>
                              </>
                            )}

                            <button
                              className="button-primary"
                              onClick={() => handleAnalyze(pcap)}
                              disabled={analyzingPcaps.has(pcap.id)}
                            >
                              {analyzingPcaps.has(pcap.id)
                                ? "Analizando..."
                                : pcap.status === "ANALYZED"
                                  ? "Reanalizar"
                                  : "Analizar"}
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              <div className="pagination">
                <span>
                  Página {currentPage} de {totalPages}
                </span>

                <div className="pagination-actions">
                  <button
                    onClick={goToPreviousPage}
                    disabled={currentPage === 1}
                  >
                    Anterior
                  </button>

                  <button
                    onClick={goToNextPage}
                    disabled={currentPage === totalPages}
                  >
                    Siguiente
                  </button>
                </div>
              </div>
            </>
          )}
        </div>
      )}

      {activeTab === "observations" && (
        <div className="panel">
          <div className="panel-header">
            <div>
              <h2>Observaciones importadas</h2>

              <p>Observaciones incorporadas a Visual OT.</p>
            </div>

            <span className="record-count">0 importaciones</span>
          </div>

          <div className="empty-state observations-empty">
            <strong>Aún no hay observaciones importadas</strong>

            <p>
              Cuando importes el resultado de un análisis, aparecerá aquí para
              su revisión y posterior asociación con el inventario.
            </p>
          </div>
        </div>
      )}
    </section>
  );
}

export default PassiveAnalysis;
