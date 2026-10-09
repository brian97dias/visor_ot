import {
  useEffect,
  useMemo,
  useState,
} from "react";

import {
  useNavigate,
} from "react-router-dom";

import {
  getCommunications,
} from "../api/network";


const PAGE_SIZE = 15;


function getStatusLabel(status) {

  const labels = {
    NO_CLASIFICADA:
      "No clasificada",

    AUTORIZADA:
      "Autorizada",

    NO_AUTORIZADA:
      "No autorizada",
  };


  return labels[status] || status;
}


function getStatusClass(status) {

  const classes = {
    NO_CLASIFICADA:
      "status status-unclassified",

    AUTORIZADA:
      "status status-authorized",

    NO_AUTORIZADA:
      "status status-unauthorized",
  };


  return (
    classes[status]
    || "status status-unclassified"
  );
}


function Communications() {

  const navigate =
    useNavigate();


  const [
    communications,
    setCommunications,
  ] = useState([]);

  const [
    search,
    setSearch,
  ] = useState("");

  const [
    statusFilter,
    setStatusFilter,
  ] = useState("ALL");

  const [
    currentPage,
    setCurrentPage,
  ] = useState(1);

  const [
    loading,
    setLoading,
  ] = useState(true);

  const [
    error,
    setError,
  ] = useState("");


  useEffect(() => {

    async function loadCommunications() {

      try {

        const data =
          await getCommunications();

        setCommunications(
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


    loadCommunications();

  }, []);


  useEffect(() => {

    setCurrentPage(1);

  }, [
    search,
    statusFilter,
  ]);


  const filteredCommunications =
    useMemo(() => {

      const normalizedSearch =
        search
          .trim()
          .toLowerCase();


      return communications.filter(
        (communication) => {

          const matchesStatus =
            statusFilter === "ALL"
            || communication.status
              === statusFilter;


          const searchableText = [
            communication.source_ip,
            communication.destination_ip,
            communication.transport_protocol,
            communication.service_port,
            communication.service,
            communication.status,
          ]
            .filter(Boolean)
            .join(" ")
            .toLowerCase();


          const matchesSearch =
            !normalizedSearch
            || searchableText.includes(
              normalizedSearch
            );


          return (
            matchesStatus
            && matchesSearch
          );

        }
      );

    }, [
      communications,
      search,
      statusFilter,
    ]);


  const totalPages = Math.max(
    1,
    Math.ceil(
      filteredCommunications.length
      / PAGE_SIZE
    )
  );


  const paginatedCommunications =
    useMemo(() => {

      const start =
        (currentPage - 1)
        * PAGE_SIZE;

      return (
        filteredCommunications.slice(
          start,
          start + PAGE_SIZE
        )
      );

    }, [
      filteredCommunications,
      currentPage,
    ]);


  if (loading) {

    return (
      <section className="page">
        <p>
          Cargando comunicaciones...
        </p>
      </section>
    );

  }


  return (
    <section className="page">

      <header className="page-header">

        <span className="page-eyebrow">
          RED
        </span>

        <h1>
          Comunicaciones
        </h1>

        <p>
          Representación consolidada
          de las comunicaciones observadas
          en las ingestas activas.
        </p>

      </header>


      {error && (

        <div className="error-message">
          {error}
        </div>

      )}


      <div className="panel">

        <div className="panel-header">

          <div>
            <h2>
              Comunicaciones observadas
            </h2>

            <p>
              Comunicaciones consolidadas
              a partir de evidencia activa.
            </p>
          </div>


          <span className="record-count">
            {communications.length}
            {" "}
            comunicaciones
          </span>

        </div>


        <div className="table-toolbar">

          <div className="search-box">

            <input
              type="search"
              placeholder={
                "Buscar por IP, protocolo, puerto o servicio..."
              }
              value={search}
              onChange={
                (event) =>
                  setSearch(
                    event.target.value
                  )
              }
            />

          </div>


          <select
            className="table-filter-select"
            value={statusFilter}
            onChange={
              (event) =>
                setStatusFilter(
                  event.target.value
                )
            }
          >
            <option value="ALL">
              Todos los estados
            </option>

            <option value="NO_CLASIFICADA">
              No clasificadas
            </option>

            <option value="AUTORIZADA">
              Autorizadas
            </option>

            <option value="NO_AUTORIZADA">
              No autorizadas
            </option>
          </select>


          <span className="filtered-count">
            {
              filteredCommunications.length
            }
            {" "}
            resultados
          </span>

        </div>


        {
          filteredCommunications.length
          === 0
            ? (

              <div className="empty-state">

                <strong>
                  No hay comunicaciones
                  con evidencia activa.
                </strong>

                <p>
                  Las comunicaciones aparecerán
                  cuando existan ingestas activas
                  con observaciones de red.
                </p>

              </div>

            )
            : (

              <>

                <div className="table-container">

                  <table className="data-table">

                    <thead>
                      <tr>
                        <th>Origen</th>
                        <th>Destino</th>
                        <th>Transporte</th>
                        <th>Servicio</th>
                        <th>Evidencias</th>
                        <th>Paquetes</th>
                        <th>Estado</th>
                        <th>Acciones</th>
                      </tr>
                    </thead>


                    <tbody>

                      {
                        paginatedCommunications.map(
                          (communication) => (

                            <tr
                              key={
                                communication.id
                              }
                            >

                              <td>
                                <span className="mono-value">
                                  {
                                    communication.source_ip
                                  }
                                </span>
                              </td>


                              <td>
                                <span className="mono-value">
                                  {
                                    communication.destination_ip
                                  }
                                </span>
                              </td>


                              <td>
                                {
                                  communication.transport_protocol
                                }
                                {" / "}
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
                                  communication.active_evidence_count
                                }
                              </td>


                              <td>
                                {
                                  communication.packets_observed
                                    .toLocaleString(
                                      "es-CO"
                                    )
                                }
                              </td>


                              <td>

                                <span
                                  className={
                                    getStatusClass(
                                      communication.status
                                    )
                                  }
                                >
                                  {
                                    getStatusLabel(
                                      communication.status
                                    )
                                  }
                                </span>

                              </td>


                              <td>

                                <button
                                  className="button-secondary"
                                  onClick={() =>
                                    navigate(
                                      `/communications/${communication.id}`
                                    )
                                  }
                                >
                                  Ver
                                </button>

                              </td>

                            </tr>

                          )
                        )
                      }

                    </tbody>

                  </table>

                </div>


                <div className="pagination">

                  <span>
                    Página
                    {" "}
                    {currentPage}
                    {" "}
                    de
                    {" "}
                    {totalPages}
                  </span>


                  <div className="pagination-actions">

                    <button
                      disabled={
                        currentPage === 1
                      }
                      onClick={() =>
                        setCurrentPage(
                          (page) =>
                            Math.max(
                              1,
                              page - 1
                            )
                        )
                      }
                    >
                      Anterior
                    </button>


                    <button
                      disabled={
                        currentPage
                        === totalPages
                      }
                      onClick={() =>
                        setCurrentPage(
                          (page) =>
                            Math.min(
                              totalPages,
                              page + 1
                            )
                        )
                      }
                    >
                      Siguiente
                    </button>

                  </div>

                </div>

              </>

            )
        }

      </div>

    </section>
  );
}


export default Communications;