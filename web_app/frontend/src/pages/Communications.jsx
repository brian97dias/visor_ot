import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";

import { getCommunications } from "../api/network";
import CommunicationEndpoint from "../components/CommunicationEndpoint";

const PACKET_OPTIONS = [
  [1, "Todos los registros"],
  [2, "2 o más paquetes"],
  [5, "5 o más paquetes"],
  [10, "10 o más paquetes"],
  [50, "50 o más paquetes"],
  [100, "100 o más paquetes"],
];

const STATUS_LABELS = {
  NO_CLASIFICADA: "No clasificada",
  AUTORIZADA: "Autorizada",
  NO_AUTORIZADA: "No autorizada",
};

const STATUS_CLASSES = {
  NO_CLASIFICADA: "status status-unclassified",
  AUTORIZADA: "status status-authorized",
  NO_AUTORIZADA: "status status-unauthorized",
};

export default function Communications() {
  const navigate = useNavigate();
  const [query, setQuery] = useState("");
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("ALL");
  const [minPackets, setMinPackets] = useState(1);
  const [currentPage, setCurrentPage] = useState(1);
  const [response, setResponse] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    const timeoutId = setTimeout(() => setSearch(query.trim()), 350);
    return () => clearTimeout(timeoutId);
  }, [query]);

  useEffect(() => {
    setCurrentPage(1);
  }, [search, statusFilter, minPackets]);

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError("");

    getCommunications({
      page: currentPage,
      search,
      status: statusFilter,
      minPackets,
    })
      .then((data) => {
        if (active) setResponse(data);
      })
      .catch((err) => {
        if (active) setError(err.message);
      })
      .finally(() => {
        if (active) setLoading(false);
      });

    return () => {
      active = false;
    };
  }, [currentPage, search, statusFilter, minPackets]);

  const communications = response?.results || [];
  const count = response?.count || 0;
  const page = response?.page || 1;
  const totalPages = Math.max(
    1, Math.ceil(count / (response?.page_size || 25))
  );

  return (
    <section className="page">
      <header className="page-header">
        <span className="page-eyebrow">RED</span>
        <h1>Comunicaciones</h1>
        <p>Representación consolidada de las comunicaciones observadas en las ingestas activas.</p>
      </header>

      <div className="panel">
        <div className="panel-header">
          <div>
            <h2>Comunicaciones observadas</h2>
            <p>Comunicaciones consolidadas a partir de evidencia activa.</p>
          </div>
          <span className="record-count">
            {count.toLocaleString("es-CO")} coincidencias
          </span>
        </div>

        <div className="table-toolbar">
          <div className="search-box">
            <input
              type="search"
              aria-label="Buscar comunicaciones"
              placeholder="Buscar por IP, protocolo, puerto o servicio..."
              value={query}
              onChange={(event) => {
                setQuery(event.target.value);
                setCurrentPage(1);
              }}
            />
          </div>

          <select className="table-filter-select"
            aria-label="Filtrar clasificación"
            value={statusFilter}
            onChange={(event) => {
              setStatusFilter(event.target.value);
              setCurrentPage(1);
            }}>
            <option value="ALL">Todos los estados</option>
            <option value="NO_CLASIFICADA">No clasificadas</option>
            <option value="AUTORIZADA">Autorizadas</option>
            <option value="NO_AUTORIZADA">No autorizadas</option>
          </select>

          <select className="table-filter-select"
            aria-label="Filtrar paquetes mínimos"
            value={minPackets}
            onChange={(event) => {
              setMinPackets(Number(event.target.value));
              setCurrentPage(1);
            }}>
            {PACKET_OPTIONS.map(([value, label]) => (
              <option key={value} value={value}>{label}</option>
            ))}
          </select>

          <span className="filtered-count">25 por página</span>
        </div>

        {error && <div className="error-message">{error}</div>}

        {loading ? (
          <div className="empty-state">Cargando página de comunicaciones...</div>
        ) : !error && communications.length === 0 ? (
          <div className="empty-state">
            <strong>No se encontraron comunicaciones.</strong>
            <p>Prueba otro valor de búsqueda, clasificación o mínimo de paquetes.</p>
          </div>
        ) : !error && (
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
                {communications.map((communication) => (
                  <tr key={communication.id}>
                    <td><CommunicationEndpoint ip={communication.source_ip} resolution={communication.source_resolution} compact /></td>
                    <td><CommunicationEndpoint ip={communication.destination_ip} resolution={communication.destination_resolution} compact /></td>
                    <td>
                      {communication.transport_protocol} / {communication.service_port}
                    </td>
                    <td>{communication.service || "Puerto " + communication.service_port}</td>
                    <td>{communication.active_evidence_count}</td>
                    <td>{Number(communication.packets_observed).toLocaleString("es-CO")}</td>
                    <td>
                      <span className={STATUS_CLASSES[communication.status] || STATUS_CLASSES.NO_CLASIFICADA}>
                        {STATUS_LABELS[communication.status] || communication.status}
                      </span>
                    </td>
                    <td>
                      <button type="button" className="button-secondary"
                        onClick={() => navigate("/communications/" + communication.id)}>
                        Ver
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        <div className="pagination">
          <span>
            {count.toLocaleString("es-CO")} coincidencias · Página {page} de {totalPages}
          </span>
          <div className="pagination-actions">
            <button type="button" disabled={loading || page <= 1}
              onClick={() => setCurrentPage(page - 1)}>
              Anterior
            </button>
            <button type="button" disabled={loading || page >= totalPages}
              onClick={() => setCurrentPage(page + 1)}>
              Siguiente
            </button>
          </div>
        </div>
      </div>
    </section>
  );
}
