import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";

import { getCommunications } from "../api/network";
import CommunicationEndpoint from "../components/CommunicationEndpoint";
import DeviceFilter from "../components/DeviceFilter";

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
  const [selectedDevices, setSelectedDevices] = useState([]);
  const selectedAssetIds = selectedDevices.map((device) => device.id);
  const assetKey = selectedAssetIds.join(",");
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
  }, [search, statusFilter, minPackets, assetKey]);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError("");
    setResponse(null);

    getCommunications({
      page: currentPage,
      search,
      status: statusFilter,
      minPackets,
      assetIds: selectedAssetIds,
      signal: controller.signal,
    })
      .then((data) => {
        if (!controller.signal.aborted) setResponse(data);
      })
      .catch((err) => {
        if (!controller.signal.aborted && err.name !== "AbortError") {
          setError(err.message);
        }
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });

    return () => controller.abort();
  }, [currentPage, search, statusFilter, minPackets, assetKey]);

  // Avoid displaying the previous query's count while a search is pending.
  const isPending = loading || query.trim() !== search;
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
            {isPending ? "Buscando..." : count.toLocaleString("es-CO") + " coincidencias"}
          </span>
        </div>

        <div className="table-toolbar">
          <div className="search-box">
            <input
              type="search"
              aria-label="Buscar comunicaciones"
              placeholder="Buscar IP, dispositivo, protocolo, puerto o servicio..."
              value={query}
              onChange={(event) => setQuery(event.target.value)}
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

        <DeviceFilter selected={selectedDevices} onChange={setSelectedDevices} />

        {error && <div className="error-message">{error}</div>}

        {isPending ? (
          <div className="empty-state">Buscando comunicaciones...</div>
        ) : !error && communications.length === 0 ? (
          <div className="empty-state">
            <strong>No se encontraron comunicaciones.</strong>
            <p>{selectedDevices.length === 2
              ? "No se encontraron comunicaciones identificadas entre estos dos dispositivos en las ingestas activas."
              : selectedDevices.length === 1
                ? "No se encontraron comunicaciones identificadas para este dispositivo en las ingestas activas."
                : "Prueba otro valor de búsqueda, clasificación o mínimo de paquetes."}</p>
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
                    <td><CommunicationEndpoint ip={communication.source_ip} resolution={communication.source_resolution} /></td>
                    <td><CommunicationEndpoint ip={communication.destination_ip} resolution={communication.destination_resolution} /></td>
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
            {isPending
              ? "Consultando..."
              : count.toLocaleString("es-CO") + " coincidencias · Página " + page + " de " + totalPages}
          </span>
          <div className="pagination-actions">
            <button type="button" disabled={isPending || page <= 1}
              onClick={() => setCurrentPage(page - 1)}>
              Anterior
            </button>
            <button type="button" disabled={isPending || page >= totalPages}
              onClick={() => setCurrentPage(page + 1)}>
              Siguiente
            </button>
          </div>
        </div>
      </div>
    </section>
  );
}
