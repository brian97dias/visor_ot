import { useEffect, useState } from "react";
import { useLocation, useNavigate, useSearchParams } from "react-router-dom";
import { readPage, parseAssetIds, updateListParams } from "../utils/listUrlState";
import { navigationFromLocation } from "../utils/returnNavigation";

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
  const location = useLocation();
  const [searchParams, setSearchParams] = useSearchParams();
  const query = searchParams.get("q") || "";
  const matchMode = searchParams.get("match_mode") === "EXACT_IP" ? "EXACT_IP" : "PARTIAL";
  const [search, setSearch] = useState(() => query.trim());
  const statusParam = searchParams.get("status") || "ALL";
  const statusFilter = Object.hasOwn(STATUS_LABELS, statusParam) ? statusParam : "ALL";
  const requestedPackets = Number(searchParams.get("min_packets") || 1);
  const minPackets = PACKET_OPTIONS.some(([n]) => n === requestedPackets) ? requestedPackets : 1;
  const selectedAssetIds = parseAssetIds(searchParams.get("devices"));
  const assetKey = selectedAssetIds.join(",");
  const currentPage = readPage(searchParams.get("page"));
  const navigationState = navigationFromLocation(location);
  function changeFilter(name, value, defaultValue = "") {
    setSearchParams(updateListParams(searchParams, name, value, { defaultValue }),
      { replace: name === "q" });
  }
  const [response, setResponse] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    const timeoutId = setTimeout(() => setSearch(query.trim()), 350);
    return () => clearTimeout(timeoutId);
  }, [query]);


useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError("");
    setResponse(null);

    getCommunications({
      page: currentPage,
      search,
      matchMode,
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
  }, [currentPage, search, matchMode, statusFilter, minPackets, assetKey]);

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
              placeholder={matchMode === "EXACT_IP"
                ? "Buscar IPv4 o IPv6 completa..."
                : "Buscar IP, dispositivo, protocolo, puerto o servicio..."}
              value={query}
              onChange={(event) => changeFilter("q", event.target.value)}
            />
          </div>

          <select className="table-filter-select"
            aria-label="Modo de búsqueda"
            value={matchMode}
            onChange={(event) => changeFilter("match_mode", event.target.value, "PARTIAL")}>
            <option value="PARTIAL">Coincidencia parcial</option>
            <option value="EXACT_IP">IP exacta</option>
          </select>

          <select className="table-filter-select"
            aria-label="Filtrar clasificación"
            value={statusFilter}
            onChange={(event) => changeFilter("status", event.target.value, "ALL")}>
            <option value="ALL">Todos los estados</option>
            <option value="NO_CLASIFICADA">No clasificadas</option>
            <option value="AUTORIZADA">Autorizadas</option>
            <option value="NO_AUTORIZADA">No autorizadas</option>
          </select>

          <select className="table-filter-select"
            aria-label="Filtrar paquetes mínimos"
            value={minPackets}
            onChange={(event) => changeFilter("min_packets", event.target.value, "1")}>
            {PACKET_OPTIONS.map(([value, label]) => (
              <option key={value} value={value}>{label}</option>
            ))}
          </select>

          <span className="filtered-count">25 por página</span>
        </div>

        <DeviceFilter selected={selectedAssetIds} onChange={(ids) => changeFilter("devices", ids.join(","))} />

        {error && <div className="error-message">{error}</div>}

        {isPending ? (
          <div className="empty-state">Buscando comunicaciones...</div>
        ) : !error && communications.length === 0 ? (
          <div className="empty-state">
            <strong>No se encontraron comunicaciones.</strong>
            <p>{selectedAssetIds.length === 2
              ? "No se encontraron comunicaciones identificadas entre estos dos dispositivos en las ingestas activas."
              : selectedAssetIds.length === 1
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
                        onClick={() => navigate("/communications/" + communication.id, { state: navigationState })}>
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
              onClick={() => changeFilter("page", page - 1, "1")}>
              Anterior
            </button>
            <button type="button" disabled={isPending || page >= totalPages}
              onClick={() => changeFilter("page", page + 1, "1")}>
              Siguiente
            </button>
          </div>
        </div>
      </div>
    </section>
  );
}
