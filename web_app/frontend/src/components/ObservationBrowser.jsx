import { useEffect, useState } from "react";

import { getObservationPage } from "../api/ingestion";

const PACKET_OPTIONS = [
  [1, "Todos los registros"],
  [2, "2 o más paquetes"],
  [5, "5 o más paquetes"],
  [10, "10 o más paquetes"],
  [50, "50 o más paquetes"],
  [100, "100 o más paquetes"],
];

export default function ObservationBrowser({ source, id, kind, onSelect, onMetadata }) {
  const [query, setQuery] = useState("");
  const [search, setSearch] = useState("");
  const [minPackets, setMinPackets] = useState(1);
  const [page, setPage] = useState(1);
  const [response, setResponse] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    const timeout = setTimeout(() => setSearch(query.trim()), 350);
    return () => clearTimeout(timeout);
  }, [query]);

  useEffect(() => {
    setQuery("");
    setSearch("");
    setMinPackets(1);
    setPage(1);
  }, [kind, id, source]);

  useEffect(() => {
    setPage(1);
  }, [search, minPackets]);

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError("");

    getObservationPage(source, id, { kind, page, search, minPackets })
      .then((data) => {
        if (!active) return;
        setResponse(data);
        if (data.capture && onMetadata) onMetadata(data);
      })
      .catch((err) => {
        if (active) setError(err.message);
      })
      .finally(() => {
        if (active) setLoading(false);
      });

    return () => { active = false; };
  }, [source, id, kind, page, search, minPackets, onMetadata]);

  const rows = response?.results || [];
  const count = response?.count || 0;
  const currentPage = response?.page || 1;
  const totalPages = Math.max(1, Math.ceil(count / (response?.page_size || 25)));

  return (
    <div className="panel">
      <div className="panel-header">
        <div>
          <h2>{kind === "interfaces" ? "Interfaces observadas" : "Comunicaciones observadas"}</h2>
          <p>{kind === "interfaces"
            ? "Direcciones MAC e IP detectadas en la captura."
            : "Flujos inferidos a partir del tráfico capturado. Los filtros no eliminan evidencia."}</p>
        </div>
        <span className="record-count">{count.toLocaleString("es-CO")} resultados</span>
      </div>

      <div className="table-toolbar observations-toolbar">
        <div className="search-box">
          <input
            type="search"
            aria-label={kind === "interfaces" ? "Buscar interfaces" : "Buscar comunicaciones"}
            placeholder={kind === "interfaces"
              ? "Buscar MAC o dirección IP..."
              : "Buscar origen, destino, servicio, protocolo o puerto..."}
            value={query}
            onChange={(event) => setQuery(event.target.value)}
          />
        </div>
        {kind === "communications" && (
          <select className="table-filter-select"
            aria-label="Filtrar por paquetes mínimos"
            value={minPackets}
            onChange={(event) => { setMinPackets(Number(event.target.value)); setPage(1); }}>
            {PACKET_OPTIONS.map(([value, label]) => (
              <option key={value} value={value}>{label}</option>
            ))}
          </select>
        )}
        <span className="filtered-count">25 registros por página</span>
      </div>

      {error && <div className="error-message">{error}</div>}
      {loading ? (
        <div className="empty-state">Consultando página de observaciones...</div>
      ) : !error && rows.length === 0 ? (
        <div className="empty-state">No existen observaciones para los filtros seleccionados.</div>
      ) : !error && (
        <div className="table-container">
          <table className="data-table">
            <thead>
              {kind === "interfaces" ? (
                <tr><th>MAC</th><th>IP observadas</th><th>Primera observación</th><th>Última observación</th></tr>
              ) : (
                <tr>
                  <th>Origen</th><th>Destino</th><th>Transporte</th><th>Puerto</th>
                  <th>Servicio</th><th>Paquetes</th><th>Primera observación</th>
                  <th>Última observación</th><th>Acciones</th>
                </tr>
              )}
            </thead>
            <tbody>
              {kind === "interfaces"
                ? rows.map((item) => (
                  <tr key={item.id || item.mac}>
                    <td className="mono-value">{item.mac}</td>
                    <td>
                      {!item.ips?.length ? (
                        <span className="muted-value">Sin IP observada</span>
                      ) : (
                        <div className="ip-list">
                          {item.ips.map((ip) => (
                            <span className="ip-badge" key={ip}>{ip}</span>
                          ))}
                        </div>
                      )}
                    </td>
                    <td>{item.first_seen}</td>
                    <td>{item.last_seen}</td>
                  </tr>
                ))
                : rows.map((item, index) => (
                  <tr key={item.id || [page, index, item.client_ip, item.service_port].join("-")}>
                    <td>{item.client_ip}</td>
                    <td>{item.server_ip}</td>
                    <td>{item.transport_protocol}</td>
                    <td>{item.service_port}</td>
                    <td>{item.service || "Puerto " + item.service_port}</td>
                    <td>{Number(item.packet_count).toLocaleString("es-CO")}</td>
                    <td>{item.first_seen}</td>
                    <td>{item.last_seen}</td>
                    <td>
                      <button type="button" className="button-secondary"
                        onClick={() => onSelect(item)}>Detalle</button>
                    </td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="pagination">
        <span>
          {count.toLocaleString("es-CO")} coincidencias · Página {currentPage} de {totalPages}
        </span>
        <div className="pagination-actions">
          <button type="button" disabled={loading || currentPage <= 1}
            onClick={() => setPage(currentPage - 1)}>Anterior</button>
          <button type="button" disabled={loading || currentPage >= totalPages}
            onClick={() => setPage(currentPage + 1)}>Siguiente</button>
        </div>
      </div>
    </div>
  );
}
