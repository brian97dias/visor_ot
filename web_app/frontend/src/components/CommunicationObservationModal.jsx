function DetailRow({ label, value }) {
  return (
    <div className="detail-row">
      <span>{label}</span>
      <strong>{value ?? "No disponible"}</strong>
    </div>
  );
}

export default function CommunicationObservationModal({ communication, onClose }) {
  if (!communication) return null;

  const formatMacs = (macs) => Array.isArray(macs) && macs.length
    ? macs.join(", ") : "No disponible";

  const roles = {
    known_service_port: "Puerto de servicio conocido",
    tcp_syn: "Inicio de conexión TCP (SYN)",
  };

  const scopes = {
    unknown: "Desconocido",
    local_segment: "Segmento local",
    external_public: "Externo público",
  };

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <section className="communication-modal" role="dialog" aria-modal="true"
        aria-label="Detalle de comunicación observada"
        onClick={(event) => event.stopPropagation()}>
        <div className="modal-header">
          <div>
            <span>Comunicación observada</span>
            <h2>{communication.client_ip} → {communication.server_ip}</h2>
          </div>
          <button type="button" className="modal-close" onClick={onClose}
            aria-label="Cerrar detalle">×</button>
        </div>
        <div className="communication-detail">
          <DetailRow label="Transporte" value={communication.transport_protocol} />
          <DetailRow label="Puerto de servicio" value={communication.service_port} />
          <DetailRow label="Servicio" value={communication.service || "No identificado"} />
          <DetailRow label="Paquetes" value={Number(communication.packet_count).toLocaleString("es-CO")} />
          <DetailRow label="Primera vez" value={communication.first_seen} />
          <DetailRow label="Última vez" value={communication.last_seen} />
          <DetailRow label="Alcance" value={scopes[communication.network_scope] || communication.network_scope || "No disponible"} />
          <DetailRow label="Rol inferido por" value={roles[communication.role_source] || communication.role_source || "No disponible"} />
          <DetailRow label="MAC cliente" value={formatMacs(communication.client_macs)} />
          <DetailRow label="MAC servidor" value={formatMacs(communication.server_macs)} />
        </div>
      </section>
    </div>
  );
}
