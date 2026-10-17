import { Link } from "react-router-dom";

/**
 * Display a device name only when the backend verified per-capture evidence.
 * IP is always visible, including when the endpoint is identified.
 */
export default function CommunicationEndpoint({ ip, resolution }) {
  const device = resolution?.status === "IDENTIFIED"
    ? resolution.identity : null;

  if (!device) {
    return (
      <div className="communication-endpoint">
        <span className="mono-value">{ip}</span>
        {resolution?.status === "AMBIGUOUS" && (
          <small className="communication-endpoint-warning">
            Identificación ambigua
          </small>
        )}
      </div>
    );
  }

  return (
    <div className="communication-endpoint">
      <Link className="communication-device-link entity-link"
        to={"/assets/" + device.asset_id}
        title={"Identificado con ARP de la captura y asociación manual; MAC " + device.mac}>
        {device.asset_name}
      </Link>
      <small className="communication-endpoint-secondary">
        {device.role} · {ip}
      </small>
    </div>
  );
}
