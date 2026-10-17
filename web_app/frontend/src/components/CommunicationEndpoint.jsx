import { Link } from "react-router-dom";
import { groupEndpointCandidates } from "../utils/endpointCandidates";

/**
 * Device names are confirmed only when the backend returns IDENTIFIED.
 * AMBIGUOUS candidates are explicitly labeled and never replace the raw IP.
 */
export default function CommunicationEndpoint({ ip, resolution }) {
  const device = resolution?.status === "IDENTIFIED"
    ? resolution.identity : null;
  const ambiguous = resolution?.status === "AMBIGUOUS";
  const { assets, unassignedMacs } = groupEndpointCandidates(
    ambiguous ? resolution?.candidates : [],
  );

  if (!device) {
    return (
      <div className="communication-endpoint">
        <span className="mono-value">{ip}</span>
        {ambiguous && (
          <>
            <small className="communication-endpoint-warning">
              Identificación ambigua
            </small>
            {assets.map((asset) => (
              <small className="communication-endpoint-candidate" key={asset.asset_id}>
                Posible activo:{" "}
                <Link className="entity-link" to={"/assets/" + asset.asset_id}>
                  {asset.asset_name}
                </Link>
              </small>
            ))}
            {unassignedMacs.map((mac) => (
              <small className="communication-endpoint-unassigned" key={mac}>
                Interfaz sin identificar: <span className="mono-value">{mac}</span>
              </small>
            ))}
          </>
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
