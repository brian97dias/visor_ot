import { useEffect, useState } from "react";
import { Link, useLocation, useOutletContext, useParams } from "react-router-dom";

import { getAsset } from "../api/assets";
import {
  canEditAssets,
  CRITICALITY_LABELS,
  displayCost,
  displayValue,
  ROLE_LABELS,
} from "../utils/assetPermissions";

function Field({ label, value }) {
  return (
    <div>
      <span>{label}</span>
      <strong>{displayValue(value)}</strong>
    </div>
  );
}

function AssetDetail() {
  const { assetId } = useParams();
  const { user } = useOutletContext();
  const location = useLocation();
  const [asset, setAsset] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    setError("");
    getAsset(assetId)
      .then((data) => { if (active) setAsset(data); })
      .catch((err) => { if (active) setError(err.message); });
    return () => { active = false; };
  }, [assetId]);

  if (error && !asset) {
    return <section className="page">
      <div className="error-message">{error}</div>
      <Link className="button-link" to="/assets">Volver al inventario</Link>
    </section>;
  }

  if (!asset) {
    return <section className="page">Cargando activo...</section>;
  }

  return (
    <section className="page">
      <div className="breadcrumbs">
        <span>Activos</span>
        <span>/</span>
        <Link to="/assets">Inventario</Link>
        <span>/</span>
        <span>#{asset.id}</span>
      </div>

      <header className="page-header assets-page-heading">
        <div>
          <span className="page-eyebrow">ACTIVO #{asset.id}</span>
          <h1>{asset.name}</h1>
          <p>{asset.description || "Sin descripción registrada."}</p>
        </div>
        {canEditAssets(user) && (
          <Link className="button-primary assets-primary-link"
            to={"/assets/" + asset.id + "/edit"}>
            Editar activo
          </Link>
        )}
      </header>

      {location.state?.notice && (
        <div className="success-message">{location.state.notice}</div>
      )}

      <section className="panel assets-detail-section">
        <div className="panel-header"><h2>Información general</h2></div>
        <div className="assets-detail-grid">
          <Field label="Tipo de activo" value={asset.asset_type === "HARDWARE" ? "Hardware" : "Software"} />
          <Field label="Criticidad" value={CRITICALITY_LABELS[asset.criticality] || asset.criticality} />
          <Field label="Impacto de indisponibilidad" value={asset.impact} />
          <Field label="Costo de reposición" value={displayCost(asset)} />
        </div>
      </section>

      {asset.hardware && (
        <section className="panel assets-detail-section">
          <div className="panel-header"><h2>Datos del hardware</h2></div>
          <div className="assets-detail-grid">
            <Field label="Fabricante" value={asset.hardware.manufacturer} />
            <Field label="Modelo / familia" value={asset.hardware.model} />
            <Field label="Rol" value={ROLE_LABELS[asset.hardware.role] || asset.hardware.role} />
            <Field label="Número de serie" value={asset.hardware.serial_number} />
            <Field label="Ubicación física" value={asset.hardware.physical_location} />
          </div>
        </section>
      )}

      <section className="panel assets-detail-section">
        <div className="panel-header"><h2>Registro y auditoría</h2></div>
        <div className="assets-detail-grid">
          <Field label="Creado por" value={asset.created_by} />
          <Field label="Última edición por" value={asset.updated_by} />
          <Field label="Creado el" value={new Date(asset.created_at).toLocaleString("es-CO")} />
          <Field label="Actualizado el" value={new Date(asset.updated_at).toLocaleString("es-CO")} />
        </div>
      </section>
    </section>
  );
}

export default AssetDetail;
