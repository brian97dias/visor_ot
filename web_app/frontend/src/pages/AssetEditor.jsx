import { useEffect, useState } from "react";
import { Link, useNavigate, useOutletContext, useParams, useSearchParams } from "react-router-dom";

import { createAsset, getAsset, updateAsset } from "../api/assets";
import AssetForm from "../components/AssetForm";
import { canCreateAssets, canEditAssets } from "../utils/assetPermissions";

function AssetEditor() {
  const { assetId } = useParams();
  const editing = Boolean(assetId);
  const { user } = useOutletContext();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const initialType = searchParams.get("type") === "SOFTWARE" ? "SOFTWARE" : "HARDWARE";
  const initialHardwareId = searchParams.get("hardware_id") || "";
  const returnToHardware = searchParams.get("from") === "hardware";
  const allowed = editing ? canEditAssets(user) : canCreateAssets(user);

  const [asset, setAsset] = useState(null);
  const [loading, setLoading] = useState(editing);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    // React Router keeps this page mounted between /assets/:id/edit and
    // /assets/new. Never reuse the previous hardware in a new Software form.
    if (!editing) {
      setAsset(null);
      setLoading(false);
      setError("");
      return;
    }
    if (!allowed) return;
    let active = true;
    setAsset(null);
    setLoading(true);
    setError("");
    getAsset(assetId)
      .then((data) => { if (active) setAsset(data); })
      .catch((err) => { if (active) setError(err.message); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [assetId, editing, allowed]);

  async function save(payload) {
    setError("");
    setSaving(true);
    try {
      if (editing && Object.keys(payload).length === 0) {
        navigate("/assets/" + assetId);
        return;
      }
      const saved = editing
        ? await updateAsset(assetId, payload)
        : await createAsset(payload);
      const returnTo = !editing && saved.asset_type === "SOFTWARE"
        && returnToHardware ? payload.hardware_asset_id : null;
      navigate(returnTo ? "/assets/" + returnTo : "/assets/" + saved.id, {
        state: {
          notice: returnTo
            ? "Software registrado e instalado correctamente."
            : editing ? "Activo actualizado correctamente." : "Activo registrado correctamente.",
        },
      });
    } catch (err) {
      setError(err.message);
    } finally {
      setSaving(false);
    }
  }

  if (!allowed) {
    return (
      <section className="page">
        <div className="error-message">No tienes permiso para realizar esta operación.</div>
        <Link className="button-link" to="/assets">Volver al inventario</Link>
      </section>
    );
  }

  if (loading) return <section className="page">Cargando activo...</section>;

  if (editing && (!asset || String(asset.id) !== String(assetId))) {
    return (
      <section className="page">
        <div className="error-message">{error || "El activo no está disponible."}</div>
        <Link className="button-link" to="/assets">Volver al inventario</Link>
      </section>
    );
  }

  return (
    <section className="page">
      <div className="breadcrumbs">
        <span>Activos</span>
        <span>/</span>
        <Link to="/assets">Inventario</Link>
        <span>/</span>
        <span>{editing ? "Editar activo" : "Nuevo activo"}</span>
      </div>

      <header className="page-header">
        <span className="page-eyebrow">ACTIVOS</span>
        <h1>{editing ? "Editar activo" : "Nuevo activo"}</h1>
        <p>{editing
          ? "Actualiza los datos técnicos y administrativos del activo."
          : "Registra manualmente un nuevo activo OT."}</p>
      </header>
      <AssetForm
        key={editing ? "edit-" + asset.id : "new-" + initialType + "-" + initialHardwareId}
        asset={editing ? asset : null}
        user={user}
        onSave={save}
        saving={saving}
        error={error}
        initialType={initialType}
        initialHardwareId={initialHardwareId}
      />
    </section>
  );
}

export default AssetEditor;
