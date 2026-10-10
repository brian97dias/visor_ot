import { useEffect, useState } from "react";
import { Link, useNavigate, useOutletContext, useParams } from "react-router-dom";

import { createAsset, getAsset, updateAsset } from "../api/assets";
import AssetForm from "../components/AssetForm";
import { canCreateAssets, canEditAssets } from "../utils/assetPermissions";

function AssetEditor() {
  const { assetId } = useParams();
  const editing = Boolean(assetId);
  const { user } = useOutletContext();
  const navigate = useNavigate();
  const allowed = editing ? canEditAssets(user) : canCreateAssets(user);

  const [asset, setAsset] = useState(null);
  const [loading, setLoading] = useState(editing);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!editing || !allowed) return;
    let active = true;
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
      navigate("/assets/" + saved.id, {
        state: {
          notice: editing ? "Activo actualizado correctamente." : "Activo registrado correctamente.",
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

  if (editing && !asset) {
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
        key={editing ? asset.id : "new"}
        asset={asset}
        user={user}
        onSave={save}
        saving={saving}
        error={error}
      />
    </section>
  );
}

export default AssetEditor;
