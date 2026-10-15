import { useEffect, useMemo, useState } from "react";

import { getAssets } from "../api/assets";

function normalize(text) {
  return String(text || "").toLocaleLowerCase("es-CO").replace(/\s+/g, "");
}

/**
 * Select zero, one, or two *real* hardware IDs. Chips are filter state, not
 * a persistent search history. The API will independently validate the IDs.
 */
export default function DeviceFilter({ selected, onChange }) {
  const [devices, setDevices] = useState([]);
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    getAssets("ACTIVE")
      .then((assets) => {
        if (active) {
          setDevices(
            assets
              .filter((asset) => asset.asset_type === "HARDWARE" && asset.hardware)
              .sort((a, b) => a.name.localeCompare(b.name, "es"))
          );
        }
      })
      .catch((err) => { if (active) setError(err.message); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, []);

  const selectedIds = selected.map((device) => device.id);
  const choices = useMemo(() => {
    const token = normalize(query);
    if (!token || selected.length >= 2) return [];
    return devices
      .filter((device) => !selectedIds.includes(device.id))
      .filter((device) => normalize([
        device.name,
        device.hardware?.manufacturer,
        device.hardware?.model,
      ].filter(Boolean).join(" ")).includes(token))
      .slice(0, 8);
  }, [devices, selected, query]);

  function add(device) {
    if (selected.length >= 2 || selectedIds.includes(device.id)) return;
    onChange([...selected, {
      id: device.id,
      name: device.name,
      role: device.hardware?.role || "Hardware",
    }]);
    setQuery("");
  }

  function remove(id) {
    onChange(selected.filter((device) => device.id !== id));
  }

  return (
    <div className="device-filter-section">
      <div className="device-filter-heading">
        <div>
          <label htmlFor="communication-device-filter">Filtrar por dispositivos</label>
          <p>Selecciona hasta dos hardware para ver sus comunicaciones, sin importar la dirección.</p>
        </div>
        {selected.length > 0 && (
          <button className="device-filter-clear" type="button"
            onClick={() => { onChange([]); setQuery(""); }}>
            Quitar filtros
          </button>
        )}
      </div>

      <div className="device-filter-tags" aria-label="Dispositivos seleccionados">
        {selected.map((device) => (
          <span className="device-filter-tag" key={device.id}>
            <span>{device.name}</span>
            <button type="button" className="device-filter-tag-remove"
              aria-label={"Quitar filtro de " + device.name}
              title={"Quitar " + device.name}
              onClick={() => remove(device.id)}>×</button>
          </span>
        ))}
      </div>

      <div className="device-filter-input-wrap">
        <input id="communication-device-filter" type="search"
          role="combobox" aria-expanded={choices.length > 0}
          aria-controls="communication-device-options"
          aria-autocomplete="list"
          placeholder={selected.length === 2
            ? "Máximo dos dispositivos seleccionados"
            : "Escribe DirectLogic, Phoenix Contact o ADAM..."}
          value={query} disabled={loading || selected.length >= 2}
          onChange={(event) => setQuery(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Enter" && choices.length > 0) {
              event.preventDefault();
              add(choices[0]);
            }
            if (event.key === "Escape") setQuery("");
          }} />
        {query.trim() && selected.length < 2 && (
          <div id="communication-device-options" className="device-filter-options"
            role="listbox" aria-label="Dispositivos coincidentes">
            {choices.length ? choices.map((device) => (
              <button type="button" key={device.id}
                className="device-filter-option"
                role="option" aria-selected={false}
                onClick={() => add(device)}>
                <span>{device.name}</span>
                <small>{device.hardware?.role || "Hardware"}</small>
              </button>
            )) : (
              <p className="device-filter-none">Sin hardware coincidente.</p>
            )}
          </div>
        )}
      </div>

      {loading && <p className="device-filter-help">Cargando hardware del inventario...</p>}
      {error && <p className="error-message" role="alert">{error}</p>}
      {!loading && !error && devices.length === 0 && (
        <p className="device-filter-help">No hay hardware activo en el inventario.</p>
      )}
      <p className="device-filter-help">
        {selected.length === 0
          ? "Sin dispositivos seleccionados: se aplica la búsqueda habitual."
          : selected.length === 1
            ? "Se mostrarán comunicaciones donde participe ese hardware como origen o destino."
            : "Se mostrarán únicamente comunicaciones entre ambos hardware, en cualquiera de los dos sentidos."}
        {" "}El buscador general y los demás filtros se combinan con esta selección.
      </p>
    </div>
  );
}
