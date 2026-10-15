import { useEffect, useState } from "react";
import { getInterfaces } from "../api/interfaces";

export default function InterfaceSelector({
  value, onChange, disabled = false,
}) {
  const [mode, setMode] = useState("EXISTING");
  const [query, setQuery] = useState("");
  const [search, setSearch] = useState("");
  const [entries, setEntries] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    const handle = setTimeout(() => setSearch(query.trim()), 300);
    return () => clearTimeout(handle);
  }, [query]);

  useEffect(() => {
    if (mode !== "EXISTING") return;
    let active = true;
    setLoading(true);
    setError("");
    getInterfaces({ search, identification: "UNIDENTIFIED" })
      .then((data) => { if (active) setEntries(data.results); })
      .catch((err) => { if (active) setError(err.message); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [mode, search]);

  function changeMode(next) {
    setMode(next);
    onChange(next === "MANUAL"
      ? { mode: "MANUAL", mac: "", declared_ip: "" }
      : null);
  }

  return (
    <div className="interface-selector">
      <div className="interface-mode-switch" role="group" aria-label="Método de asociación">
        <button type="button" className={mode === "EXISTING" ? "selected" : ""}
          disabled={disabled} onClick={() => changeMode("EXISTING")}>
          Asociar existente
        </button>
        <button type="button" className={mode === "MANUAL" ? "selected" : ""}
          disabled={disabled} onClick={() => changeMode("MANUAL")}>
          Registrar manualmente
        </button>
      </div>

      {mode === "EXISTING" ? (
        <div className="interface-selector-content">
          <label htmlFor="interface-search">Buscar MAC o IP observada</label>
          <input id="interface-search" type="search"
            placeholder="Ej. 192.168.88.15 o 00:e0:62..."
            value={query} disabled={disabled}
            onChange={(event) => setQuery(event.target.value)} />
          {error && <p className="error-message">{error}</p>}
          {loading ? <p className="interface-hint">Buscando interfaces...</p> : (
            <div className="interface-candidates">
              {entries.length === 0 && <p className="interface-hint">Sin coincidencias disponibles.</p>}
              {entries.map((entry) => (
                <button type="button" key={entry.id} disabled={disabled}
                  className={value?.mode === "EXISTING" && value.interface_id === entry.id
                    ? "interface-candidate selected" : "interface-candidate"}
                  onClick={() => onChange({ mode: "EXISTING", interface_id: entry.id })}>
                  <strong>{entry.mac || "Sin MAC"}</strong>
                  <span>{[...new Set([...(entry.observed_ips || []),
                    entry.declared_ip].filter(Boolean))].join(", ") || "Sin IP"}</span>
                  <small>{entry.has_active_evidence ? "Evidencia activa" : "Sin evidencia activa"}</small>
                </button>
              ))}
            </div>
          )}
          {value?.mode === "EXISTING" && (
            <div className="interface-selection-note">
              Interfaz #{value.interface_id} seleccionada.
              <button type="button" disabled={disabled} onClick={() => onChange(null)}>
                Quitar selección
              </button>
            </div>
          )}
        </div>
      ) : (
        <div className="interface-selector-content">
          <label htmlFor="interface-manual-mac">MAC (opcional)</label>
          <input id="interface-manual-mac" maxLength={17} disabled={disabled}
            placeholder="00:11:22:33:44:55" value={value?.mac || ""}
            onChange={(event) => onChange({
              mode: "MANUAL", mac: event.target.value,
              declared_ip: value?.declared_ip || "",
            })} />
          <label htmlFor="interface-manual-ip">IP declarada (opcional)</label>
          <input id="interface-manual-ip" disabled={disabled}
            placeholder="192.168.88.15" value={value?.declared_ip || ""}
            onChange={(event) => onChange({
              mode: "MANUAL", mac: value?.mac || "",
              declared_ip: event.target.value,
            })} />
          <p className="interface-hint">Indica una MAC o una IP. La IP declarada no se trata como evidencia del PCAP.</p>
        </div>
      )}
    </div>
  );
}
