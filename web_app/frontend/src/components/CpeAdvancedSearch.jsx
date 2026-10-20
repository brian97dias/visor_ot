import { useState } from "react";

/** The HTTP request only enqueues; NVD queries run exclusively in the worker. */
export default function CpeAdvancedSearch({ asset, busy, onStart }) {
  const manufacturer = asset.hardware?.manufacturer || "";
  const [expanded, setExpanded] = useState(false);
  const [strategy, setStrategy] = useState("keywordSearch");
  const [parameter, setParameter] = useState(manufacturer);
  const [startPage, setStartPage] = useState("1");
  const [pageCount, setPageCount] = useState("1");
  const [formError, setFormError] = useState("");

  function selectStrategy(value) {
    setStrategy(value);
    setParameter(value === "keywordSearch" ? manufacturer : "");
    setFormError("");
  }
  function submit(event) {
    event.preventDefault();
    const first = Number(startPage);
    const pages = Number(pageCount);
    if (!Number.isInteger(first) || first < 1 || first > 101 ||
        !Number.isInteger(pages) || pages < 1 || pages > 3) {
      setFormError("Selecciona una página inicial entre 1 y 101 y entre 1 y 3 páginas por búsqueda.");
      return;
    }
    if (!parameter.trim()) {
      setFormError("Ingresa un parámetro de búsqueda.");
      return;
    }
    setFormError("");
    onStart({
      strategy, parameter: parameter.trim(),
      start_index: (first - 1) * 100, max_pages: pages,
    });
  }
  return <section className="cpe-advanced" aria-labelledby="cpe-advanced-heading">
    <button className="button-secondary" type="button"
      aria-expanded={expanded} aria-controls="cpe-advanced-content"
      disabled={busy} onClick={() => setExpanded(v => !v)}>
      {expanded ? "Ocultar búsqueda avanzada" : "Búsqueda avanzada"}
    </button>
    {expanded && <div id="cpe-advanced-content" className="cpe-advanced-content">
      <h2 id="cpe-advanced-heading">Búsqueda avanzada en NVD</h2>
      <p>Investiga variantes de nombre o continúa desde otra página.
        La búsqueda se encola y pasa por el mismo worker. Ningún CPE queda confirmado automáticamente.</p>
      <form onSubmit={submit} className="cpe-advanced-form">
        <label htmlFor="cpe-advanced-strategy">Estrategia</label>
        <select id="cpe-advanced-strategy" value={strategy} disabled={busy}
          onChange={event => selectStrategy(event.target.value)}>
          <option value="keywordSearch">keywordSearch · texto</option>
          <option value="cpeMatchString">cpeMatchString · prefijo CPE</option>
        </select>
        <label htmlFor="cpe-advanced-parameter">Parámetro enviado a NVD</label>
        <input id="cpe-advanced-parameter" value={parameter} maxLength={160}
          disabled={busy} onChange={event => setParameter(event.target.value)}
          placeholder={strategy === "keywordSearch" ? "Ej.: Rockwell o Siemens CPU" :
            "Ej.: cpe:2.3:h:rockwellautomation:1783*"} required />
        <p className="cpe-advanced-hint">
          {strategy === "keywordSearch"
            ? "Incluye una palabra del fabricante. Ejemplo: Rockwell, Siemens o AXIS 206."
            : "Usa solo CPE de hardware (h) con un identificador conocido del fabricante. Ej.: cpe:2.3:h:rockwellautomation:1783*."}
        </p>
        <div className="cpe-advanced-grid">
          <div>
            <label htmlFor="cpe-advanced-start">Página inicial de NVD</label>
            <input id="cpe-advanced-start" type="number" inputMode="numeric"
              min="1" max="101" step="1" value={startPage} disabled={busy}
              onChange={event => setStartPage(event.target.value)} required/>
          </div>
          <div>
            <label htmlFor="cpe-advanced-pages">Páginas por solicitud</label>
            <select id="cpe-advanced-pages" value={pageCount} disabled={busy}
              onChange={event => setPageCount(event.target.value)}>
              <option value="1">1 (hasta 100 registros)</option>
              <option value="2">2 (hasta 200 registros)</option>
              <option value="3">3 (hasta 300 registros)</option>
            </select>
          </div>
        </div>
        <p className="cpe-advanced-hint">
          Cada página contiene hasta 100 registros. Si comienzas en una página posterior,
          VISOR OT informa que solo examinaste una parte del catálogo.
          Las coincidencias se contrastan con la identidad inventariada.
        </p>
        {formError && <p className="error-message" role="alert">{formError}</p>}
        <div className="cpe-tools">
          <button className="button-primary" type="submit" disabled={busy}>
            {busy ? "Encolando..." : "Encolar búsqueda avanzada"}
          </button>
        </div>
      </form>
    </div>}
  </section>;
}
