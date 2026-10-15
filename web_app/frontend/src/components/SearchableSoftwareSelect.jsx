import { useEffect, useId, useRef, useState } from "react";

function normalize(value) {
  return String(value ?? "").toLocaleLowerCase("es-CO").replace(/\s+/g, "");
}

export function matchesSoftware(item, query) {
  const name = [
    item.name, item.software?.manufacturer, item.software?.product,
    item.software?.version, item.software?.software_type,
  ].filter(Boolean).join(" ");
  return normalize(name).includes(normalize(query));
}

export function softwareLabel(item) {
  return [item.name, item.software?.product, item.software?.version || "Versión desconocida"]
    .filter(Boolean).join(" · ");
}

/** One search + dropdown for known software assets. All controls are type=button
 * so they never submit the surrounding hardware edit form.
 */
export default function SearchableSoftwareSelect({
  options, selectedId, onChange, disabled = false,
}) {
  const id = useId();
  const rootRef = useRef(null);
  const [query, setQuery] = useState("");
  const [opened, setOpened] = useState(false);
  const [highlighted, setHighlighted] = useState(0);

  const chosen = options.find((item) => item.id === selectedId);
  const matches = options.filter((item) => matchesSoftware(item, query)).slice(0, 75);

  // Close on outside clicks without swallowing option selection.
  useEffect(() => {
    if (!opened) return undefined;
    const onPointerDown = (event) => {
      if (!rootRef.current?.contains(event.target)) setOpened(false);
    };
    document.addEventListener("pointerdown", onPointerDown);
    return () => document.removeEventListener("pointerdown", onPointerDown);
  }, [opened]);

  function select(item) {
    onChange(item.id);
    setQuery(softwareLabel(item));
    setOpened(false);
    setHighlighted(0);
  }

  function onTextChange(value) {
    setQuery(value);
    onChange(null);
    setOpened(true);
    setHighlighted(0);
  }

  return (
    <div className="software-combobox" ref={rootRef}>
      <label htmlFor={id + "-input"}>Seleccionar software existente</label>
      <div className="software-combobox-input">
        <input id={id + "-input"} type="text" autoComplete="off"
          role="combobox" aria-autocomplete="list"
          aria-expanded={opened} aria-controls={id + "-list"}
          aria-activedescendant={opened && matches[highlighted]
            ? id + "-option-" + matches[highlighted].id : undefined}
          disabled={disabled}
          value={query} placeholder="Buscar o desplegar software..."
          onFocus={() => {
            if (!disabled) {
              if (chosen && query === softwareLabel(chosen)) {
                setQuery("");
              }
              setOpened(true);
            }
          }}
          onChange={(event) => onTextChange(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Escape") { setOpened(false); return; }
            if (event.key === "ArrowDown") {
              event.preventDefault();
              setOpened(true);
              setHighlighted((current) => Math.min(current + 1, matches.length - 1));
            }
            if (event.key === "ArrowUp") {
              event.preventDefault();
              setHighlighted((current) => Math.max(0, current - 1));
            }
            if (event.key === "Enter" && opened && matches[highlighted]) {
              event.preventDefault();
              select(matches[highlighted]);
            }
          }}
        />
        <button type="button" disabled={disabled}
          aria-label={opened ? "Cerrar opciones" : "Mostrar todo el software"}
          onClick={() => {
            setQuery("");
            setHighlighted(0);
            setOpened(!opened);
          }}>
          <span aria-hidden="true">▾</span>
        </button>
      </div>
      {chosen && !opened && (
        <p className="interface-hint">Seleccionado: {softwareLabel(chosen)}</p>
      )}
      {opened && (
        <div className="software-combobox-options" id={id + "-list"}
          role="listbox" aria-label="Software registrado">
          {matches.length ? matches.map((item, i) => (
            <button key={item.id} type="button" role="option"
              id={id + "-option-" + item.id}
              aria-selected={selectedId === item.id}
              className={i === highlighted ? "software-combobox-highlight" : ""}
              onMouseEnter={() => setHighlighted(i)}
              onClick={() => select(item)}>
              <span>{item.name}</span>
              <small>{item.software?.manufacturer || "Fabricante desconocido"} · {item.software?.product} · {item.software?.version || "Versión desconocida"}</small>
            </button>
          )) : (
            <p className="interface-hint software-combobox-empty">No hay software que coincida.</p>
          )}
        </div>
      )}
    </div>
  );
}
