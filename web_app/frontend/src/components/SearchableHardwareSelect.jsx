import { useEffect, useId, useRef, useState } from "react";

import { hardwareLabel, matchesHardware } from "../utils/hardwareAssociationSearch";

/** Searchable dropdown for existing hardware, with no nested forms. */
export default function SearchableHardwareSelect({
  options, selectedId, onChange, disabled = false,
}) {
  const id = useId();
  const rootRef = useRef(null);
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState(false);
  const [highlighted, setHighlighted] = useState(0);

  const selected = selectedId == null ? null
    : options.find((item) => Number(item.id) === Number(selectedId));
  const matches = options.filter((item) => matchesHardware(item, query)).slice(0, 75);

  useEffect(() => {
    if (!open) return undefined;
    function closeOnOutside(event) {
      if (!rootRef.current?.contains(event.target)) setOpen(false);
    }
    document.addEventListener("pointerdown", closeOnOutside);
    return () => document.removeEventListener("pointerdown", closeOnOutside);
  }, [open]);

  function choose(item) {
    onChange(item.id);
    setQuery(hardwareLabel(item));
    setOpen(false);
    setHighlighted(0);
  }

  return (
    <div className="software-combobox" ref={rootRef}>
      <label htmlFor={id + "-input"}>Buscar y seleccionar hardware existente</label>
      <div className="software-combobox-input">
        <input id={id + "-input"} type="text" autoComplete="off" disabled={disabled}
          role="combobox" aria-autocomplete="list"
          aria-expanded={open} aria-controls={id + "-list"}
          aria-activedescendant={open && matches[highlighted]
            ? id + "-choice-" + matches[highlighted].id : undefined}
          placeholder="Nombre, fabricante, modelo o rol..."
          value={query}
          onFocus={() => {
            if (disabled) return;
            if (selected && query === hardwareLabel(selected)) setQuery("");
            setOpen(true);
          }}
          onChange={(event) => {
            setQuery(event.target.value);
            onChange(null);
            setHighlighted(0);
            setOpen(true);
          }}
          onKeyDown={(event) => {
            if (event.key === "Escape") {
              setOpen(false);
            } else if (event.key === "ArrowDown") {
              event.preventDefault();
              setOpen(true);
              if (matches.length) {
                setHighlighted((current) => Math.min(current + 1, matches.length - 1));
              }
            } else if (event.key === "ArrowUp") {
              event.preventDefault();
              setHighlighted((current) => Math.max(0, current - 1));
            } else if (event.key === "Enter") {
              // Prevent submitting the parent Edit Software form.
              event.preventDefault();
              if (open && matches[highlighted]) choose(matches[highlighted]);
            }
          }}
        />
        <button type="button" disabled={disabled}
          aria-label={open ? "Cerrar opciones" : "Mostrar todos los hardware"}
          onClick={() => { setQuery(""); setHighlighted(0); setOpen((value) => !value); }}>
          <span aria-hidden="true">▾</span>
        </button>
      </div>
      {selected && !open && (
        <p className="interface-hint">Seleccionado: {hardwareLabel(selected)}</p>
      )}
      {open && (
        <div className="software-combobox-options" id={id + "-list"}
          role="listbox" aria-label="Hardware disponible">
          {matches.length ? matches.map((item, index) => (
            <button type="button" key={item.id}
              role="option" id={id + "-choice-" + item.id}
              aria-selected={Number(selectedId) === Number(item.id)}
              className={index === highlighted ? "software-combobox-highlight" : ""}
              onMouseEnter={() => setHighlighted(index)}
              onClick={() => choose(item)}>
              <span>{item.name}</span>
              <small>
                {item.hardware?.manufacturer || "Fabricante sin registrar"} ·{" "}
                {item.hardware?.model || item.hardware?.role || "Hardware"}
              </small>
            </button>
          )) : (
            <p className="interface-hint software-combobox-empty">
              No se encontraron hardware coincidentes.
            </p>
          )}
        </div>
      )}
    </div>
  );
}
