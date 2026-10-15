/** Shared technical fields for software inventory forms (inline and full page). */
export const emptySoftwareFields = () => ({
  software_type: "FIRMWARE",
  manufacturer: "",
  product: "",
  version: "",
});

export default function SoftwareFields({ values, onChange, idPrefix = "software", disabled = false, required = true }) {
  return (
    <div className="assets-form-grid">
      <div className="assets-field assets-full-row">
        <label htmlFor={idPrefix + "-type"}>Tipo de software *</label>
        <select id={idPrefix + "-type"} required={required} disabled={disabled}
          value={values.software_type}
          onChange={(event) => onChange("software_type", event.target.value)}>
          <option value="FIRMWARE">Firmware</option>
          <option value="OS">Sistema operativo</option>
          <option value="APPLICATION">Aplicación</option>
        </select>
      </div>
      <div className="assets-field">
        <label htmlFor={idPrefix + "-manufacturer"}>Fabricante</label>
        <input id={idPrefix + "-manufacturer"} maxLength={200} disabled={disabled}
          value={values.manufacturer}
          onChange={(event) => onChange("manufacturer", event.target.value)}
          placeholder="Ej. Siemens, Advantech" />
      </div>
      <div className="assets-field">
        <label htmlFor={idPrefix + "-product"}>Producto *</label>
        <input id={idPrefix + "-product"} required={required} maxLength={200} disabled={disabled}
          value={values.product}
          onChange={(event) => onChange("product", event.target.value)}
          placeholder="Ej. TIA Portal, Firmware ADAM" />
      </div>
      <div className="assets-field assets-full-row">
        <label htmlFor={idPrefix + "-version"}>Versión</label>
        <input id={idPrefix + "-version"} maxLength={100} disabled={disabled}
          value={values.version}
          onChange={(event) => onChange("version", event.target.value)}
          placeholder="Opcional / desconocida" />
      </div>
    </div>
  );
}
