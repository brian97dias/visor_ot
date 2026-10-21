import { nvdQueryUrl } from "../utils/nvdLinks";
import {
  groupCpeQueries, levelName, resultLabel, reasonLabel, queryStatusLabel, queryDescription,
} from "../utils/cpeDiscoveryPresentation";

/** Read-only view of JSON persisted by the worker; NVD is not called here. */
export default function CpeDiscoveryTrace({ queries, truncated }) {
  const groups = groupCpeQueries(queries);
  return <section className="cpe-trace" aria-labelledby="cpe-trace-heading">
    <h3 id="cpe-trace-heading">Recorrido de descubrimiento</h3>
    <p className="cpe-trace-muted">Las consultas están agrupadas por nivel. Los registros
      recuperados pueden repetirse entre búsquedas; no representan CPE únicos.</p>
    {groups.length === 0 && <p className="cpe-trace-muted">Sin consultas registradas todavía.</p>}
    {groups.map((group, index) => <details className="cpe-trace-level"
      key={group.level + "-" + index} open={index === groups.length - 1}>
      <summary>
        <strong>{levelName(group.level)}</strong>
        <span>{group.queries.length} consultas
          {group.hasPages && " · " + group.pages + " páginas"}
          {group.hasRetrieved && " · " + group.retrieved + " registros NVD"}</span>
        {group.result === "PARTIAL_RESULTS" && <em>Parcial</em>}
        {group.status === "FAILED" && <em>Error</em>}
      </summary>
      <div className="cpe-trace-detail">
        {group.level === "LEGACY" && <p className="cpe-trace-muted">
          Registro histórico sin niveles: no se puede reconstruir su evaluación.</p>}
        {group.level === "ADVANCED" && group.queries[0] && <p>
          <strong>Tramo solicitado:</strong> página inicial {
            Number(group.queries[0].start_index || 0) / 100 + 1
          } · máximo {group.queries[0].max_pages || 1} página(s).
        </p>}
        {group.result && <p><strong>Evaluación:</strong> {resultLabel(group.result)}</p>}
        {group.nextReason && <p><strong>Ampliación:</strong> {reasonLabel(group.nextReason)}</p>}
        {group.stopReason && <p><strong>Límite:</strong> {reasonLabel(group.stopReason)}</p>}
        {group.uniqueCandidates !== null && <p>
          <strong>Candidatos únicos observados en este nivel:</strong> {group.uniqueCandidates}
          {group.pertinentCandidates !== null &&
            " · Correspondencias suficientes: " + group.pertinentCandidates}
        </p>}
        <div className="cpe-trace-queries">
          {group.queries.map((q, i) => {
            const pages = Number(q.pages);
            const url = Number.isFinite(pages) && pages > 0 ? nvdQueryUrl(q) : null;
            return <div className="cpe-trace-query" key={i}>
              <div className="cpe-trace-query-title">
                <strong>{q.strategy || "Consulta histórica"}</strong>
                <span data-status={q.status || ""}>{queryStatusLabel(q.status)}</span>
              </div>
              <p>{queryDescription(q)}</p>
              <div className="cpe-trace-parameter">
                {url ? <a href={url} target="_blank" rel="noopener noreferrer">
                    <code>{q.parameter}</code> ↗
                  </a> : <code>{q.parameter || "Parámetro no registrado"}</code>}
              </div>
              {Number.isFinite(pages) && pages > 1 && <div className="cpe-query-links">
                {Array.from({length: Math.min(pages, 3) - 1}, (_, p) =>
                  <a key={p} href={nvdQueryUrl(q, p + 1)} target="_blank"
                    rel="noopener noreferrer">NVD página {p + 2} ↗</a>)}
              </div>}
              <div className="cpe-trace-metrics">
                {q.retrieved != null && <span>{q.retrieved} registros recibidos</span>}
                {q.hardware_results != null && q.hardware_results > 0 &&
                  <span>{q.hardware_results} hardware procesados</span>}
                {q.software_results != null &&
                  <span>{q.software_results} software procesados</span>}
                {q.filtered_hardware_results > 0 &&
                  <span>{q.filtered_hardware_results} descartados por pertinencia</span>}
                {q.related_results > 0 && <span>{q.related_results} relacionados</span>}
                {q.exploratory_results > 0 && <span>
                  {q.exploratory_results} correspondencias exploratorias
                </span>}
                {q.pertinent_results > 0 && <span>{q.pertinent_results} pertinentes</span>}
              </div>
              {q.stop_reason && <p className="cpe-trace-stop">
                {reasonLabel(q.stop_reason)}</p>}
            </div>;
          })}
        </div>
      </div>
    </details>)}
    {truncated && <p className="cpe-trace-warning">
      Exploración incompleta: los resultados no permiten descartar la existencia de otros CPE.
    </p>}
    <p className="cpe-trace-muted">Los enlaces consultan NVD actualmente; su respuesta puede
      haber cambiado respecto de la búsqueda registrada.</p>
  </section>;
}
