/** Present CPE statistics already computed by the backend (no duplicated state logic). */
export function cpeCountDetails(row) {
  const number = value => Number.isFinite(Number(value))
    ? Math.max(0, Number(value)) : 0;
  return [
    { key: "confirmed", count: number(row?.confirmed_count), label: "confirmados" },
    { key: "rejected", count: number(row?.rejected_count), label: "rechazados" },
    { key: "unreviewed", count: number(row?.unreviewed_count), label: "por revisar" },
  ];
}

/** Provenance is descriptive, never an extra amount added to overall totals. */
export function cpeManualDecisionDetails(row) {
  const number = value => Number.isFinite(Number(value))
    ? Math.max(0, Number(value)) : 0;
  const confirmed = number(row?.manual_confirmed_count);
  const rejected = number(row?.manual_rejected_count);
  return confirmed || rejected ? { confirmed, rejected } : null;
}
