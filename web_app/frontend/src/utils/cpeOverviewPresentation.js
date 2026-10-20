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
