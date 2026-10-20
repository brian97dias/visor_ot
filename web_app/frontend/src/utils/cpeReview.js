/** Keep candidate discovery separate from analyst-reviewed associations. */
export function unreviewedCpeCandidates(candidates = [], associations = []) {
  const reviewed = new Set(
    (associations || []).map(item => String(item.cpe_name_id || "").toLowerCase())
  );
  return (candidates || []).filter(candidate =>
    candidate?.cpe_name_id &&
    !reviewed.has(String(candidate.cpe_name_id).toLowerCase())
  );
}
