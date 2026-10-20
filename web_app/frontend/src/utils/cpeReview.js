/** Separate discovery results from human decisions without deleting evidence. */
const key = value => String(value || "").trim().toLowerCase();

export function reviewedCpeAssociations(associations = []) {
  return (associations || []).filter(a => a.validation_status !== "REOPENED");
}

export function unreviewedCpeCandidates(candidates = [], associations = []) {
  const reviewed = new Set(
    reviewedCpeAssociations(associations).map(item => key(item.cpe_name_id))
  );
  return (candidates || []).filter(candidate =>
    candidate?.cpe_name_id && !reviewed.has(key(candidate.cpe_name_id))
  );
}

/** Reopened CPEs without a match in the latest search remain visible. */
export function reopenedWithoutCurrentCandidate(candidates = [], associations = []) {
  const ids = new Set((candidates || []).map(c => key(c.cpe_name_id)));
  return (associations || []).filter(item =>
    item.validation_status === "REOPENED" && !ids.has(key(item.cpe_name_id))
  );
}
