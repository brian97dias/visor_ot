/** Group per-MAC evidence for display, never for identity resolution. */
export function groupEndpointCandidates(candidates = []) {
  const assets = new Map();
  const unassignedMacs = new Set();

  for (const candidate of Array.isArray(candidates) ? candidates : []) {
    if (!candidate || typeof candidate !== "object") continue;
    if (candidate.asset_id != null && candidate.asset_name) {
      if (!assets.has(candidate.asset_id)) {
        assets.set(candidate.asset_id, {
          asset_id: candidate.asset_id,
          asset_name: candidate.asset_name,
        });
      }
    } else if (candidate.mac) {
      unassignedMacs.add(candidate.mac);
    }
  }

  return {
    assets: [...assets.values()],
    unassignedMacs: [...unassignedMacs].sort(),
  };
}
