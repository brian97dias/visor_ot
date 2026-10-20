/** Pure selection helpers: selection survives filtering and pagination. */
export function toggleRowSelection(selected, assetId, checked) {
  const ids = new Set(selected);
  if (checked) ids.add(assetId);
  else ids.delete(assetId);
  return [...ids];
}

export function togglePageSelection(selected, pageIds, checked) {
  const ids = new Set(selected);
  for (const id of pageIds) {
    if (checked) ids.add(id);
    else ids.delete(id);
  }
  return [...ids];
}

export function countSelectedTypes(rows) {
  return {
    hardware: rows.filter(row => row.asset_type === "HARDWARE").length,
    software: rows.filter(row => row.asset_type === "SOFTWARE").length,
  };
}
