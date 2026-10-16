/** Pure inventory filters. All filters combine with logical AND.
 * Link counts come from the existing GET /api/assets/ annotations.
 * A zero count means there is no *recorded association*, not that
 * hardware lacks firmware or network interfaces in reality.
 */
export const RELATIONSHIP_FILTERS = Object.freeze({
  HARDWARE: [
    { value: "ALL", label: "Todas las vinculaciones" },
    { value: "HAS_SOFTWARE", label: "Con software asociado" },
    { value: "NO_SOFTWARE", label: "Sin software asociado" },
    { value: "NO_INTERFACES", label: "Sin interfaces asociadas" },
  ],
  SOFTWARE: [
    { value: "ALL", label: "Todas las vinculaciones" },
    { value: "HAS_HARDWARE", label: "Con hardware asociado" },
    { value: "NO_HARDWARE", label: "Sin hardware asociado" },
  ],
});

function hasCount(asset, key) {
  return Number.isInteger(asset[key]) && asset[key] >= 0;
}

export function matchesRelationshipFilter(asset, assetType, relationshipFilter) {
  if (relationshipFilter === "ALL" || assetType === "ALL") return true;
  if (asset.asset_type !== assetType) return false;

  if (assetType === "HARDWARE") {
    if (relationshipFilter === "HAS_SOFTWARE") {
      return hasCount(asset, "software_count") && asset.software_count > 0;
    }
    if (relationshipFilter === "NO_SOFTWARE") {
      return hasCount(asset, "software_count") && asset.software_count === 0;
    }
    if (relationshipFilter === "NO_INTERFACES") {
      return hasCount(asset, "interface_count") && asset.interface_count === 0;
    }
  }
  if (assetType === "SOFTWARE") {
    if (relationshipFilter === "HAS_HARDWARE") {
      return hasCount(asset, "hardware_count") && asset.hardware_count > 0;
    }
    if (relationshipFilter === "NO_HARDWARE") {
      return hasCount(asset, "hardware_count") && asset.hardware_count === 0;
    }
  }
  return false;
}

export function filterInventoryAssets(assets, {
  assetType = "ALL",
  criticality = "ALL",
  relationshipFilter = "ALL",
  search = "",
} = {}) {
  const query = search.trim().toLowerCase();
  return assets.filter((asset) => {
    if (assetType !== "ALL" && asset.asset_type !== assetType) return false;
    if (criticality !== "ALL" && asset.criticality !== criticality) return false;
    if (!matchesRelationshipFilter(asset, assetType, relationshipFilter)) return false;

    const searchable = [
      asset.id, asset.name, asset.description, asset.asset_type,
      asset.hardware?.manufacturer, asset.hardware?.model,
      asset.hardware?.role, asset.software?.software_type,
      asset.software?.manufacturer, asset.software?.product,
      asset.software?.version,
    ].filter((value) => value !== null && value !== undefined)
      .join(" ").toLowerCase();
    return !query || searchable.includes(query);
  });
}
