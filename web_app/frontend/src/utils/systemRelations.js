/** Group unique Software variants under each participating Hardware asset. */
export function groupSoftwareByHardware(variants) {
  const grouped = new Map();
  for (const variant of variants) {
    for (const host of variant.hardware || []) {
      const items = grouped.get(host.hardware_asset_id) || [];
      if (!items.some(item => item.software_asset_id === variant.software_asset_id)) {
        items.push(variant);
      }
      grouped.set(host.hardware_asset_id, items);
    }
  }
  return grouped;
}
