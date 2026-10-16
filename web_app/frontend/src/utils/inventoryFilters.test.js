import assert from "node:assert/strict";
import { test } from "node:test";
import {
  filterInventoryAssets,
  matchesRelationshipFilter,
  RELATIONSHIP_FILTERS,
} from "./inventoryFilters.js";

const inventory = [
  { id: 1, name: "DirectLogic 205", asset_type: "HARDWARE",
    criticality: "MEDIUM", software_count: 1, interface_count: 1,
    hardware: { manufacturer: "AutomationDirect", model: "DL205", role: "PLC" } },
  { id: 2, name: "AXIS 206", asset_type: "HARDWARE",
    criticality: "LOW", software_count: 0, interface_count: 1,
    hardware: { manufacturer: "Axis", model: "206", role: "OTHER" } },
  { id: 3, name: "Siemens PLC", asset_type: "HARDWARE",
    criticality: "HIGH", software_count: 0, interface_count: 0,
    hardware: { manufacturer: "Siemens", model: "S7-1200", role: "PLC" } },
  { id: 4, name: "Firmware DL205", asset_type: "SOFTWARE",
    criticality: "MEDIUM", hardware_count: 1,
    software: { manufacturer: "AutomationDirect", product: "DL205", version: "1.0" } },
  { id: 5, name: "Firmware sin instalar", asset_type: "SOFTWARE",
    criticality: "UNDEFINED", hardware_count: 0,
    software: { manufacturer: "Test", product: "No instalado" } },
];
const ids = (items) => items.map((x) => x.id);

test("hardware filter includes only records with current software associations", () => {
  assert.deepEqual(ids(filterInventoryAssets(inventory,
    { assetType: "HARDWARE", relationshipFilter: "HAS_SOFTWARE" })), [1]);
});
test("hardware with zero software is distinguished from software-less physical devices", () => {
  assert.deepEqual(ids(filterInventoryAssets(inventory,
    { assetType: "HARDWARE", relationshipFilter: "NO_SOFTWARE" })), [2, 3]);
});
test("hardware without interfaces excludes devices with one or more", () => {
  assert.deepEqual(ids(filterInventoryAssets(inventory,
    { assetType: "HARDWARE", relationshipFilter: "NO_INTERFACES" })), [3]);
});
test("software with and without current hosting hardware", () => {
  assert.deepEqual(ids(filterInventoryAssets(inventory,
    { assetType: "SOFTWARE", relationshipFilter: "HAS_HARDWARE" })), [4]);
  assert.deepEqual(ids(filterInventoryAssets(inventory,
    { assetType: "SOFTWARE", relationshipFilter: "NO_HARDWARE" })), [5]);
});
test("search, criticality, type and associations all apply together", () => {
  assert.deepEqual(ids(filterInventoryAssets(inventory, {
    assetType: "HARDWARE", relationshipFilter: "NO_SOFTWARE",
    search: "Siemens", criticality: "HIGH",
  })), [3]);
  assert.deepEqual(ids(filterInventoryAssets(inventory, {
    assetType: "HARDWARE", relationshipFilter: "NO_SOFTWARE",
    search: "Siemens", criticality: "LOW",
  })), []);
});
test("search matches product and manufacturer without losing earlier behavior", () => {
  assert.deepEqual(ids(filterInventoryAssets(inventory, { search: "DL205" })), [1, 4]);
  assert.deepEqual(ids(filterInventoryAssets(inventory, { search: "axis" })), [2]);
});
test("all asset types means all relationships and no hidden type restriction", () => {
  assert.deepEqual(ids(filterInventoryAssets(inventory,
    { assetType: "ALL", relationshipFilter: "ALL" })), [1, 2, 3, 4, 5]);
  assert.equal(matchesRelationshipFilter(inventory[3], "ALL", "NO_SOFTWARE"), true);
});
test("missing or invalid counts must not masquerade as zero associations", () => {
  assert.equal(matchesRelationshipFilter(
    { asset_type: "HARDWARE" }, "HARDWARE", "NO_SOFTWARE"), false);
  assert.equal(matchesRelationshipFilter(
    { asset_type: "SOFTWARE", hardware_count: null }, "SOFTWARE", "NO_HARDWARE"), false);
  assert.equal(matchesRelationshipFilter(
    { asset_type: "HARDWARE", interface_count: "0" }, "HARDWARE", "NO_INTERFACES"), false);
});
test("filter options are specific to each asset type", () => {
  assert.deepEqual(RELATIONSHIP_FILTERS.HARDWARE.map(x => x.value),
    ["ALL", "HAS_SOFTWARE", "NO_SOFTWARE", "NO_INTERFACES"]);
  assert.deepEqual(RELATIONSHIP_FILTERS.SOFTWARE.map(x => x.value),
    ["ALL", "HAS_HARDWARE", "NO_HARDWARE"]);
  assert.equal(matchesRelationshipFilter(
    inventory[3], "SOFTWARE", "NO_SOFTWARE"), false);
});
test("an archived asset remains filterable when included by inventory status", () => {
  const all = [...inventory, {
    id: 6, name: "PLC archivado", asset_type: "HARDWARE",
    inventory_status: "ARCHIVED", software_count: 0, interface_count: 0,
  }];
  assert.deepEqual(ids(filterInventoryAssets(all, {
    assetType: "HARDWARE", relationshipFilter: "NO_INTERFACES",
  })), [3, 6]);
});
