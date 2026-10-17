import assert from "node:assert/strict";
import { test } from "node:test";
import { groupEndpointCandidates } from "./endpointCandidates.js";

test("one identified and one unassigned MAC are shown separately", () => {
  const result = groupEndpointCandidates([
    { mac: "00:07:7c:1a:61:83", asset_id: 20,
      asset_name: "Westermo Lynx 3643-0105", interface_id: 83 },
    { mac: "b0:99:28:d9:1a:24", asset_id: null,
      asset_name: null, interface_id: 116 },
  ]);
  assert.deepEqual(result.assets, [
    { asset_id: 20, asset_name: "Westermo Lynx 3643-0105" },
  ]);
  assert.deepEqual(result.unassignedMacs, ["b0:99:28:d9:1a:24"]);
});

test("two MACs associated to same hardware do not repeat its name", () => {
  const result = groupEndpointCandidates([
    { mac: "00:01:02:03:04:05", asset_id: 5, asset_name: "PLC-01" },
    { mac: "00:01:02:03:04:06", asset_id: 5, asset_name: "PLC-01" },
  ]);
  assert.equal(result.assets.length, 1);
  assert.equal(result.assets[0].asset_id, 5);
});

test("no candidates leaves the previous ambiguous display unchanged", () => {
  assert.deepEqual(groupEndpointCandidates(), {assets: [], unassignedMacs: []});
  assert.deepEqual(groupEndpointCandidates([]), {assets: [], unassignedMacs: []});
});

test("unassigned MACs are deduplicated, with no fabricated identities", () => {
  const result = groupEndpointCandidates([
    { mac: "aa:bb:cc:dd:ee:ff", asset_id: null },
    { mac: "aa:bb:cc:dd:ee:ff", asset_id: null },
    { mac: "11:22:33:44:55:66", asset_id: 5, asset_name: null },
  ]);
  assert.deepEqual(result.assets, []);
  assert.deepEqual(result.unassignedMacs, [
    "11:22:33:44:55:66", "aa:bb:cc:dd:ee:ff",
  ]);
});
