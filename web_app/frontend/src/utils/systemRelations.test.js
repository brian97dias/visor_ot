import assert from "node:assert/strict";
import { test } from "node:test";
import { groupSoftwareByHardware } from "./systemRelations.js";

test("one software installed on two hosts appears once under each host", () => {
  const variant = {
    software_asset_id: 7, name: "Firmware DL205",
    hardware: [{hardware_asset_id:1}, {hardware_asset_id:2}],
  };
  const grouped = groupSoftwareByHardware([variant]);
  assert.deepEqual([...grouped.keys()], [1,2]);
  assert.equal(grouped.get(1).length, 1);
  assert.equal(grouped.get(2)[0].software_asset_id, 7);
});

test("separate software variants stay grouped by host", () => {
  const results = [
    {software_asset_id:7, hardware:[{hardware_asset_id:1}]},
    {software_asset_id:8, hardware:[{hardware_asset_id:1}]},
    {software_asset_id:9, hardware:[]},
  ];
  const grouped=groupSoftwareByHardware(results);
  assert.deepEqual(grouped.get(1).map(v=>v.software_asset_id), [7,8]);
  assert.equal(grouped.has(9),false);
});

test("duplicate host references do not repeat the same software variant", () => {
  const grouped=groupSoftwareByHardware([{
    software_asset_id:7,
    hardware:[{hardware_asset_id:1}, {hardware_asset_id:1}],
  }]);
  assert.equal(grouped.get(1).length,1);
  assert.deepEqual([...groupSoftwareByHardware([])],[]);
});
