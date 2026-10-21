import test from "node:test";
import assert from "node:assert/strict";
import {groupCpeQueries,describeCandidate,reasonLabel,resultLabel,queryDescription,levelName} from "./cpeDiscoveryPresentation.js";

test("regroups discovery in original order and counts non-unique records",()=>{
 const groups=groupCpeQueries([
  {level:"SPECIFIC",pages:1,retrieved:9,status:"COMPLETED",level_result:"NO_PERTINENT_CANDIDATES"},
  {level:"SPECIFIC",pages:1,retrieved:1,status:"COMPLETED"},
  {level:"FAMILY",pages:1,retrieved:0,status:"COMPLETED"},
  {level:"MANUFACTURER",pages:2,retrieved:200,filtered_hardware_results:199,
    status:"PARTIAL",stop_reason:"MANUFACTURER_LEVEL_LIMIT",level_result:"PARTIAL_RESULTS",
    level_unique_hardware_candidates:1},
 ]);
 assert.deepEqual(groups.map(x=>x.level),["SPECIFIC","FAMILY","MANUFACTURER"]);
 assert.equal(groups[0].retrieved,10);
 assert.equal(groups[2].filtered,199);
 assert.equal(groups[2].uniqueCandidates,1);
 assert.match(resultLabel(groups[2].result),/incompleta/);
 assert.match(reasonLabel(groups[2].stopReason),/límite/);
});
test("older records without a level are kept as history, never guessed",()=>{
 const group=groupCpeQueries([{strategy:"keywordSearch",pages:1}])[0];
 assert.equal(group.level,"LEGACY");
 assert.equal(group.hasRetrieved,false);
 assert.equal(group.uniqueCandidates,null);
 assert.equal(group.result,"");
 assert.deepEqual(groupCpeQueries(null),[]);
 assert.deepEqual(groupCpeQueries([null,"invalid"]),[]);
});
test("Rockwell 1783-NATR is related not confirmed",()=>{
 const x=describeCandidate({match_level:"RELATED",match_reason:"Solo comparte un prefijo de catálogo",
  discovery_levels:["MANUFACTURER"],methods:["cpeMatchString"]});
 assert.equal(x.tone,"related");
 assert.equal(x.levels[0],levelName("MANUFACTURER"));
 assert.match(queryDescription({strategy:"cpeMatchString",parameter:"cpe:2.3:h:rockwellautomation:1783*"}),/1783/);
});
test("AXIS 207 is not labelled exact match for AXIS 206",()=>{
 assert.equal(describeCandidate({match_level:"POSSIBLE_INCOMPATIBILITY"}).tone,"incompatible");
});
test("Siemens CPU exact remains textual; old candidates remain unclassified",()=>{
 assert.equal(describeCandidate({match_level:"SPECIFIC"}).tone,"specific");
 assert.equal(describeCandidate({title:"Legacy"}).tone,"unknown");
 assert.equal(describeCandidate({title:"Legacy"}).levels.length,0);
 assert.match(reasonLabel("REQUEST_FAILED"),/no terminó/);
});

test("catalogue evidence provenance is not incorrectly labelled historical", () => {
  const grouped = groupCpeQueries([{level:"CATALOGUE", strategy:"cpeMatchString",
    snapshot_id:2, evidence_id:14, status:"COMPLETED"}]);
  assert.equal(grouped[0].level,"CATALOGUE");
  assert.match(levelName("CATALOGUE"),/catálogo/);
  const selected = describeCandidate({match_level:"FAMILY",discovery_levels:["CATALOGUE"]});
  assert.deepEqual(selected.levels,[levelName("CATALOGUE")]);
});

test("exploratory candidate shares existing card and retains its reason",()=>{
 const info=describeCandidate({match_level:"EXPLORATORY",
  match_reason:"Numeración próxima pero modelo distinto"});
 assert.match(info.label,/Correspondencia débil/);
 assert.match(info.reason,/modelo distinto/);
 assert.equal(info.tone,"related");
});
