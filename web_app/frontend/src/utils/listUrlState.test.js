import assert from "node:assert/strict";
import { test } from "node:test";
import { readPage, updateListParams, parseAssetIds } from "./listUrlState.js";
import { navigationFromLocation, getBackNavigation, isSafeReturnPath } from "./returnNavigation.js";
test("communications retain all criteria and their page", () => {
  const params = new URLSearchParams("status=NO_AUTORIZADA&min_packets=50&devices=5,7&q=modbus&page=3");
  const location = { pathname: "/communications", search: "?" + params };
  const navigation = navigationFromLocation(location);
  assert.equal(getBackNavigation({state:navigation}).to, "/communications?" + params);
  const changed = updateListParams(params, "status", "AUTORIZADA", {defaultValue:"ALL"});
  assert.equal(changed.has("page"),false);
  assert.deepEqual(parseAssetIds(changed.get("devices")),[5,7]);
});
test("interface and passive-analysis contexts can be restored", () => {
  for(const path of ["/assets/interfaces?q=192.168&identification=IDENTIFIED&page=2",
    "/passive-analysis?tab=observations&ingestion_status=ACTIVE",
    "/passive-analysis?pcap_page=3&pcap_status=ANALYZED"]) {
    const [pathname, search] = path.split("?");
    assert.equal(getBackNavigation({state:navigationFromLocation({pathname,search:search?"?"+search:""})}).to,path);
  }
});
test("tab switches retain separate capture and ingestion criteria", () => {
  const params = new URLSearchParams("tab=observations&pcap_q=4SICS&pcap_page=3&ingestion_status=ACTIVE");
  const next = updateListParams(params,"tab","pcaps",{defaultValue:"pcaps",resetPage:false});
  assert.equal(next.has("tab"),false);
  assert.equal(next.get("pcap_page"),"3");
  assert.equal(next.get("ingestion_status"),"ACTIVE");
});
test("device IDs, pagination and internal targets are validated", () => {
  assert.deepEqual(parseAssetIds("1,1,002,bad,5"),[1,2]);
  assert.deepEqual(parseAssetIds("0,-1,xyz"),[]);
  assert.equal(readPage("2"),2);
  assert.equal(readPage("-1"),1);
  assert.equal(isSafeReturnPath("/communications/4"),true);
  assert.equal(isSafeReturnPath("/communications-evil"),false);
  assert.equal(isSafeReturnPath("//evil.test"),false);
});
