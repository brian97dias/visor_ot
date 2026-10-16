import assert from "node:assert/strict";
import { test } from "node:test";
import { readPositiveInt, updateInventoryParams } from "./inventoryUrlState.js";
import { getBackNavigation, navigationFromLocation, detailStateAfterEdit, isSafeReturnPath } from "./returnNavigation.js";
test("inventory filters remain in return URLs", () => {
 const inventory = { pathname:"/assets", search:"?type=HARDWARE&relation=NO_INTERFACES&q=Moxa&page=2", state:null };
 const edit = { pathname:"/assets/15/edit", state:navigationFromLocation(inventory) };
 assert.equal(getBackNavigation(edit).to, "/assets?type=HARDWARE&relation=NO_INTERFACES&q=Moxa&page=2");
 assert.equal(detailStateAfterEdit(edit,15).returnTo, getBackNavigation(edit).to);
});
test("changing filters clears stale expansion and page", () => {
 const initial = new URLSearchParams("type=HARDWARE&relation=NO_INTERFACES&page=2&expanded=15");
 const next=updateInventoryParams(initial,"q","red");
 assert.equal(next.get("q"),"red");
 assert.equal(next.has("page"),false);
 assert.equal(next.has("expanded"),false);
 assert.equal(next.get("relation"),"NO_INTERFACES");
 assert.equal(updateInventoryParams(initial,"type","SOFTWARE").has("relation"),false);
});
test("direct navigation and malformed targets fall back", () => {
 assert.equal(getBackNavigation({state:null},"/assets/15").to,"/assets/15");
 assert.equal(isSafeReturnPath("//example.com"),false);
 assert.equal(getBackNavigation({state:{returnTo:"//example.com"}}).to,"/assets");
 assert.equal(readPositiveInt("0"),1);
 assert.equal(readPositiveInt("12"),12);
});
