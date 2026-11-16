const test = require("node:test");
const assert = require("node:assert/strict");
const {
  canAccessPage,
  canAssignRequest,
  canCreateRequest,
  canUpdateRequest,
  nextRequestStatus
} = require("../policy");

test("page access is restricted to each role", () => {
  assert.equal(canAccessPage("Requester", "requester"), true);
  assert.equal(canAccessPage("Requester", "dispatch"), false);
  assert.equal(canAccessPage("Ambulance Driver", "drivers"), true);
  assert.equal(canAccessPage("Ambulance Driver", "reports"), false);
  assert.equal(canAccessPage("Dispatcher", "admin"), false);
});

test("request actions enforce role and driver ownership", () => {
  const call = { driver: "Marcus Lee" };
  assert.equal(canCreateRequest("Requester"), true);
  assert.equal(canCreateRequest("Ambulance Driver"), false);
  assert.equal(canAssignRequest("Requester"), false);
  assert.equal(canAssignRequest("Dispatcher"), true);
  assert.equal(canUpdateRequest({ role: "Ambulance Driver", driverName: "Marcus Lee" }, call), true);
  assert.equal(canUpdateRequest({ role: "Ambulance Driver", driverName: "Priya Patel" }, call), false);
  assert.equal(canUpdateRequest({ role: "Requester" }, call), false);
});

test("request status transitions reject terminal and unassigned states", () => {
  assert.equal(nextRequestStatus("Dispatched"), "Pickup");
  assert.equal(nextRequestStatus("Pickup"), "En route");
  assert.equal(nextRequestStatus("En route"), "Completed");
  assert.equal(nextRequestStatus("Requested"), null);
  assert.equal(nextRequestStatus("Completed"), null);
});
