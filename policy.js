const rolePages = {
  Admin: ["overview", "dispatch", "requests", "ambulances", "drivers", "requester", "reports", "admin"],
  Dispatcher: ["overview", "dispatch", "requests", "ambulances", "drivers", "reports"],
  "Ambulance Driver": ["drivers"],
  Requester: ["requester"]
};

const requestTransitions = {
  Dispatched: "Pickup",
  Pickup: "En route",
  "En route": "Completed"
};

function canAccessPage(role, page) {
  return Boolean(rolePages[role] && rolePages[role].includes(page));
}

function canCreateRequest(role) {
  return ["Admin", "Dispatcher", "Requester"].includes(role);
}

function canAssignRequest(role) {
  return ["Admin", "Dispatcher"].includes(role);
}

function canUpdateRequest(user, request) {
  return ["Admin", "Dispatcher"].includes(user.role)
    || (user.role === "Ambulance Driver" && request.driver === user.driverName);
}

function nextRequestStatus(status) {
  return requestTransitions[status] || null;
}

module.exports = {
  canAccessPage,
  canAssignRequest,
  canCreateRequest,
  canUpdateRequest,
  nextRequestStatus,
  rolePages
};
