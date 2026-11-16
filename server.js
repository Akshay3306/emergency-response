require("dotenv").config();

const path = require("node:path");
const { randomUUID } = require("node:crypto");
const bcrypt = require("bcryptjs");
const connectPgSimple = require("connect-pg-simple");
const express = require("express");
const { rateLimit } = require("express-rate-limit");
const session = require("express-session");
const helmet = require("helmet");
const { Pool } = require("pg");
const {
  canAssignRequest,
  canCreateRequest,
  canUpdateRequest,
  nextRequestStatus
} = require("./policy");

const app = express();
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : undefined
});
const PgSessionStore = connectPgSimple(session);
const sessionStore = new PgSessionStore({
  pool,
  createTableIfMissing: true,
  tableName: "sessions"
});

const emergencyTypes = [
  "Medical emergency",
  "Road traffic accident",
  "Cardiac event",
  "Trauma / injury",
  "Other emergency"
];
const priorities = ["Critical", "High", "Standard"];
const statuses = ["Requested", "Dispatched", "Pickup", "En route", "Completed"];

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function asyncHandler(handler) {
  return (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.session.user) {
      return res.status(401).json({ error: "Sign in is required." });
    }
    if (!roles.includes(req.session.user.role)) {
      return res.status(403).json({ error: "Your role cannot perform this action." });
    }
    return next();
  };
}

function requireAuthenticated(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ error: "Sign in is required." });
  }
  return next();
}

function requestText(value, field, maxLength, required = true) {
  if (typeof value !== "string") {
    if (!required && (value === undefined || value === null)) return "";
    throw new HttpError(400, `${field} is required.`);
  }
  const trimmed = value.trim();
  if (required && !trimmed) throw new HttpError(400, `${field} is required.`);
  if (trimmed.length > maxLength) throw new HttpError(400, `${field} is too long.`);
  return trimmed;
}

function sessionUser(row) {
  return {
    id: row.id,
    role: row.role,
    name: row.display_name,
    initials: row.initials,
    label: row.label,
    driverName: row.driver_name
  };
}

function regenerateSession(req) {
  return new Promise((resolve, reject) => {
    req.session.regenerate(error => error ? reject(error) : resolve());
  });
}

function saveSession(req) {
  return new Promise((resolve, reject) => {
    req.session.save(error => error ? reject(error) : resolve());
  });
}

function destroySession(req) {
  return new Promise((resolve, reject) => {
    req.session.destroy(error => error ? reject(error) : resolve());
  });
}

async function ensureDatabase() {
  if (!process.env.DATABASE_URL) {
    throw new Error("DATABASE_URL must be configured.");
  }
  if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
    throw new Error("SESSION_SECRET must contain at least 32 characters.");
  }

  await pool.query(`
    CREATE SEQUENCE IF NOT EXISTS emergency_request_number_seq START WITH 2049;
    CREATE TABLE IF NOT EXISTS staff_users (
      id BIGSERIAL PRIMARY KEY,
      employee_id TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('Admin', 'Dispatcher', 'Ambulance Driver')),
      display_name TEXT NOT NULL,
      initials TEXT NOT NULL,
      label TEXT NOT NULL,
      driver_name TEXT
    );
    CREATE TABLE IF NOT EXISTS ambulances (
      id TEXT PRIMARY KEY,
      type TEXT NOT NULL,
      status TEXT NOT NULL,
      driver TEXT NOT NULL,
      station TEXT NOT NULL,
      equipment TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS drivers (
      name TEXT PRIMARY KEY,
      initials TEXT NOT NULL,
      shift TEXT NOT NULL,
      status TEXT NOT NULL,
      vehicle TEXT NOT NULL,
      calls INTEGER NOT NULL DEFAULT 0,
      response TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS emergency_requests (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      phone TEXT NOT NULL,
      type TEXT NOT NULL,
      location TEXT NOT NULL,
      priority TEXT NOT NULL,
      status TEXT NOT NULL,
      time TEXT NOT NULL,
      vehicle TEXT,
      driver TEXT,
      eta TEXT,
      notes TEXT NOT NULL DEFAULT '',
      owner_session_id TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS emergency_requests_owner_idx
      ON emergency_requests (owner_session_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS emergency_requests_driver_idx
      ON emergency_requests (driver, created_at DESC);
  `);

  const accountSeeds = [
    {
      employeeId: "ADM-1001",
      envName: "INITIAL_ADMIN_PASSWORD",
      role: "Admin",
      name: "Jordan Blake",
      initials: "JB",
      label: "System administrator",
      driverName: null
    },
    {
      employeeId: "DSP-1001",
      envName: "INITIAL_DISPATCHER_PASSWORD",
      role: "Dispatcher",
      name: "Alex Morgan",
      initials: "AM",
      label: "Operations team",
      driverName: null
    },
    {
      employeeId: "DRV-1001",
      envName: "INITIAL_DRIVER_PASSWORD",
      role: "Ambulance Driver",
      name: "Marcus Lee",
      initials: "ML",
      label: "Driver · AMB-04",
      driverName: "Marcus Lee"
    }
  ];

  const configuredPasswords = new Set();
  for (const account of accountSeeds) {
    const password = process.env[account.envName];
    if (!password || password.length < 12) {
      throw new Error(`${account.envName} must be set to a unique password of at least 12 characters.`);
    }
    if (configuredPasswords.has(password)) {
      throw new Error("Initial staff passwords must be unique.");
    }
    configuredPasswords.add(password);
    const passwordHash = await bcrypt.hash(password, 12);
    await pool.query(
      `INSERT INTO staff_users
        (employee_id, password_hash, role, display_name, initials, label, driver_name)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       ON CONFLICT (employee_id) DO NOTHING`,
      [account.employeeId, passwordHash, account.role, account.name, account.initials, account.label, account.driverName]
    );
  }

  const unitSeeds = [
    ["AMB-01", "Advanced life support", "Available", "David Chen", "Central Station", "ALS"],
    ["AMB-02", "Advanced life support", "On scene", "Priya Patel", "North Station", "ALS"],
    ["AMB-03", "Basic life support", "Available", "Elena Garcia", "West Station", "BLS"],
    ["AMB-04", "Advanced life support", "Busy", "Marcus Lee", "Central Station", "ALS"],
    ["AMB-05", "Basic life support", "Available", "Andre Johnson", "South Station", "BLS"],
    ["AMB-06", "Advanced life support", "Maintenance", "—", "Fleet depot", "ALS"],
    ["AMB-07", "Advanced life support", "Dispatched", "James Wilson", "East Station", "ALS"]
  ];
  for (const unit of unitSeeds) {
    await pool.query(
      `INSERT INTO ambulances (id, type, status, driver, station, equipment)
       VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (id) DO NOTHING`,
      unit
    );
  }

  const driverSeeds = [
    ["David Chen", "DC", "06:00 – 18:00", "On duty", "AMB-01", 6, "7.2 min"],
    ["Priya Patel", "PP", "06:00 – 18:00", "On duty", "AMB-02", 4, "6.8 min"],
    ["Elena Garcia", "EG", "08:00 – 20:00", "On duty", "AMB-03", 3, "8.1 min"],
    ["Marcus Lee", "ML", "06:00 – 18:00", "On duty", "AMB-04", 5, "5.9 min"],
    ["Andre Johnson", "AJ", "12:00 – 00:00", "On duty", "AMB-05", 2, "7.6 min"],
    ["James Wilson", "JW", "08:00 – 20:00", "On duty", "AMB-07", 4, "6.4 min"],
    ["Sarah Kim", "SK", "Off shift", "Off duty", "—", 0, "—"]
  ];
  for (const driver of driverSeeds) {
    await pool.query(
      `INSERT INTO drivers (name, initials, shift, status, vehicle, calls, response)
       VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (name) DO NOTHING`,
      driver
    );
  }

  const requestSeeds = [
    ["ER-2048", "Olivia Carter", "(555) 019-2814", "Cardiac event", "214 Waverly Place, Midtown", "Critical", "En route", "2 min ago", "AMB-04", "Marcus Lee", "4 min", ""],
    ["ER-2047", "Noah Williams", "(555) 012-6380", "Road traffic accident", "8th Ave & Pine Street", "High", "Pickup", "8 min ago", "AMB-02", "Priya Patel", "On scene", ""],
    ["ER-2046", "Sophia Martinez", "(555) 016-9912", "Medical emergency", "Parkside Senior Living", "Standard", "Dispatched", "14 min ago", "AMB-07", "James Wilson", "6 min", ""],
    ["ER-2045", "Ethan Brooks", "(555) 018-4492", "Trauma / injury", "402 Harbor Road, East District", "High", "Requested", "Just now", null, null, null, ""],
    ["ER-2044", "Ava Thompson", "(555) 011-2064", "Medical emergency", "91 Maplewood Drive", "Standard", "Completed", "32 min ago", "AMB-01", "David Chen", "Completed", ""]
  ];
  for (const request of requestSeeds) {
    await pool.query(
      `INSERT INTO emergency_requests
        (id, name, phone, type, location, priority, status, time, vehicle, driver, eta, notes)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
       ON CONFLICT (id) DO NOTHING`,
      request
    );
  }
}

app.set("trust proxy", 1);
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"]
    }
  }
}));
app.use(express.json({ limit: "16kb" }));
app.use("/api", (req, res, next) => {
  res.set("Cache-Control", "no-store");
  next();
});
app.use(session({
  name: "relay.sid",
  secret: process.env.SESSION_SECRET || "development-only-session-secret-change-me",
  store: sessionStore,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 8 * 60 * 60 * 1000
  }
}));

app.get("/api/health", asyncHandler(async (req, res) => {
  await pool.query("SELECT 1");
  res.status(200).json({ status: "ok" });
}));

app.get("/api/auth/session", (req, res) => {
  res.json({ user: req.session.user || null });
});

app.post("/api/auth/login", rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many sign-in attempts. Try again later." }
}), asyncHandler(async (req, res) => {
  const body = req.body || {};
  const role = requestText(body.role, "Role", 40);
  const employeeId = requestText(body.employeeId, "Employee ID", 80).toUpperCase();
  if (typeof body.password !== "string" || !body.password || body.password.length > 200) {
    throw new HttpError(400, "Password is required.");
  }
  const password = body.password;
  const result = await pool.query(
    `SELECT id, employee_id, password_hash, role, display_name, initials, label, driver_name
     FROM staff_users WHERE employee_id = $1 AND role = $2`,
    [employeeId, role]
  );
  const account = result.rows[0];
  if (!account || !(await bcrypt.compare(password, account.password_hash))) {
    throw new HttpError(401, "Employee ID or password is incorrect for the selected role.");
  }
  await regenerateSession(req);
  req.session.user = sessionUser(account);
  await saveSession(req);
  res.json({ user: req.session.user });
}));

app.post("/api/auth/logout", asyncHandler(async (req, res) => {
  if (req.session) await destroySession(req);
  res.clearCookie("relay.sid", { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production" });
  res.json({ ok: true });
}));

app.get("/api/state", asyncHandler(async (req, res) => {
  const user = req.session.user;
  let requestsQuery;
  let requestsParams = [];
  let driversQuery = "SELECT name, initials, shift, status, vehicle, calls, response FROM drivers ORDER BY name";
  let ambulancesQuery = "SELECT id, type, status, driver, station, equipment FROM ambulances ORDER BY id";

  if (!user) {
    req.session.guestId = req.session.guestId || randomUUID();
    requestsQuery = `SELECT id, name, phone, type, location, priority, status, time, vehicle, driver, eta, notes
      FROM emergency_requests WHERE owner_session_id = $1 ORDER BY created_at DESC`;
    requestsParams = [req.session.guestId];
    driversQuery = "SELECT name, initials, shift, status, vehicle, calls, response FROM drivers WHERE false";
    ambulancesQuery = "SELECT id, type, status, driver, station, equipment FROM ambulances WHERE false";
  } else if (user.role === "Ambulance Driver") {
    requestsQuery = `SELECT id, name, phone, type, location, priority, status, time, vehicle, driver, eta, notes
      FROM emergency_requests WHERE driver = $1 ORDER BY created_at DESC`;
    requestsParams = [user.driverName];
    driversQuery = `SELECT name, initials, shift, status, vehicle, calls, response
      FROM drivers WHERE name = $1`;
    ambulancesQuery = "SELECT id, type, status, driver, station, equipment FROM ambulances WHERE false";
  } else if (["Admin", "Dispatcher"].includes(user.role)) {
    requestsQuery = `SELECT id, name, phone, type, location, priority, status, time, vehicle, driver, eta, notes
      FROM emergency_requests ORDER BY created_at DESC`;
  } else {
    throw new HttpError(403, "Your role cannot access operational data.");
  }

  const [requestsResult, driversResult, ambulancesResult] = await Promise.all([
    pool.query(requestsQuery, requestsParams),
    user && user.role === "Ambulance Driver"
      ? pool.query(driversQuery, [user.driverName])
      : pool.query(driversQuery),
    pool.query(ambulancesQuery)
  ]);
  res.json({
    requests: requestsResult.rows,
    drivers: driversResult.rows,
    ambulances: ambulancesResult.rows
  });
}));

app.post("/api/requests", rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests submitted. Try again later." }
}), asyncHandler(async (req, res) => {
  const body = req.body || {};
  const user = req.session.user;
  if (user && !canCreateRequest(user.role)) {
    throw new HttpError(403, "Your role cannot create emergency requests.");
  }
  if (user && !["Admin", "Dispatcher"].includes(user.role)) {
    throw new HttpError(403, "Your role cannot create emergency requests.");
  }

  const name = requestText(body.name, "Name", 120);
  const phone = requestText(body.phone, "Phone number", 40);
  const location = requestText(body.location, "Location", 240);
  const type = requestText(body.type, "Emergency type", 60);
  const priority = requestText(body.priority, "Priority", 20);
  const notes = requestText(body.notes, "Additional information", 2000, false);
  if (!emergencyTypes.includes(type) || !priorities.includes(priority)) {
    throw new HttpError(400, "Choose a valid emergency type and priority.");
  }

  let ownerSessionId = null;
  if (!user) {
    req.session.guestId = req.session.guestId || randomUUID();
    ownerSessionId = req.session.guestId;
  }
  const sequence = await pool.query("SELECT nextval('emergency_request_number_seq') AS number");
  const id = `ER-${sequence.rows[0].number}`;
  await pool.query(
    `INSERT INTO emergency_requests
      (id, name, phone, type, location, priority, status, time, notes, owner_session_id)
     VALUES ($1, $2, $3, $4, $5, $6, 'Requested', 'Just now', $7, $8)`,
    [id, name, phone, type, location, priority, notes, ownerSessionId]
  );
  res.status(201).json({ id });
}));

app.post("/api/requests/:id/assign", requireRole("Admin", "Dispatcher"), asyncHandler(async (req, res) => {
  if (!canAssignRequest(req.session.user.role)) {
    throw new HttpError(403, "Your role cannot assign ambulance units.");
  }
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const requestResult = await client.query(
      "SELECT id, status FROM emergency_requests WHERE id = $1 FOR UPDATE",
      [req.params.id]
    );
    const request = requestResult.rows[0];
    if (!request || request.status !== "Requested") {
      throw new HttpError(409, "This request cannot be assigned.");
    }
    const unitResult = await client.query(
      "SELECT id, driver FROM ambulances WHERE status = 'Available' ORDER BY id FOR UPDATE SKIP LOCKED LIMIT 1"
    );
    const unit = unitResult.rows[0];
    if (!unit) throw new HttpError(409, "No ambulance is available.");
    await client.query(
      `UPDATE emergency_requests SET vehicle = $1, driver = $2, status = 'Dispatched', eta = '8 min'
       WHERE id = $3`,
      [unit.id, unit.driver, request.id]
    );
    await client.query("UPDATE ambulances SET status = 'Dispatched' WHERE id = $1", [unit.id]);
    await client.query("COMMIT");
    res.json({ id: request.id, vehicle: unit.id, driver: unit.driver, status: "Dispatched" });
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}));

app.patch("/api/requests/:id/status", requireAuthenticated, asyncHandler(async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const result = await client.query(
      `SELECT id, status, vehicle, driver FROM emergency_requests WHERE id = $1 FOR UPDATE`,
      [req.params.id]
    );
    const request = result.rows[0];
    if (!request) throw new HttpError(404, "Emergency request not found.");
    if (!canUpdateRequest(req.session.user, request)) {
      throw new HttpError(403, "You can only update your own assigned call.");
    }
    const nextStatus = nextRequestStatus(request.status);
    if (!nextStatus || !statuses.includes(nextStatus)) {
      throw new HttpError(409, "This call cannot be advanced from its current status.");
    }
    const eta = nextStatus === "Pickup" ? "On scene" : nextStatus === "En route" ? "4 min" : "Completed";
    await client.query(
      "UPDATE emergency_requests SET status = $1, eta = $2 WHERE id = $3",
      [nextStatus, eta, request.id]
    );
    if (request.vehicle && nextStatus === "Pickup") {
      await client.query("UPDATE ambulances SET status = 'On scene' WHERE id = $1", [request.vehicle]);
    } else if (request.vehicle && nextStatus === "En route") {
      await client.query("UPDATE ambulances SET status = 'Busy' WHERE id = $1", [request.vehicle]);
    } else if (request.vehicle && nextStatus === "Completed") {
      await client.query("UPDATE ambulances SET status = 'Available' WHERE id = $1", [request.vehicle]);
      await client.query("UPDATE drivers SET calls = calls + 1 WHERE name = $1", [request.driver]);
    }
    await client.query("COMMIT");
    res.json({ id: request.id, status: nextStatus });
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}));

app.get("/", (req, res) => res.sendFile(path.join(__dirname, "index.html")));

app.use("/api", (req, res) => res.status(404).json({ error: "API endpoint not found." }));
app.use((req, res) => res.status(404).send("Not found."));
app.use((error, req, res, next) => {
  if (res.headersSent) return next(error);
  if (error instanceof HttpError) {
    return res.status(error.status).json({ error: error.message });
  }
  if (error.type === "entity.parse.failed") {
    return res.status(400).json({ error: "Request body must be valid JSON." });
  }
  if (error.type === "entity.too.large") {
    return res.status(413).json({ error: "Request body is too large." });
  }
  console.error("Request failed:", error);
  return res.status(500).json({ error: "The server could not complete the request." });
});

async function startServer() {
  await ensureDatabase();
  const port = Number(process.env.PORT) || 3000;
  app.listen(port, "0.0.0.0", () => {
    console.log(`Emergency response demo listening on port ${port}.`);
  });
}

if (require.main === module) {
  startServer().catch(error => {
    console.error("Server startup failed:", error);
    process.exitCode = 1;
  });
}
