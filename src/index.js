const JSON_HEADERS = { "content-type": "application/json; charset=utf-8" };

function json(body, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: JSON_HEADERS });
}

function nowISO() { return new Date().toISOString(); }
function id() { return crypto.randomUUID(); }

async function sha256(value) {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function encryptionKey(env) {
  if (!env.TOKEN_ENCRYPTION_KEY) throw new Error("TOKEN_ENCRYPTION_KEY is not configured");
  const material = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(env.TOKEN_ENCRYPTION_KEY));
  return crypto.subtle.importKey("raw", material, "AES-GCM", false, ["encrypt", "decrypt"]);
}

async function encrypt(value, env) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await encryptionKey(env);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(value));
  const packed = new Uint8Array(iv.length + ciphertext.byteLength);
  packed.set(iv, 0); packed.set(new Uint8Array(ciphertext), iv.length);
  return btoa(String.fromCharCode(...packed));
}

async function decrypt(value, env) {
  const packed = Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
  const key = await encryptionKey(env);
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv: packed.slice(0, 12) }, key, packed.slice(12));
  return new TextDecoder().decode(plaintext);
}

const FORD_TOKEN_URL = "https://api.vehicle.ford.com/dah2vb2cprod.onmicrosoft.com/oauth2/v2.0/token?p=B2C_1A_FCON_AUTHORIZE";
const FORD_DATA_BASE = "https://api.vehicle.ford.com/fcon-query/v1";
const FORD_REDIRECT_URI = "https://cellblock.cc/";

// Retained for compatibility with the Durable Object binding used by older
// Worker versions. The current polling path is D1-backed, but Cloudflare will
// not accept a deployment that removes a class with existing instances.
export class FordRateLimiter {
  constructor(state) { this.state = state; }
  async fetch() { return new Response("deprecated", { status: 410 }); }
}

async function fordTokenExchange(env, params) {
  if (!env.FORD_CLIENT_ID || !env.FORD_CLIENT_SECRET) throw new Error("Ford OAuth is not configured");
  const response = await fetch(FORD_TOKEN_URL, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      ...params,
      client_id: env.FORD_CLIENT_ID,
      client_secret: env.FORD_CLIENT_SECRET,
      redirect_uri: params.redirect_uri || FORD_REDIRECT_URI,
      scope: `${env.FORD_CLIENT_ID} offline_access openid`
    })
  });
  return { response, payload: await response.json().catch(() => null) };
}

function apnsPrivateKey(env) {
  return env.APNS_PRIVATE_KEY_P8 || env.APNS_AUTH_KEY || null;
}

function requiredAPNs(env) {
  return env.APNS_TEAM_ID && env.APNS_KEY_ID && apnsPrivateKey(env) && env.APNS_BUNDLE_ID ? env : null;
}

function base64url(value) {
  return btoa(String.fromCharCode(...new Uint8Array(value)))
    .replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function pemBytes(pem) {
  const body = pem.replace(/-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----|\s/g, "");
  const binary = atob(body);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

async function apnsJWT(env) {
  const header = base64url(new TextEncoder().encode(JSON.stringify({ alg: "ES256", kid: env.APNS_KEY_ID })));
  const claims = base64url(new TextEncoder().encode(JSON.stringify({ iss: env.APNS_TEAM_ID, iat: Math.floor(Date.now() / 1000) })));
  const key = await crypto.subtle.importKey("pkcs8", pemBytes(apnsPrivateKey(env)), { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, new TextEncoder().encode(`${header}.${claims}`));
  return `${header}.${claims}.${base64url(signature)}`;
}

async function sendAPNs(env, token, environment, event, contentState, attributes = null) {
  if (!requiredAPNs(env)) return { configured: false, status: 0 };
  const jwt = await apnsJWT(env);
  const payload = { aps: { timestamp: Math.floor(Date.now() / 1000), event, "content-state": contentState } };
  if (event === "start") {
    payload.aps["attributes-type"] = "ChargingActivityAttributes";
    payload.aps.attributes = attributes;
  }
  if (event === "end") payload.aps["dismissal-date"] = Math.floor(Date.now() / 1000);
  const host = environment === "sandbox" ? "https://api.sandbox.push.apple.com" : "https://api.push.apple.com";
  const response = await fetch(`${host}/3/device/${token}`, {
    method: "POST",
    headers: { authorization: `bearer ${jwt}`, "apns-topic": `${env.APNS_BUNDLE_ID}.push-type.liveactivity`, "apns-push-type": "liveactivity", "apns-priority": "10", "content-type": "application/json" },
    body: JSON.stringify(payload)
  });
  return { configured: true, status: response.status, reason: response.status === 410 ? "invalid" : null };
}

function bearer(request) {
  const value = request.headers.get("authorization") || "";
  return value.startsWith("Bearer ") ? value.slice(7) : null;
}

async function authenticate(request, env) {
  const token = bearer(request);
  if (!token) return null;
  const tokenHash = await sha256(token);
  return env.DB.prepare("SELECT installation_id FROM installations WHERE auth_token_hash = ? AND revoked_at IS NULL")
    .bind(tokenHash).first();
}

function validateVehicleID(value) {
  return typeof value === "string" && /^v1-[0-9a-f]{32}$/.test(value);
}

function validateEnvironment(value) { return value === "sandbox" || value === "production"; }
function validateMode(value) { return value === "fast" || value === "allAC" || value === "both"; }

function garageVINs(garage) {
  const vins = new Set();
  const visit = (value) => {
    if (!value || typeof value !== "object") return;
    for (const [key, item] of Object.entries(value)) {
      if (key.toLowerCase() === "vin" && typeof item === "string") vins.add(item.toUpperCase());
      else if (item && typeof item === "object") visit(item);
    }
  };
  visit(garage);
  return [...vins];
}

async function bootstrap(request, env) {
  // Bootstrap accepts a current Ford access token only as a one-time proof.
  // It is used to fetch the garage; the Worker stores neither it nor a Ford
  // refresh token. The opaque vehicle ID must match a VIN returned by Ford.
  const fordToken = bearer(request);
  if (!fordToken) return json({ error: "Unauthorized" }, 401);
  const body = await request.json().catch(() => null);
  if (!body || !validateVehicleID(body.opaqueVehicleID)) return json({ error: "Invalid opaqueVehicleID" }, 400);
  const fordCheck = await fetch("https://api.vehicle.ford.com/fcon-query/v1/garage", {
    headers: { Authorization: `Bearer ${fordToken}`, Accept: "application/json" }
  });
  if (!fordCheck.ok) return json({ error: "Ford authorization required" }, 401);
  const garage = await fordCheck.json().catch(() => null);
  const vins = garageVINs(garage);
  const expectedVehicleIDs = await Promise.all(vins.map((vin) => sha256(vin.toUpperCase()).then((hash) => `v1-${hash.slice(0, 32)}`)));
  if (!expectedVehicleIDs.includes(body.opaqueVehicleID)) return json({ error: "Vehicle authorization required" }, 403);
  const installationID = id();
  const token = `${id()}${id()}`.replaceAll("-", "");
  const tokenHash = await sha256(token);
  const timestamp = nowISO();
  await env.DB.prepare(`INSERT INTO installations
      (installation_id, auth_token_hash, created_at, updated_at)
      VALUES (?, ?, ?, ?)`)
    .bind(installationID, tokenHash, timestamp, timestamp).run();
  return json({ installationID, token });
}

async function enroll(request, env, principal) {
  const body = await request.json().catch(() => null);
  if (!body || !validateVehicleID(body.opaqueVehicleID) || !validateEnvironment(body.apnsEnvironment)) {
    return json({ error: "Invalid enrollment" }, 400);
  }
  const mode = validateMode(body.chargingMode) ? body.chargingMode : "both";
  const timestamp = nowISO();
  const enrollmentID = id();
  await env.DB.prepare(`INSERT INTO enrollments
      (enrollment_id, installation_id, opaque_vehicle_id, apns_environment, charging_mode, status, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, 'enrolled', ?, ?)
      ON CONFLICT(installation_id, opaque_vehicle_id) DO UPDATE SET
        apns_environment=excluded.apns_environment,
        charging_mode=excluded.charging_mode,
        status='enrolled', revoked_at=NULL, updated_at=excluded.updated_at`)
    .bind(enrollmentID, principal.installation_id, body.opaqueVehicleID, body.apnsEnvironment, mode, timestamp, timestamp).run();
  const row = await env.DB.prepare("SELECT enrollment_id FROM enrollments WHERE installation_id=? AND opaque_vehicle_id=?")
    .bind(principal.installation_id, body.opaqueVehicleID).first();
  await env.DB.prepare(`INSERT INTO vehicle_poll_state (enrollment_id, next_poll_at, updated_at)
      VALUES (?, ?, ?)
      ON CONFLICT(enrollment_id) DO NOTHING`)
    .bind(row.enrollment_id, nowISO(), timestamp).run();
  return json({ status: "enrolled", enrollmentID: row.enrollment_id });
}

async function authorizeFord(request, env, principal) {
  const body = await request.json().catch(() => null);
  if (!body || typeof body.refreshToken !== "string" || body.refreshToken.length < 20
      || !validateVehicleID(body.opaqueVehicleID)) {
    return json({ error: "Invalid Ford authorization" }, 400);
  }
  const existing = await env.DB.prepare("SELECT enrollment_id FROM enrollments WHERE installation_id=? AND opaque_vehicle_id=? AND status='enrolled'")
    .bind(principal.installation_id, body.opaqueVehicleID).first();
  if (!existing) return json({ error: "Not enrolled" }, 409);
  const exchanged = await fordTokenExchange(env, {
    grant_type: "refresh_token",
    refresh_token: body.refreshToken,
    redirect_uri: body.redirectURI || FORD_REDIRECT_URI
  });
  if (!exchanged.response.ok || !exchanged.payload?.access_token || !exchanged.payload?.refresh_token) {
    return json({ error: "Ford reauthorization required" }, 401);
  }
  const garageResponse = await fetch(`${FORD_DATA_BASE}/garage`, {
    headers: { Authorization: `Bearer ${exchanged.payload.access_token}`, Accept: "application/json" }
  });
  const garage = await garageResponse.json().catch(() => null);
  let matchedVIN = null;
  for (const vin of garageVINs(garage)) {
    if (`v1-${(await sha256(vin)).slice(0, 32)}` === body.opaqueVehicleID) {
      matchedVIN = vin;
      break;
    }
  }
  if (!matchedVIN) return json({ error: "Vehicle authorization required" }, 403);
  const timestamp = nowISO();
  const accountID = `ford-${principal.installation_id}`;
  await env.DB.prepare(`INSERT INTO ford_accounts
      (ford_account_id, installation_id, refresh_token_ciphertext, token_expires_at, status, created_at, updated_at)
      VALUES (?, ?, ?, ?, 'active', ?, ?)
      ON CONFLICT(ford_account_id) DO UPDATE SET
        refresh_token_ciphertext=excluded.refresh_token_ciphertext,
        token_expires_at=excluded.token_expires_at, status='active', updated_at=excluded.updated_at`)
    .bind(accountID, principal.installation_id, await encrypt(exchanged.payload.refresh_token, env),
      exchanged.payload.refresh_token_expires_in ? new Date(Date.now() + exchanged.payload.refresh_token_expires_in * 1000).toISOString() : null,
      timestamp, timestamp).run();
  await env.DB.prepare(`UPDATE enrollments SET vehicle_ciphertext=?, updated_at=?
      WHERE installation_id=? AND opaque_vehicle_id=? AND status='enrolled'`)
    .bind(await encrypt(matchedVIN, env), timestamp, principal.installation_id, body.opaqueVehicleID).run();
  return json({ status: "authorized" });
}

async function capability(env, principal, opaqueVehicleID) {
  if (!validateVehicleID(opaqueVehicleID)) return json({ status: "unavailable", reason: "Invalid vehicle" }, 400);
  const row = await env.DB.prepare(`SELECT enrollment_id, status FROM enrollments
    WHERE installation_id=? AND opaque_vehicle_id=? AND revoked_at IS NULL`)
    .bind(principal.installation_id, opaqueVehicleID).first();
  if (!row) return json({ status: "eligible", reason: null, enrollmentID: null });
  return json({ status: row.status, reason: null, enrollmentID: row.enrollment_id });
}

async function revoke(env, principal, opaqueVehicleID) {
  const timestamp = nowISO();
  await env.DB.prepare(`UPDATE enrollments SET status='revoked', revoked_at=?, updated_at=?
    WHERE installation_id=? AND opaque_vehicle_id=?`).bind(timestamp, timestamp, principal.installation_id, opaqueVehicleID).run();
  return json({});
}

async function updateToken(request, env, principal) {
  const body = await request.json().catch(() => null);
  if (!body || !validateVehicleID(body.opaqueVehicleID) || !validateEnvironment(body.apnsEnvironment)
      || !["pushToStart", "activity"].includes(body.tokenKind)
      || typeof body.token !== "string" || !/^[0-9a-f]{16,512}$/.test(body.token)
      || (body.tokenKind === "activity" && typeof body.activityID !== "string")) {
    return json({ error: "Invalid token registration" }, 400);
  }
  const enrollment = await env.DB.prepare(`SELECT enrollment_id FROM enrollments
    WHERE installation_id=? AND opaque_vehicle_id=? AND status='enrolled' AND revoked_at IS NULL`)
    .bind(principal.installation_id, body.opaqueVehicleID).first();
  if (!enrollment) return json({ error: "Not enrolled" }, 409);
  const timestamp = nowISO();
  const tokenHash = await sha256(body.token);
  const encryptedToken = await encrypt(body.token, env);
  await env.DB.prepare(`INSERT INTO activity_tokens
      (token_id, enrollment_id, token_kind, token_ciphertext, token_hash, apns_environment, activity_id, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(enrollment_id, token_kind, activity_id) DO UPDATE SET
        token_ciphertext=excluded.token_ciphertext, token_hash=excluded.token_hash,
        apns_environment=excluded.apns_environment, invalidated_at=NULL, updated_at=excluded.updated_at`)
    .bind(id(), enrollment.enrollment_id, body.tokenKind, encryptedToken, tokenHash,
      body.apnsEnvironment, body.activityID || "", timestamp, timestamp).run();
  return json({});
}

async function preferences(request, env, principal, opaqueVehicleID) {
  const body = await request.json().catch(() => null);
  if (!body || !validateMode(body.chargingMode)) return json({ error: "Invalid chargingMode" }, 400);
  await env.DB.prepare(`UPDATE enrollments SET charging_mode=?, updated_at=?
    WHERE installation_id=? AND opaque_vehicle_id=? AND status='enrolled'`)
    .bind(body.chargingMode, nowISO(), principal.installation_id, opaqueVehicleID).run();
  return json({ chargingMode: body.chargingMode });
}

async function testLiveActivity(request, env, principal) {
  const body = await request.json().catch(() => null);
  const action = body?.action;
  const opaqueVehicleID = body?.opaqueVehicleID;
  if (!validateVehicleID(opaqueVehicleID) || !["start", "update", "end"].includes(action)) {
    return json({ error: "Invalid live activity test request" }, 400);
  }
  const enrollment = await env.DB.prepare(`SELECT enrollment_id, apns_environment
      FROM enrollments WHERE installation_id=? AND opaque_vehicle_id=?
      AND status='enrolled' AND revoked_at IS NULL`)
    .bind(principal.installation_id, opaqueVehicleID).first();
  if (!enrollment) return json({ error: "Not enrolled" }, 409);

  // Each action is deliberately one-shot. The UI can call start, update, and end
  // independently, which makes APNs failures diagnosable without touching Ford.
  const tokenKind = action === "start" ? "pushToStart" : "activity";
  const tokens = await env.DB.prepare(`SELECT token_ciphertext, apns_environment, activity_id
      FROM activity_tokens WHERE enrollment_id=? AND token_kind=? AND invalidated_at IS NULL
      ORDER BY updated_at DESC LIMIT 10`)
    .bind(enrollment.enrollment_id, tokenKind).all();
  if (!tokens.results?.length) return json({ error: `No ${tokenKind} token registered` }, 409);

  const contentState = {
    phase: action === "end" ? "plugged" : "active",
    powerKW: action === "end" ? 0 : action === "update" ? 7.4 : 7.2,
    socPercent: action === "end" ? 43 : action === "update" ? 42 : 41,
    rangeKm: null,
    timeToFullMinutes: action === "end" ? null : 97,
    startedAt: new Date(Date.now() - 60_000).toISOString(),
    lastSourceUpdatedAt: nowISO(),
    isStale: false
  };
  const results = [];
  for (const row of tokens.results) {
    const token = await decrypt(row.token_ciphertext, env);
    const result = await sendAPNs(env, token, row.apns_environment || enrollment.apns_environment,
      action, contentState, action === "start" ? { sessionID: `test-${id()}`, vehicleDisplayName: "Test vehicle" } : null);
    results.push({ status: result.status, reason: result.reason || null, activityID: row.activity_id || null });
    if (result.reason === "invalid") {
      await env.DB.prepare("UPDATE activity_tokens SET invalidated_at=?, updated_at=? WHERE enrollment_id=? AND token_kind=? AND activity_id=?")
        .bind(nowISO(), nowISO(), enrollment.enrollment_id, tokenKind, row.activity_id || "").run();
    }
  }
  return json({ action, results });
}

async function status(env) {
  const enrolled = await env.DB.prepare("SELECT COUNT(*) AS count FROM enrollments WHERE status='enrolled'").first();
  const ford = await env.DB.prepare("SELECT COUNT(*) AS count FROM ford_accounts WHERE status='active'").first();
  const tokens = await env.DB.prepare("SELECT COUNT(*) AS count FROM activity_tokens WHERE invalidated_at IS NULL").first();
  const lastTick = await env.DB.prepare("SELECT value, updated_at FROM service_state WHERE key='last_cron_tick'").first();
  const config = requiredAPNs(env) ? "configured" : "notConfigured";
  const enrolledVehicles = enrolled?.count || 0;
  const fordAuthorizations = ford?.count || 0;
  return json({
    service: "cellblock-live-activities",
    status: "ok",
    enrolledVehicles,
    fordAuthorizations,
    activityTokens: tokens?.count || 0,
    apns: config,
    apnsInputs: {
      team: Boolean(env.APNS_TEAM_ID),
      keyID: Boolean(env.APNS_KEY_ID),
      privateKey: Boolean(apnsPrivateKey(env)),
      bundleID: Boolean(env.APNS_BUNDLE_ID)
    },
    scheduler: lastTick ? "active" : "notObserved",
    lastCronTick: lastTick ? { at: lastTick.updated_at, ...(JSON.parse(lastTick.value || "{}")) } : null,
    backgroundPolling: enrolledVehicles > 0 && fordAuthorizations > 0 ? "active" : "waitingForEnrollment"
  });
}

async function fetchHandler(request, env) {
  const url = new URL(request.url);
  if (request.method === "GET" && url.pathname === "/health") return status(env);
  if (request.method === "POST" && url.pathname === "/api/installations/bootstrap") return bootstrap(request, env);
  const principal = await authenticate(request, env);
  if (!principal) return json({ error: "Unauthorized" }, 401);
  if (request.method === "POST" && url.pathname === "/api/live-activities/enroll") return enroll(request, env, principal);
  if (request.method === "POST" && url.pathname === "/api/ford/authorize") return authorizeFord(request, env, principal);
  if (request.method === "PUT" && url.pathname === "/api/live-activities/tokens") return updateToken(request, env, principal);
  const capabilityMatch = url.pathname.match(/^\/api\/live-activities\/capability\/(.+)$/);
  if (request.method === "GET" && capabilityMatch) return capability(env, principal, decodeURIComponent(capabilityMatch[1]));
  const enrollmentMatch = url.pathname.match(/^\/api\/live-activities\/enroll\/(.+)$/);
  if (request.method === "DELETE" && enrollmentMatch) return revoke(env, principal, decodeURIComponent(enrollmentMatch[1]));
  const preferenceMatch = url.pathname.match(/^\/api\/live-activities\/preferences\/(.+)$/);
  if (request.method === "PUT" && preferenceMatch) return preferences(request, env, principal, decodeURIComponent(preferenceMatch[1]));
  if (request.method === "POST" && url.pathname === "/api/live-activities/test") return testLiveActivity(request, env, principal);
  return json({ error: "Not found" }, 404);
}

function toNumber(value) {
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}

function extractMetric(payload, names) {
  const wanted = new Set(names.map((name) => name.toLowerCase()));
  let result = null;
  const visit = (value) => {
    if (!value || typeof value !== "object" || result !== null) return;
    for (const [key, item] of Object.entries(value)) {
      if (wanted.has(key.toLowerCase())) {
        const number = toNumber(typeof item === "object" ? item?.value : item);
        if (number !== null) { result = number; return; }
      }
      visit(item);
    }
  };
  visit(payload);
  return result;
}

function sourceTimestamp(payload) {
  const candidates = ["sourceUpdatedAt", "updatedAt", "timestamp", "lastUpdated"];
  let found = null;
  const visit = (value) => {
    if (!value || typeof value !== "object" || found) return;
    for (const [key, item] of Object.entries(value)) {
      if (candidates.includes(key) && typeof item === "string" && !Number.isNaN(Date.parse(item))) found = new Date(item);
      visit(item);
    }
  };
  visit(payload);
  return found;
}

function phaseFromTelemetry(payload, powerKW) {
  const text = JSON.stringify(payload).toUpperCase();
  if (text.includes("CHARGING") && (powerKW ?? 0) >= 0.5) return "active";
  if (text.includes("PLUGGED") || text.includes("CONNECTED")) return "plugged";
  return "unplugged";
}

function sessionEvent(previousPhase, phase) {
  if (phase === "active" && previousPhase !== "active") return "start";
  if (previousPhase === "active" && phase !== "active") return "end";
  return "update";
}

async function pollDue(env) {
  const now = new Date();
  const rows = await env.DB.prepare(`SELECT e.enrollment_id, e.opaque_vehicle_id, e.apns_environment, e.charging_mode,
      e.vehicle_ciphertext, p.next_poll_at, p.charge_phase, p.last_source_updated_at,
      f.refresh_token_ciphertext, f.ford_account_id
      FROM enrollments e JOIN vehicle_poll_state p ON p.enrollment_id=e.enrollment_id
      JOIN installations i ON i.installation_id=e.installation_id AND i.revoked_at IS NULL
      JOIN ford_accounts f ON f.installation_id=e.installation_id AND f.status='active'
      WHERE e.status='enrolled' AND e.revoked_at IS NULL AND (p.next_poll_at IS NULL OR p.next_poll_at <= ?)
      LIMIT 20`).bind(now.toISOString()).all();
  let polled = 0;
  for (const row of rows.results || []) {
    try {
      const refreshToken = await decrypt(row.refresh_token_ciphertext, env);
      const exchanged = await fordTokenExchange(env, { grant_type: "refresh_token", refresh_token: refreshToken });
      if (!exchanged.response.ok || !exchanged.payload?.access_token) throw new Error("Ford refresh rejected");
      const vin = await decrypt(row.vehicle_ciphertext, env);
      const telemetryResponse = await fetch(`${FORD_DATA_BASE}/telemetry?vin=${encodeURIComponent(vin)}`, {
        headers: { Authorization: `Bearer ${exchanged.payload.access_token}`, Accept: "application/json" }
      });
      if (!telemetryResponse.ok) throw new Error("Ford telemetry unavailable");
      const telemetry = await telemetryResponse.json();
      const sourceAt = sourceTimestamp(telemetry);
      if (!sourceAt || (row.last_source_updated_at && sourceAt <= new Date(row.last_source_updated_at))) throw new Error("stale telemetry");
      const powerKW = extractMetric(telemetry, ["calculatedChargePower", "chargePowerKW", "chargeRateKW"]);
      const soc = extractMetric(telemetry, ["stateOfCharge", "socPercent", "batteryLevel"]);
      const phase = phaseFromTelemetry(telemetry, powerKW);
      const intervalMinutes = phase === "active" ? 2 : phase === "plugged" ? 4 : 12;
      const event = sessionEvent(row.charge_phase, phase);
      const sessionID = event === "start" ? `${row.enrollment_id}-${sourceAt.getTime()}` : row.last_session_id;
      await env.DB.prepare(`UPDATE vehicle_poll_state SET next_poll_at=?, last_source_updated_at=?, charge_phase=?, last_soc=?, last_power_kw=?, last_session_id=?, session_started_at=COALESCE(session_started_at, ?), consecutive_qualifying=0, consecutive_nonqualifying=0, updated_at=? WHERE enrollment_id=?`)
        .bind(new Date(Date.now() + intervalMinutes * 60000).toISOString(), sourceAt.toISOString(), phase, soc, powerKW, sessionID, event === "start" ? sourceAt.toISOString() : null, nowISO(), row.enrollment_id).run();
      await env.DB.prepare("UPDATE ford_accounts SET refresh_token_ciphertext=?, token_expires_at=?, updated_at=? WHERE ford_account_id=?")
        .bind(await encrypt(exchanged.payload.refresh_token, env), exchanged.payload.refresh_token_expires_in ? new Date(Date.now() + exchanged.payload.refresh_token_expires_in * 1000).toISOString() : null, nowISO(), row.ford_account_id).run();
      const tokenRows = await env.DB.prepare(`SELECT token_ciphertext, apns_environment, token_kind, activity_id
          FROM activity_tokens WHERE enrollment_id=? AND invalidated_at IS NULL`).bind(row.enrollment_id).all();
      for (const tokenRow of tokenRows.results || []) {
        const token = await decrypt(tokenRow.token_ciphertext, env);
        const tokenEvent = event === "start" && tokenRow.token_kind === "pushToStart" ? "start" : event;
        const result = await sendAPNs(env, token, tokenRow.apns_environment, tokenEvent, {
          phase,
          powerKW,
          socPercent: soc,
          rangeKm: null,
          timeToFullMinutes: null,
          startedAt: sourceAt.toISOString(),
          lastSourceUpdatedAt: sourceAt.toISOString(),
          isStale: false
        }, tokenEvent === "start" ? { sessionID, vehicleDisplayName: "Your vehicle" } : null);
        if (result.reason === "invalid") await env.DB.prepare("UPDATE activity_tokens SET invalidated_at=?, updated_at=? WHERE enrollment_id=? AND token_kind=? AND activity_id=?").bind(nowISO(), nowISO(), row.enrollment_id, tokenRow.token_kind, tokenRow.activity_id).run();
      }
      polled++;
    } catch (error) {
      const next = new Date(Date.now() + 15 * 60000).toISOString();
      await env.DB.prepare("UPDATE vehicle_poll_state SET next_poll_at=?, updated_at=? WHERE enrollment_id=?").bind(next, nowISO(), row.enrollment_id).run();
      if (String(error).includes("refresh rejected")) await env.DB.prepare("UPDATE ford_accounts SET status='reauthorizationRequired', updated_at=? WHERE ford_account_id=?").bind(nowISO(), row.ford_account_id).run();
    }
  }
  return polled;
}

async function scheduledHandler(_event, env) {
  const polled = await pollDue(env);
  await env.DB.prepare("UPDATE service_state SET value=?, updated_at=? WHERE key='last_cron_tick'").bind(JSON.stringify({ at: nowISO(), polled }), nowISO()).run();
}

export default { fetch: fetchHandler, scheduled: scheduledHandler };
export { fetchHandler, validateVehicleID, validateMode, testLiveActivity };
