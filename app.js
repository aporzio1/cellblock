// ===== CellBlock — Ford EV Telemetry Dashboard =====

// ===== CONFIG =====
// Endpoints below are confirmed against the real FordConnect-2.0-Postman
// collection (Azure AD B2C auth, /fcon-query/v1/* data API) — the previous
// login.ford.com / /vehicles/v1/vehicles/{vin}/* endpoints this app used
// before were invented and don't exist in the real API.
const CLIENT_ID = 'd98bc150-b7d4-476c-98ce-10951345caf6';
const REDIRECT_URI = window.location.origin + window.location.pathname;
// Confirmed straight from Ford's own FCON2.0-Documentation PDF (sent by Ford
// support, 2026-05-13) — this is the actual account-linking init endpoint,
// distinct from both the raw Azure B2C authorize URL and the FordPass
// consumer common/login wrapper (both of which we tried first, based on
// third-party sources, and both of which were wrong for FordConnect 2.0).
const FORD_AUTHORIZE_URL = 'https://api.vehicle.ford.com/fcon-public/v1/auth/init';
// Backend proxy — see server/. Handles two things a browser can't do itself:
// (1) FordConnect's token endpoint requires a client_secret, which can never
// live in browser JS; (2) api.vehicle.ford.com sends no CORS headers at all,
// confirmed live — a direct browser fetch to its data endpoints fails
// regardless of how valid the bearer token is. So both token exchange *and*
// vehicle-data calls are routed through this proxy instead of straight to Ford.
const BACKEND_BASE = 'https://proxy.cellblock.cc';
const API_BASE = `${BACKEND_BASE}/api/data`;
const REFRESH_KEY = 'ford_refresh';
// Fallback bound on refresh-token lifetime when Ford's token response doesn't
// tell us its own expiry. See the TOKEN STORAGE section below for the
// security rationale and a longer-term server-side recommendation.
const REFRESH_MAX_AGE_MS = 14 * 24 * 60 * 60 * 1000; // 14 days

// ===== STATE =====
let accessToken = null;
let refreshToken = null;
let vehicleData = {};
let refreshPromise = null;         // single-flight guard
let vinCache = null;               // VIN doesn't change, fetch once
let refs = {};                     // cached DOM lookups

// Real /telemetry doorStatus array entries are keyed by vehicleDoor +
// vehicleOccupantRole (e.g. {vehicleDoor:"REAR_LEFT", vehicleOccupantRole:
// "PASSENGER"}), confirmed live — not the simple driverFrontDoor-style keys
// originally guessed. This maps a raw entry to a friendly label.
function doorLabel(entry) {
  switch (entry.vehicleDoor) {
    case 'UNSPECIFIED_FRONT': return entry.vehicleOccupantRole === 'DRIVER' ? 'Driver Front' : 'Passenger Front';
    case 'REAR_LEFT': return 'Rear Left';
    case 'REAR_RIGHT': return 'Rear Right';
    case 'TAILGATE': return 'Tailgate';
    case 'INNER_TAILGATE': return 'Inner Tailgate';
    default: return (entry.vehicleDoor || 'Door').replace(/_/g, ' ');
  }
}

// Tire PSI thresholds
const TIRE_DANGER = { low: 28, high: 48 };
const TIRE_WARN = { low: 32, high: 44 };
const TIRE_LABELS = { 'tire-fl': 'Front Left', 'tire-fr': 'Front Right', 'tire-rl': 'Rear Left', 'tire-rr': 'Rear Right' };
// Real /telemetry tirePressure array is keyed by vehicleWheel, in kPa.
const TIRE_WHEELS = { 'tire-fl': 'FRONT_LEFT', 'tire-fr': 'FRONT_RIGHT', 'tire-rl': 'REAR_LEFT', 'tire-rr': 'REAR_RIGHT' };

// SOC gauge geometry — 270deg arc (see index.html transform="rotate(135 ...)")
const SOC_ARC_LENGTH = 2 * Math.PI * 85 * 0.75; // ~400.55

// ===== UNIT CONVERSION =====
// Confirmed live: /telemetry reports in metric SI regardless of the
// account's displaySystemOfMeasure setting (temps in °C, pressure in kPa,
// distance/speed in km — outsideTemperature of 35.5 on a summer day, and
// tire pressures of ~260kPa/~38psi matching an F-150 placard, both confirm
// this rather than guessing).
const cToF = c => typeof c === 'number' ? c * 9 / 5 + 32 : undefined;
const kpaToPsi = kpa => typeof kpa === 'number' ? kpa / 6.89476 : undefined;
const kmToMi = km => typeof km === 'number' ? km * 0.621371 : undefined;
const mToFt = m => typeof m === 'number' ? m * 3.28084 : undefined;

// ===== INIT — single path =====
document.addEventListener('DOMContentLoaded', () => {
  cacheDom();
  const params = new URLSearchParams(window.location.search);
  if (params.has('demo')) {
    loadDemoData();
  } else if (params.has('code')) {
    handleCallback();
  } else {
    loadSession();
  }
});

// ===== DEMO MODE — ?demo=1, bypasses OAuth entirely with mock data =====
// Mock shape below mirrors a real /telemetry response captured live
// (metrics.<name>.value nesting, kPa/°C/km units, array-based door/tire
// entries) — see renderDashboard() for the real field mapping.
function loadDemoData() {
  showDashboard();
  setStatus('DEMO MODE — mock data, not a live Ford connection');
  refs['vin-display'].textContent = 'DEMO-VIN-0000000';

  const metric = value => ({ value });

  vehicleData = {
    telemetry: {
      metrics: {
        xevBatteryStateOfCharge: metric(100),
        xevBatteryRange: metric(457.8),
        xevBatteryChargeDisplayStatus: metric('NOT_READY'),
        xevBatteryVoltage: metric(391.5),
        xevBatteryTemperature: metric(30),
        xevBatteryChargerVoltageOutput: metric(4),
        xevBatteryChargerCurrentOutput: metric(0.1),
        xevBatteryPerformanceStatus: metric('NORMAL'),
        xevBatteryCapacity: metric(141.7),
        xevBatteryEnergyRemaining: metric(135.15),
        xevBatteryActualStateOfCharge: metric(95.83),
        odometer: metric(15600),
        outsideTemperature: metric(35.5),
        xevPlugChargerStatus: metric('DISCONNECTED'),
        xevBatteryTimeToFullCharge: metric(0),
        gearLeverPosition: metric('PARK'),
        ignitionStatus: metric('OFF'),
        alarmStatus: metric('DISARMED'),
        hoodStatus: metric('CLOSED'),
        tirePressure: [
          { vehicleWheel: 'FRONT_LEFT', value: 262 },
          { vehicleWheel: 'FRONT_RIGHT', value: 264 },
          { vehicleWheel: 'REAR_LEFT', value: 252 },
          { vehicleWheel: 'REAR_RIGHT', value: 274 }
        ],
        tirePressureStatus: [
          { vehicleWheel: 'FRONT_LEFT', value: 'NORMAL' },
          { vehicleWheel: 'FRONT_RIGHT', value: 'NORMAL' },
          { vehicleWheel: 'REAR_LEFT', value: 'NORMAL' },
          { vehicleWheel: 'REAR_RIGHT', value: 'NORMAL' }
        ],
        position: metric({ location: { lat: 42.999, lon: -83.781, alt: 240 } }),
        heading: metric({ heading: 85 }),
        speed: metric(0),
        acceleration: metric({ x: -0.015, y: 0.16, z: 0 }),
        doorStatus: [
          { vehicleDoor: 'UNSPECIFIED_FRONT', vehicleOccupantRole: 'DRIVER', value: 'CLOSED' },
          { vehicleDoor: 'REAR_LEFT', vehicleOccupantRole: 'PASSENGER', value: 'CLOSED' },
          { vehicleDoor: 'UNSPECIFIED_FRONT', vehicleOccupantRole: 'PASSENGER', value: 'CLOSED' },
          { vehicleDoor: 'REAR_RIGHT', vehicleOccupantRole: 'PASSENGER', value: 'CLOSED' },
          { vehicleDoor: 'TAILGATE', vehicleOccupantRole: 'PASSENGER', value: 'CLOSED' },
          { vehicleDoor: 'INNER_TAILGATE', vehicleOccupantRole: 'PASSENGER', value: 'CLOSED' }
        ]
      }
    },
    health: { VehicleAlertList: [{ Vin: 'DEMO-VIN-0000000', ActiveAlerts: [], StatusCode: 200, StatusDesc: 'OK' }] },
    wallbox: null, departureTimes: null, chargeSchedules: null,
    vin: 'DEMO-VIN-0000000',
    fetchOk: { telemetry: true, health: true, wallbox: false, departureTimes: false, chargeSchedules: false }
  };

  renderDashboard();
}

function cacheDom() {
  const ids = [
    'login-screen','dashboard','refresh-bar','login-btn','logout-btn',
    'connection-status','soc-circle','soc-value','range-value','charge-status',
    'pack-voltage','battery-temp','charge-rate','vin-display','health-score',
    'lat','lon','alt','heading','speed','accel',
    'doors-grid','health-alerts',
    'tire-fl','tire-fr','tire-rl','tire-rr',
    'last-update','top-alerts','badge-vehicle','badge-tire','manual-token-input',
    'vehicle-image','vehicle-image-card',
    'battery-capacity','energy-remaining','odometer-display','outside-temp',
    'time-to-full','gear-position','ignition-status'
  ];
  for (const id of ids) refs[id] = document.getElementById(id);
}

function loadSession() {
  refreshToken = loadRefreshToken();
  if (refreshToken) {
    showDashboard();
    setStatus('Restoring session...');
    // Proactively refresh the access token before making data calls
    refreshAccessToken().then(() => {
      refreshData();
    }).catch(() => {
      // refreshAccessToken already calls logout() on failure
      // which shows the login screen — no action needed here
    });
  } else {
    showLogin();
  }
}

// ===== AUTH =====
// No PKCE here — the real FordConnect token endpoint has no code_verifier
// field in its request body (confirmed via the Postman collection), so it
// doesn't validate one. state is still used for CSRF protection.
function startLogin() {
  const state = generateState();
  sessionStorage.setItem('auth_state', state);

  const url = new URL(FORD_AUTHORIZE_URL);
  url.searchParams.set('client_id', CLIENT_ID);
  url.searchParams.set('state', state);
  url.searchParams.set('redirect_uri', REDIRECT_URI);

  window.location.href = url.toString();
}

// Dev/testing bypass — real API, real token, just not acquired through our
// (currently Ford-side-broken, AADB2C90006) browser login redirect. Accepts
// either a bare access token string or the full JSON response from a manual
// token exchange (e.g. Postman). If a refresh_token is present it's persisted
// normally via saveRefreshToken; if not, the session just ends when the
// pasted access token expires.
function useManualToken() {
  const raw = refs['manual-token-input']?.value.trim();
  if (!raw) return;

  let access = raw;
  let refresh = null;
  let expiresIn = null;

  try {
    const parsed = JSON.parse(raw);
    if (parsed.access_token) {
      access = parsed.access_token;
      refresh = parsed.refresh_token ?? null;
      expiresIn = parsed.refresh_token_expires_in ?? null;
    }
  } catch {
    // not JSON — treat the whole input as a bare access token
  }

  accessToken = access;
  refreshToken = refresh;
  if (refresh) saveRefreshToken(refresh, expiresIn);

  showDashboard();
  refreshData();
}

function handleCallback() {
  const urlParams = new URLSearchParams(window.location.search);
  const code = urlParams.get('code');
  const state = urlParams.get('state');

  if (!code || !state) { loadSession(); return; }

  const savedState = sessionStorage.getItem('auth_state');
  sessionStorage.removeItem('auth_state');
  if (state !== savedState) {
    showError('Invalid auth state — session may have expired. Please try again.');
    history.replaceState(null, '', window.location.pathname);
    loadSession();
    return;
  }

  exchangeCodeForToken(code);
}

async function exchangeCodeForToken(code) {
  try {
    const resp = await fetch(`${BACKEND_BASE}/api/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code, redirect_uri: REDIRECT_URI })
    });

    if (!resp.ok) {
      const body = await resp.text();
      throw new Error(`Token exchange failed (${resp.status}): ${body}`);
    }

    const data = await resp.json();
    accessToken = data.access_token;
    refreshToken = data.refresh_token;
    saveRefreshToken(refreshToken, data.refresh_token_expires_in);
    history.replaceState(null, '', window.location.pathname);
    showDashboard();
    refreshData();
  } catch (err) {
    showError('Failed to authenticate: ' + err.message);
  }
}

function generateState() {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  return Array.from(array, b => b.toString(16).padStart(2, '0')).join('');
}

// ===== TOKEN STORAGE =====
// Access token: memory only, never persisted.
// Refresh token: localStorage, wrapped with an explicit expiry so a stolen
// token (e.g. via XSS) is only useful for a bounded window instead of
// indefinitely — sessionStorage would force a Ford re-login every browser
// restart, which was rejected for UX; a bare localStorage string (the prior
// state) had no expiry at all.
//
// SECURITY NOTE: the server/ proxy (see AUTH section above) exists because
// FordConnect's token endpoint requires a client_secret — it holds that
// secret, nothing else. It does NOT change the tradeoff here: the refresh
// token itself still lives in the browser's localStorage, still fully
// exposed to an XSS bug in this page or a dependency. The properly secure
// pattern is the proxy setting the refresh token as an HttpOnly, Secure,
// SameSite=Strict cookie so JS never touches it at all — see SECURITY.md
// for what that would take and when to revisit it.
function saveRefreshToken(token, expiresInSeconds) {
  const hasValidServerExpiry = typeof expiresInSeconds === 'number' && expiresInSeconds > 0;
  const expiresAt = hasValidServerExpiry
    ? Date.now() + expiresInSeconds * 1000
    : Date.now() + REFRESH_MAX_AGE_MS;
  localStorage.setItem(REFRESH_KEY, JSON.stringify({ token, expiresAt }));
}

function loadRefreshToken() {
  const raw = localStorage.getItem(REFRESH_KEY);
  if (!raw) return null;

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    localStorage.removeItem(REFRESH_KEY); // stale pre-expiry format, discard
    return null;
  }

  if (!parsed?.token || typeof parsed.expiresAt !== 'number' || Date.now() >= parsed.expiresAt) {
    localStorage.removeItem(REFRESH_KEY);
    return null;
  }

  return parsed.token;
}

function clearTokens() {
  accessToken = null;
  refreshToken = null;
  localStorage.removeItem(REFRESH_KEY);
}

// ===== API — single-flight refresh, one-deep retry =====
async function apiCall(endpoint, retried = false) {
  const resp = await fetch(`${API_BASE}${endpoint}`, {
    headers: { 'Authorization': `Bearer ${accessToken}`, 'Accept': 'application/json' }
  });

  if (resp.status === 401 && refreshToken && !retried) {
    await refreshAccessToken();
    return apiCall(endpoint, true);
  }

  if (!resp.ok) throw new Error(`API error: ${resp.status}`);
  return resp.json();
}

async function refreshAccessToken() {
  if (refreshPromise) return refreshPromise;

  refreshPromise = (async () => {
    try {
      const resp = await fetch(`${BACKEND_BASE}/api/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token: refreshToken, redirect_uri: REDIRECT_URI })
      });

      if (resp.status === 429) {
        // Rate-limited — don't log out, just keep the old session
        console.warn('[auth] Rate limited during token refresh — session preserved');
        return;
      }

      if (!resp.ok) throw new Error(`Refresh failed: ${resp.status}`);

      const data = await resp.json();
      accessToken = data.access_token;
      refreshToken = data.refresh_token;
      saveRefreshToken(refreshToken, data.refresh_token_expires_in);
    } catch (err) {
      console.warn('[auth] Token refresh failed:', err.message);
      logout();
      throw err;
    } finally {
      refreshPromise = null;
    }
  })();

  return refreshPromise;
}

// ===== DATA FETCHING =====
// Cache last successful response per endpoint (sessionStorage, 5 min TTL)
const CACHE_TTL_MS = 5 * 60 * 1000;
const CACHE_KEY = 'cellblock_cache';

function loadCache() {
  try {
    const raw = sessionStorage.getItem(CACHE_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw);
    if (typeof parsed !== 'object') return {};
    return parsed;
  } catch { return {}; }
}

function saveToCache(key, data) {
  const cache = loadCache();
  cache[key] = { data, ts: Date.now() };
  try { sessionStorage.setItem(CACHE_KEY, JSON.stringify(cache)); } catch {}
}

function getFromCache(key) {
  const cache = loadCache();
  const entry = cache[key];
  if (!entry || Date.now() - entry.ts > CACHE_TTL_MS) return null;
  return entry.data;
}

function clearCache() {
  try { sessionStorage.removeItem(CACHE_KEY); } catch {}
}

let isRefreshing = false;

async function refreshData() {
  if (isRefreshing) return; // Prevent double-refreshes
  if (new URLSearchParams(window.location.search).has('demo')) {
    loadDemoData(); // re-render mock data instead of hitting the real API
    return;
  }

  isRefreshing = true;
  setStatus('Updating...');
  toggleLoading(true);

  try {
    if (!vinCache) {
      const garage = await apiCall('/garage');
      vinCache = firstVin(garage);
      if (!vinCache) {
        showError('No vehicles found in garage');
        return;
      }
    }

    refs['vin-display'].textContent = vinCache;

    // Fetch telemetry+health (critical), fall back to cache on failure
    let telemetry = getFromCache('telemetry');
    let health = getFromCache('health');
    if (!telemetry || !health) {
      try {
        const [t, h] = await Promise.all([
          apiCall(`/telemetry?vin=${vinCache}`),
          apiCall(`/vehicle-health/alerts?vin=${vinCache}`)
        ]);
        telemetry = t; health = h;
        if (telemetry) saveToCache('telemetry', telemetry);
        if (health) saveToCache('health', health);
      } catch (err) {
        console.warn('[refresh] primary calls failed:', err.message || err);
        if (!telemetry && !health) setStatus('Rate limited — showing cached data');
      }
    }

    // Secondary calls (wallbox/departure/charge) only attempt if caches are empty
    let wallbox = getFromCache('wallbox');
    let departureTimes = getFromCache('departureTimes');
    let chargeSchedules = getFromCache('chargeSchedules');
    if (!wallbox || !departureTimes || !chargeSchedules) {
      // Brief delay before secondary calls
      await new Promise(r => setTimeout(r, 1000));
      try {
        wallbox = await apiCall(`/wallbox?vin=${vinCache}`);
        if (wallbox) saveToCache('wallbox', wallbox);
      } catch (err) { console.warn('[wallbox]', err.message || err); }
      await new Promise(r => setTimeout(r, 1000));
      try {
        departureTimes = await apiCall(`/electric/departure-times?vin=${vinCache}`);
        if (departureTimes) saveToCache('departureTimes', departureTimes);
      } catch (err) { console.warn('[departure]', err.message || err); }
      await new Promise(r => setTimeout(r, 1000));
      try {
        chargeSchedules = await apiCall(`/electric/charge-schedules?vin=${vinCache}`);
        if (chargeSchedules) saveToCache('chargeSchedules', chargeSchedules);
      } catch (err) { console.warn('[chargeschedule]', err.message || err); }
    }

    vehicleData = {
      telemetry, health, wallbox, departureTimes, chargeSchedules,
      vin: vinCache,
      fetchOk: {
        telemetry: !!telemetry, health: !!health, wallbox: !!wallbox,
        departureTimes: !!departureTimes, chargeSchedules: !!chargeSchedules
      }
    };

    renderDashboard();
    loadVehicleImage(vinCache); // fire-and-forget, shows vehicle photo
    setStatus('Updated just now');
    setEl('last-update', `Last updated: ${new Date().toLocaleTimeString()}`);
  } catch (err) {
    console.error(err);
    setStatus('Error loading data');
  } finally {
    toggleLoading(false);
    isRefreshing = false;
  }
}

// Best-effort VIN extraction — the Postman collection has no saved example
// response for /garage, so this shape is a guess at common REST list
// conventions. Verify against a real response and adjust if it's wrong.
function firstVin(garage) {
  // Confirmed live: a single-vehicle garage returns a flat object with `vin`
  // directly on it (no array wrapper at all) — not the {vehicles:[...]} or
  // {data:[...]} list shape we'd guessed. Handle both, in case a multi-vehicle
  // garage responds with an actual array.
  if (Array.isArray(garage)) return garage[0]?.vin ?? null;
  if (Array.isArray(garage?.vehicles)) return garage.vehicles[0]?.vin ?? null;
  if (Array.isArray(garage?.data)) return garage.data[0]?.vin ?? null;
  return garage?.vin ?? null;
}

// Cheap loading feedback — pulse the primary readouts while a fetch is in flight
function toggleLoading(isLoading) {
  const ids = ['soc-value', 'range-value', 'pack-voltage', 'battery-temp', 'charge-rate'];
  for (const id of ids) {
    if (refs[id]) refs[id].classList.toggle('loading', isLoading);
  }
}

// ===== FORMAT HELPERS =====
function fmt(val, digits, unit) {
  if (typeof val !== 'number' || isNaN(val)) return '--';
  return `${val.toFixed(digits)}${unit ? ' ' + unit : ''}`;
}

function setEl(id, text) {
  if (refs[id]) refs[id].textContent = text;
}

// ===== RENDERING =====
function renderDashboard() {
  const { telemetry, health, fetchOk, wallbox, departureTimes, chargeSchedules } = vehicleData;

  // Confirmed live against a real F-150 Lightning: /telemetry returns
  // { updateTime, vehicleId, vin, metrics: { <name>: { value, updateTime,
  // oemCorrelationId, ... }, ... } } — a flat metrics bag, not the nested
  // battery/tires/gps/doors groups originally guessed. m() below reads a
  // metric's .value; units are metric SI regardless of account display
  // settings (see UNIT CONVERSION above).
  const metrics = telemetry?.metrics ?? {};
  const m = name => metrics[name]?.value;

  // SOC Ring — real EV pack SoC is xevBatteryStateOfCharge; batteryStateOfCharge
  // is the 12V auxiliary battery, a different thing entirely.
  const soc = m('xevBatteryStateOfCharge');
  const range = kmToMi(m('xevBatteryRange'));
  const circle = refs['soc-circle'];
  if (circle && typeof soc === 'number') {
    circle.style.strokeDashoffset = SOC_ARC_LENGTH - (soc / 100) * SOC_ARC_LENGTH;
    circle.style.stroke = soc > 20 ? 'var(--accent)' : soc > 10 ? 'var(--warn)' : 'var(--danger)';
  }
  setEl('soc-value', typeof soc === 'number' ? `${Math.round(soc)}%` : '--%');
  setEl('range-value', typeof range === 'number' ? `Range: ${Math.round(range)} mi` : 'Range: -- mi');

  // Charge status — xevBatteryChargeDisplayStatus is the user-facing status
  // field; xevPlugChargerStatus (plug connected/disconnected) is a fallback.
  const chargeStatus = m('xevBatteryChargeDisplayStatus') ?? m('xevPlugChargerStatus');
  const badge = refs['charge-status'];
  if (chargeStatus) {
    badge.textContent = chargeStatus.replace(/_/g, ' ');
    badge.style.background = chargeStatus.includes('CHARGING') ? 'var(--good-soft)' : 'var(--info-soft)';
    badge.style.color = chargeStatus.includes('CHARGING') ? 'var(--good)' : 'var(--info)';
    // Tooltip explaining charge status
    const TOOLTIPS = {
      CHARGING: 'Vehicle is actively charging',
      NOT_READY: 'Battery full or unplugged — not in a charge-ready state',
      CHARGED: 'Fully charged and still plugged in',
      READY: 'Ready to charge (plugged in, waiting for schedule or timer)',
      DISCONNECTED: 'Charge cable is not connected to the vehicle',
      ERROR: 'Charging system fault detected',
    };
    const key = chargeStatus.toUpperCase().replace(/ /g, '_');
    badge.title = TOOLTIPS[key] ?? `Charge status: ${chargeStatus.replace(/_/g, ' ')}`;
  } else if (!fetchOk.telemetry) {
    badge.textContent = 'Data unavailable';
    badge.style.background = 'var(--danger-soft)';
    badge.style.color = 'var(--danger)';
  } else {
    badge.textContent = '—';
    badge.style.background = 'transparent';
    badge.style.color = 'var(--text-dim)';
  }

  // Pack overview
  setEl('pack-voltage', fmt(m('xevBatteryVoltage'), 0, 'V'));
  setEl('battery-temp', fmt(cToF(m('xevBatteryTemperature')), 0, '°F'));
  const chargerV = m('xevBatteryChargerVoltageOutput');
  const chargerA = m('xevBatteryChargerCurrentOutput');
  const chargeRateKW = typeof chargerV === 'number' && typeof chargerA === 'number' ? (chargerV * chargerA) / 1000 : undefined;
  setEl('charge-rate', fmt(chargeRateKW, 1, 'kW'));
  setEl('battery-capacity', fmt(m('xevBatteryCapacity'), 1, 'kWh'));
  setEl('energy-remaining', fmt(m('xevBatteryEnergyRemaining'), 1, 'kWh'));
  setEl('odometer-display', fmt(kmToMi(m('odometer')), 0, 'mi'));
  setEl('outside-temp', fmt(cToF(m('outsideTemperature')), 0, '°F'));
  const timeToFull = m('xevBatteryTimeToFullCharge');
  setEl('time-to-full', typeof timeToFull === 'number' && timeToFull > 0 ? `${Math.round(timeToFull)} min` : '-- min');

  // Battery health — use Ford's own xevBatteryPerformanceStatus plus a
  // calculated percentage based on known design capacity. Uses VIN prefix
  // to determine model and apply the correct factory spec.
  const perfStatus = m('xevBatteryPerformanceStatus');
  const capacity = m('xevBatteryCapacity');
  
  // Ford EV design capacities (total, not usable) by VIN prefix.
  // These are reference points; if the reported capacity is significantly
  // different (new model year / battery variant), we use the reported value
  // as the baseline to avoid showing false degradation.
  const DESIGN_CAPACITY = {
    '1FT': 141,   // F-150 Lightning ER (pre-2025: 131kWh usable / ~141 total)
                   // 2025+ Flash: 123 kWh usable / ~132 total — handled by tolerance below
    '3FM': 98,    // Mustang Mach-E ER
    '1FM': 76,    // E-Transit
  };
  const vinPrefix = (vinCache || '').slice(0, 3);
  let designCapacity = DESIGN_CAPACITY[vinPrefix] || 100;
  // If reported capacity differs from known spec by >5%, assume a different
  // battery variant and use the reported value as the baseline (no degradation calc)
  if (typeof capacity === 'number' && capacity > 0) {
    const ratio = capacity / designCapacity;
    if (ratio < 0.95 || ratio > 1.05) {
      designCapacity = Math.round(capacity); // different battery, treat as baseline
    }
  }
  // Lightning SR detection: capacity well below ER spec
  if (vinPrefix === '1FT' && typeof capacity === 'number' && capacity < 110) designCapacity = 105;
  // Mach-E SR detection
  if (vinPrefix === '3FM' && typeof capacity === 'number' && capacity < 85) designCapacity = 75;
  
  const healthPct = typeof capacity === 'number' && capacity > 0
    ? Math.min(100, Math.round((capacity / designCapacity) * 100))
    : null;
  const scoreEl = refs['health-score'];
  if (perfStatus || healthPct) {
    const parts = [];
    if (perfStatus) parts.push(perfStatus.replace(/_/g, ' '));
    if (healthPct) parts.push(`${healthPct}%`);
    scoreEl.textContent = parts.join(' · ') || '—';
    const isGood = perfStatus === 'NORMAL' && (healthPct === null || healthPct >= 95);
    scoreEl.className = 'health-score ' + (isGood ? 'health-good' : 'health-warn');
  } else {
    scoreEl.textContent = fetchOk.telemetry ? '—' : 'No data';
    scoreEl.className = 'health-score ' + (fetchOk.telemetry ? '' : 'health-bad');
  }

  // Tires — real tirePressure is a bare array keyed by vehicleWheel, in kPa
  // (unlike scalar metrics, array-type metrics aren't wrapped in {value:...}
  // — each array element carries its own value/updateTime/etc. instead).
  const tireArray = metrics.tirePressure ?? [];
  const tirePsi = wheel => {
    const entry = Array.isArray(tireArray) ? tireArray.find(t => t.vehicleWheel === wheel) : null;
    return kpaToPsi(entry?.value);
  };
  const tireIssues = Object.keys(TIRE_WHEELS)
    .map(id => setTire(id, tirePsi(TIRE_WHEELS[id])))
    .filter(Boolean);
  setBadge('badge-tire', tireIssues.length);

  // GPS
  const position = m('position')?.location ?? {};
  const heading = m('heading')?.heading;
  const speedKmh = m('speed');
  const acc = m('acceleration');
  setEl('lat', position.lat ?? '--');
  setEl('lon', position.lon ?? '--');
  setEl('alt', position.alt != null ? `${Math.round(mToFt(position.alt))} ft` : '-- ft');
  setEl('heading', heading != null ? `${Math.round(heading)}°` : '--°');
  setEl('speed', speedKmh != null ? `${Math.round(kmToMi(speedKmh))} mph` : '-- mph');
  setEl('accel', acc ? `${acc.x.toFixed(2)}/${acc.y.toFixed(2)}/${acc.z.toFixed(2)} g` : '--/--/-- g');

  // Sub-renderers (all DOM-safe)
  const doors = normalizeDoors(metrics.doorStatus); // bare array, see tirePressure note above
  const openDoorCount = renderDoors(doors);
  const activeAlertCount = renderAlerts(health);

  setBadge('badge-vehicle', openDoorCount + activeAlertCount);
  renderTopAlerts(doors, health, tireIssues);

  // Vehicle info
  setEl('gear-position', m('gearLeverPosition')?.replace(/_/g, ' ') ?? '--');
  setEl('ignition-status', m('ignitionStatus')?.replace(/_/g, ' ') ?? '--');

  // Wallbox / charger status
  renderWallbox(wallbox);

  // Charge schedules
  renderChargeSchedules(chargeSchedules);

  // Departure times
  renderDepartureTimes(departureTimes);
}

// Real doorStatus array entries repeat the same physical door under multiple
// occupant-role contexts sometimes — dedupe by door+role so the grid doesn't
// show duplicate tiles for one door.
function normalizeDoors(doorArray) {
  if (!Array.isArray(doorArray)) return [];
  const seen = new Set();
  const out = [];
  for (const entry of doorArray) {
    const key = `${entry.vehicleDoor}|${entry.vehicleOccupantRole}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ label: doorLabel(entry), status: entry.value });
  }
  return out;
}

// Colors a tire tile by PSI threshold and returns an issue descriptor
// (or null if the tire is within normal range) for the badge/alert-strip counts.
function setTire(id, val) {
  const el = refs[id];
  if (!el) return null;

  el.querySelector('.tire-val').textContent = fmt(val, 0, 'PSI');
  el.classList.remove('tire-warn', 'tire-danger');

  if (typeof val !== 'number') return null;

  if (val < TIRE_DANGER.low || val > TIRE_DANGER.high) {
    el.classList.add('tire-danger');
    return { label: TIRE_LABELS[id], value: val, severity: 'CRITICAL' };
  }
  if (val < TIRE_WARN.low || val > TIRE_WARN.high) {
    el.classList.add('tire-warn');
    return { label: TIRE_LABELS[id], value: val, severity: 'WARNING' };
  }
  return null;
}

// Small severity glyph so status isn't color-only (colorblind-safe)
function severityGlyph(sev) {
  return sev === 'CRITICAL' || sev === 'WARNING' ? '▲' : '●';
}

function setBadge(id, count) {
  const el = refs[id];
  if (!el) return;
  if (count > 0) {
    el.textContent = `● ${count}`;
    el.classList.add('badge-active');
  } else {
    el.textContent = '';
    el.classList.remove('badge-active');
  }
}

// Builds the at-a-glance strip shown above the fold — surfaces the same
// signals that live inside the (closed-by-default) accordions below.
function renderTopAlerts(doors, healthData, tireIssues) {
  const strip = refs['top-alerts'];
  if (!strip) return;
  strip.replaceChildren();

  const items = [];
  const alerts = getActiveAlerts(healthData).map(normalizeAlert);

  for (const alert of alerts) {
    if (alert.severity === 'CRITICAL' || alert.severity === 'WARNING') {
      items.push({ severity: alert.severity, text: alert.text });
    }
  }

  for (const door of doors) {
    if (door.status === 'OPEN') {
      items.push({ severity: 'WARNING', text: `${door.label} is open` });
    }
  }

  for (const issue of tireIssues) {
    items.push({ severity: issue.severity, text: `${issue.label} tire at ${issue.value} PSI` });
  }

  if (!items.length) {
    strip.style.display = 'none';
    return;
  }

  strip.style.display = 'flex';
  for (const item of items) {
    const sevCls = item.severity === 'CRITICAL' ? 'alert-critical' : 'alert-warning';
    const div = document.createElement('div');
    div.className = 'alert-item ' + sevCls;

    const glyph = document.createElement('span');
    glyph.className = 'alert-glyph';
    glyph.setAttribute('aria-hidden', 'true');
    glyph.textContent = severityGlyph(item.severity);
    div.appendChild(glyph);

    div.appendChild(document.createTextNode(item.text));
    strip.appendChild(div);
  }
}

// ===== SAFE HTML RENDERERS =====
// Returns the number of open doors, for the Vehicle Status badge.
function renderDoors(doors) {
  const grid = refs['doors-grid'];
  grid.replaceChildren();  // safer than innerHTML = ''

  if (!doors.length) { grid.textContent = 'No door data available.'; return 0; }

  let openCount = 0;
  for (const { label, status } of doors) {
    if (status === 'OPEN') openCount++;
    const div = document.createElement('div');
    div.className = 'door-item ' + (status === 'OPEN' ? 'door-open' : 'door-closed');
    div.appendChild(document.createTextNode(label));
    div.appendChild(document.createElement('br'));
    div.appendChild(document.createTextNode(status));
    grid.appendChild(div);
  }

  return openCount;
}

// Returns the number of CRITICAL/WARNING alerts, for the Vehicle Status badge.
// Confirmed live: /vehicle-health/alerts returns
// { VehicleAlertList: [{ Vin, ActiveAlerts: [...], StatusCode, StatusDesc }] }
// — one entry per vehicle, not the {alerts:[...]} shape originally guessed.
// This account's ActiveAlerts was empty (StatusDesc "No Data"), so the shape
// of an actual populated alert is still unconfirmed — normalizeAlert() below
// guesses PascalCase field names matching the surrounding response
// (ActiveAlerts/EventTimeStamp/StatusCode/StatusDesc/Vin all use PascalCase)
// with defensive fallbacks to the earlier lowercase guess. Correct once a
// real populated alert is seen.
function getActiveAlerts(healthData) {
  const list = healthData?.VehicleAlertList;
  if (!Array.isArray(list) || !list.length) return [];
  const entry = list.find(v => v.Vin === vinCache) ?? list[0];
  return Array.isArray(entry?.ActiveAlerts) ? entry.ActiveAlerts : [];
}

function normalizeAlert(alert) {
  const severity = (alert.Severity ?? alert.severity ?? 'INFO').toUpperCase();
  const text = alert.AlertDescription ?? alert.Description ?? alert.description
    ?? alert.AlertName ?? alert.Name ?? alert.Code ?? alert.code ?? 'Vehicle alert';
  return { severity, text };
}

function renderAlerts(healthData) {
  const container = refs['health-alerts'];
  container.replaceChildren();
  const alerts = getActiveAlerts(healthData).map(normalizeAlert);

  if (!alerts.length) {
    const p = document.createElement('p');
    p.style.color = 'var(--text-dim)';
    p.textContent = 'No active alerts.';
    container.appendChild(p);
    return 0;
  }

  let activeCount = 0;
  for (const alert of alerts.slice(0, 10)) {
    const sevCls = alert.severity === 'CRITICAL' ? 'alert-critical' :
                   alert.severity === 'WARNING' ? 'alert-warning' : 'alert-info';
    if (alert.severity === 'CRITICAL' || alert.severity === 'WARNING') activeCount++;

    const div = document.createElement('div');
    div.className = 'alert-item ' + sevCls;

    const glyph = document.createElement('span');
    glyph.className = 'alert-glyph';
    glyph.setAttribute('aria-hidden', 'true');
    glyph.textContent = severityGlyph(alert.severity);
    div.appendChild(glyph);

    const strong = document.createElement('strong');
    strong.textContent = `[${alert.severity}]`;
    div.appendChild(strong);

    div.appendChild(document.createTextNode(' ' + alert.text));
    container.appendChild(div);
  }
  return activeCount;
}

// ===== WALLBOX / CHARGER RENDERER =====
function renderWallbox(data) {
  const container = refs['wallbox-info'];
  if (!container) return;
  container.replaceChildren();

  if (!data) {
    container.innerHTML = '<p class="unavailable-note">No wallbox configured.</p>';
    return;
  }

  // Expected shape: { wallbox: [{ wallboxId, status, ... }] } or flat object
  const wb = Array.isArray(data.wallbox) ? data.wallbox[0] : data;
  // Empty object means no wallbox configured — show the note
  if (!wb || Object.keys(wb).length === 0) {
    container.innerHTML = '<p class="unavailable-note">No wallbox configured.</p>';
    return;
  }

  const fields = [
    ['Status', wb.status ?? wb.Status ?? '--'],
    ['Connector Type', wb.connectorType ?? wb.ConnectorType ?? '--'],
    ['Max Current (A)', wb.maxCurrent ?? wb.MaxCurrent != null ? wb.MaxCurrent : '--'],
    ['Power (kW)', wb.power ?? wb.Power != null ? parseFloat(wb.Power).toFixed(1) : '--'],
    ['Voltage (V)', wb.voltage ?? wb.Voltage ?? '--'],
    ['Location', wb.location ?? wb.Location ?? '--'],
    ['Last Updated', wb.lastUpdatedTime ?? wb.LastUpdatedTime ?? '--'],
  ];

  for (const [label, value] of fields) {
    const row = document.createElement('div');
    row.className = 'info-row';
    const lbl = document.createElement('span');
    lbl.className = 'info-label';
    lbl.textContent = label;
    const val = document.createElement('span');
    val.className = 'info-value';
    val.textContent = String(value);
    row.appendChild(lbl);
    row.appendChild(val);
    container.appendChild(row);
  }
}

// ===== CHARGE SCHEDULES RENDERER =====
function renderChargeSchedules(data) {
  const container = refs['charge-schedules-list'];
  if (!container) return;
  container.replaceChildren();

  if (!data) {
    container.innerHTML = '<p class="unavailable-note">No charge schedules configured.</p>';
    return;
  }

  const schedules = Array.isArray(data.chargeSchedule) ? data.chargeSchedule :
                    Array.isArray(data.ChargeSchedule) ? data.ChargeSchedule :
                    Array.isArray(data) ? data : [];

  if (!schedules.length) {
    container.innerHTML = '<p class="unavailable-note">No active charge schedules.</p>';
    return;
  }

  for (const sched of schedules.slice(0, 5)) {
    const div = document.createElement('div');
    div.className = 'info-row';

    const enabled = sched.enabled ?? sched.Enabled ?? sched.isEnabled ?? sched.IsEnabled;
    const dayOfWeek = sched.dayOfWeek ?? sched.DayOfWeek ?? '--';
    const startTime = sched.startTime ?? sched.StartTime ?? '--';
    const endTime = sched.endTime ?? sched.EndTime ?? '--';
    const chargeLimit = sched.chargeLimitPercentage ?? sched.chargeLimitPercent ?? sched.ChargeLimitPercentage ?? '--';

    div.innerHTML = `<span class="info-label">${dayOfWeek}</span>
      <span class="info-value">${startTime} – ${endTime}${chargeLimit != null ? ' · Limit: ' + chargeLimit + '%' : ''}${enabled !== undefined ? ' · ' + (enabled ? 'Enabled' : 'Disabled') : ''}</span>`;
    container.appendChild(div);
  }
}

// ===== DEPARTURE TIMES RENDERER =====
function renderDepartureTimes(data) {
  const container = refs['departure-times-list'];
  if (!container) return;
  container.replaceChildren();

  if (!data) {
    container.innerHTML = '<p class="unavailable-note">No departure times configured.</p>';
    return;
  }

  const times = Array.isArray(data.departureTime) ? data.departureTime :
                Array.isArray(data.DepartureTime) ? data.DepartureTime :
                Array.isArray(data) ? data : [];

  if (!times.length) {
    container.innerHTML = '<p class="unavailable-note">No active departure times.</p>';
    return;
  }

  for (const dt of times.slice(0, 5)) {
    const div = document.createElement('div');
    div.className = 'info-row';

    const enabled = dt.enabled ?? dt.Enabled ?? dt.isEnabled ?? dt.IsEnabled;
    const dayOfWeek = dt.dayOfWeek ?? dt.DayOfWeek ?? '--';
    const time = dt.time ?? dt.Time ?? '--';
    const ac = dt.acPreconditioningEnabled ?? dt.ACPreconditioningEnabled ?? dt.acPreconditioning ?? dt.ACPreconditioning;

    div.innerHTML = `<span class="info-label">${dayOfWeek}</span>
      <span class="info-value">${time}${ac !== undefined ? ' · AC: ' + (ac ? 'On' : 'Off') : ''}${enabled !== undefined ? ' · ' + (enabled ? 'Enabled' : 'Disabled') : ''}</span>`;
    container.appendChild(div);
  }
}

// ===== VEHICLE IMAGE =====
async function loadVehicleImage(vin) {
  const card = refs['vehicle-image-card'];
  const img = refs['vehicle-image'];
  if (!card || !img || !vin) return;

  try {
    const resp = await fetch(`${API_BASE}/vehicle-image?vin=${vin}`, {
      headers: { 'Authorization': `Bearer ${accessToken}` }
    });
    if (!resp.ok) throw new Error(`Image fetch failed: ${resp.status}`);
    const blob = await resp.blob();
    const url = URL.createObjectURL(blob);
    if (blob.size > 1024) { // Only use if it's a real image, not an error
      img.src = url;
      card.style.display = '';
      img.onload = () => { if (img._prevUrl) URL.revokeObjectURL(img._prevUrl); img._prevUrl = url; };
      return;
    }
    throw new Error('Empty image response');
  } catch (err) {
    console.warn('[vehicle-image]', err.message || err);
    // Fallback: detect model from VIN, show appropriate generic image
    const model = vin.startsWith('1FT') ? 'lightning' : vin.startsWith('3FM') ? 'mache' : 'ev';
    img.src = `images/${model}.svg`;
    card.style.display = '';
  }
}

// ===== UI HELPERS =====
function showLogin() {
  refs['login-screen'].classList.add('active');
  refs['dashboard'].classList.remove('active');
  refs['refresh-bar'].style.display = 'none';
  refs['login-btn'].style.display = 'inline-block';
  refs['logout-btn'].style.display = 'none';
}

function showDashboard() {
  refs['login-screen'].classList.remove('active');
  refs['dashboard'].classList.add('active');
  refs['refresh-bar'].style.display = 'flex';
  refs['login-btn'].style.display = 'none';
  refs['logout-btn'].style.display = 'inline-block';
}

function logout() {
  clearTokens();
  vinCache = null;
  showLogin();
}

function toggleSection(btn) {
  const content = btn.nextElementSibling;
  const isOpen = content.classList.toggle('open');
  btn.setAttribute('aria-expanded', String(isOpen));
  const arrow = btn.querySelector('.toggle-arrow');
  if (arrow) arrow.textContent = isOpen ? '\u25B4' : '\u25BE';
}

function setStatus(msg) {
  refs['connection-status'].textContent = msg;
}

function showError(msg) {
  const div = document.createElement('div');
  div.className = 'error-msg';
  div.textContent = msg;
  document.querySelector('.container').prepend(div);
  setTimeout(() => div.remove(), 8000);
}
