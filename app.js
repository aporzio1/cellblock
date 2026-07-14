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
const BACKEND_BASE = 'https://lightning-rod-proxy.aporzio1.workers.dev';
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
let cellSpreadHistory = [];
let refreshPromise = null;         // single-flight guard
let vinCache = null;               // VIN doesn't change, fetch once
let cellSpreadChart = null;
let refs = {};                     // cached DOM lookups

// Shared door label map (used by renderDoors + the top-level alert strip)
const DOOR_LABELS = {
  driverFrontDoor: 'Driver Front', passengerFrontDoor: 'Passenger Front',
  driverRearDoor: 'Driver Rear', passengerRearDoor: 'Passenger Rear',
  liftgate: 'Liftgate', hood: 'Hood', fuelDoor: 'Fuel Door'
};

// Tire PSI thresholds
const TIRE_DANGER = { low: 28, high: 48 };
const TIRE_WARN = { low: 32, high: 44 };
const TIRE_LABELS = { 'tire-fl': 'Front Left', 'tire-fr': 'Front Right', 'tire-rl': 'Rear Left', 'tire-rr': 'Rear Right' };

// SOC gauge geometry — 270deg arc (see index.html transform="rotate(135 ...)")
const SOC_ARC_LENGTH = 2 * Math.PI * 85 * 0.75; // ~400.55

// Resolve a CSS custom property to its computed value — needed for contexts
// (like Chart.js canvas rendering) that can't parse var() directly.
function cssVar(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

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
// Ford's FordConnect login wrapper currently rejects its own callback URL
// (AADB2C90006, confirmed on two separate client_ids — a provisioning gap on
// Ford's side, not fixable from here), which blocks real login. This lets the
// rest of the app — layout, rendering, the alert strip, etc. — be exercised
// without it. Field shapes here are the same best-effort guesses documented
// in renderDashboard(); this doesn't confirm real API shapes, only that the
// UI renders correctly given *a* shape roughly like this one.
function loadDemoData() {
  showDashboard();
  setStatus('DEMO MODE — mock data, not a live Ford connection');
  refs['vin-display'].textContent = 'DEMO-VIN-0000000';

  vehicleData = {
    telemetry: {
      data: {
        battery: {
          stateOfCharge: 71, estimatedRange: 220, chargeStatus: 'CHARGING_AC',
          evBatteryTotalVoltage: 398, evBatteryTemperature: 81, evChargingRateKW: 10.8,
          evBatteryCellMinVoltage: 3.91, evBatteryCellMaxVoltage: 3.95,
          evBatteryCellMinTemp: 77, evBatteryCellMaxTemp: 83
        },
        tires: { frontLeft: { pressure: 42 }, frontRight: { pressure: 30 }, rearLeft: { pressure: 43 }, rearRight: { pressure: 42 } },
        gps: { latitude: 42.33, longitude: -83.04, altitude: 610, heading: 90, speed: 12, acceleration: { x: 0.1, y: 0, z: 1 } },
        doors: { driverFrontDoor: 'OPEN', passengerFrontDoor: 'LOCKED', driverRearDoor: 'CLOSED', passengerRearDoor: 'CLOSED', liftgate: 'CLOSED', hood: 'CLOSED', fuelDoor: 'CLOSED' }
      }
    },
    health: { data: { alerts: [{ severity: 'WARNING', description: 'Tire pressure low — front right' }] } },
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
    'pack-voltage','battery-temp','charge-rate','vin-display',
    'health-score','min-cell-v','max-cell-v','cell-spread','min-cell-t','max-cell-t','temp-spread',
    'lat','lon','alt','heading','speed','accel',
    'doors-grid','health-alerts','cell-spread-chart',
    'tire-fl','tire-fr','tire-rl','tire-rr',
    'last-update','top-alerts','badge-vehicle','badge-tire','manual-token-input'
  ];
  for (const id of ids) refs[id] = document.getElementById(id);
}

function loadSession() {
  refreshToken = loadRefreshToken();
  if (refreshToken) {
    showDashboard();
    refreshData();
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

      if (!resp.ok) throw new Error('Refresh failed');

      const data = await resp.json();
      accessToken = data.access_token;
      refreshToken = data.refresh_token;
      saveRefreshToken(refreshToken, data.refresh_token_expires_in);
    } catch (err) {
      logout();
      throw err;
    } finally {
      refreshPromise = null;
    }
  })();

  return refreshPromise;
}

// ===== DATA FETCHING =====
async function refreshData() {
  if (new URLSearchParams(window.location.search).has('demo')) {
    loadDemoData(); // re-render mock data instead of hitting the real API
    return;
  }

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

    // wallbox/departure-times/charge-schedules are fetched for completeness
    // (fetchOk tracking) but not wired into any UI section yet — follow-up
    // work once their real response shapes are confirmed.
    const [telemetry, health, wallbox, departureTimes, chargeSchedules] = await Promise.all([
      apiCall(`/telemetry?vin=${vinCache}`).catch(() => null),
      apiCall(`/vehicle-health/alerts?vin=${vinCache}`).catch(() => null),
      apiCall(`/wallbox?vin=${vinCache}`).catch(() => null),
      apiCall(`/electric/departure-times?vin=${vinCache}`).catch(() => null),
      apiCall(`/electric/charge-schedules?vin=${vinCache}`).catch(() => null)
    ]);

    vehicleData = {
      telemetry, health, wallbox, departureTimes, chargeSchedules,
      vin: vinCache,
      fetchOk: {
        telemetry: !!telemetry, health: !!health, wallbox: !!wallbox,
        departureTimes: !!departureTimes, chargeSchedules: !!chargeSchedules
      }
    };

    renderDashboard();
    setStatus('Updated just now');
    setEl('last-update', `Last updated: ${new Date().toLocaleTimeString()}`);
  } catch (err) {
    console.error(err);
    setStatus('Error loading data');
  } finally {
    toggleLoading(false);
  }
}

// Best-effort VIN extraction — the Postman collection has no saved example
// response for /garage, so this shape is a guess at common REST list
// conventions. Verify against a real response and adjust if it's wrong.
function firstVin(garage) {
  const list = garage?.vehicles ?? garage?.data ?? garage;
  return Array.isArray(list) ? (list[0]?.vin ?? null) : null;
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
  const { telemetry, health, fetchOk } = vehicleData;

  // NOTE ON FIELD NAMES BELOW: the FordConnect Postman collection saves no
  // example response for /telemetry (every "response" array in the
  // collection is empty), so this nesting and these field names are a
  // best-effort guess at plausible shapes, not confirmed. Once you've made
  // one real call and can see an actual payload, correct the optional-
  // chaining paths in this function accordingly -- everything here is
  // written to degrade to "--"/unavailable rather than throw if a guess
  // turns out wrong.
  const td = telemetry?.data ?? telemetry ?? {};
  const battery = td.battery ?? td.evBattery ?? td;
  const tires = td.tires ?? td.tirePressure ?? {};
  const gps = td.gps ?? td.location ?? {};
  const doors = td.doors ?? td.doorStatus ?? {};

  // SOC Ring
  const soc = battery?.stateOfCharge ?? battery?.soc ?? battery?.evBatteryStateOfCharge;
  const range = battery?.estimatedRange ?? battery?.range ?? battery?.evEstimatedRange;
  const circle = refs['soc-circle'];
  if (circle && typeof soc === 'number') {
    circle.style.strokeDashoffset = SOC_ARC_LENGTH - (soc / 100) * SOC_ARC_LENGTH;
    circle.style.stroke = soc > 20 ? 'var(--accent)' : soc > 10 ? 'var(--warn)' : 'var(--danger)';
  }
  setEl('soc-value', typeof soc === 'number' ? `${Math.round(soc)}%` : '--%');
  setEl('range-value', typeof range === 'number' ? `Range: ${Math.round(range)} mi` : 'Range: -- mi');

  // Charge status
  const chargeStatus = battery?.chargeStatus ?? battery?.evChargeStatus;
  const badge = refs['charge-status'];
  if (chargeStatus) {
    badge.textContent = chargeStatus.replace(/_/g, ' ');
    badge.style.background = chargeStatus.includes('CHARGING') ? 'var(--good-soft)' : 'var(--info-soft)';
    badge.style.color = chargeStatus.includes('CHARGING') ? 'var(--good)' : 'var(--info)';
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
  setEl('pack-voltage', fmt(battery?.evBatteryTotalVoltage ?? battery?.batteryVoltage, 0, 'V'));
  setEl('battery-temp', fmt(battery?.evBatteryTemperature ?? battery?.batteryTemp, 0, '°F'));
  setEl('charge-rate', fmt(battery?.evChargingRateKW ?? battery?.chargeRate, 1, 'kW'));

  // Battery health -- only render if telemetry data is present
  if (fetchOk.telemetry) {
    const minCV = battery?.evBatteryCellMinVoltage ?? battery?.minCellVoltage;
    const maxCV = battery?.evBatteryCellMaxVoltage ?? battery?.maxCellVoltage;
    const minCT = battery?.evBatteryCellMinTemp ?? battery?.minCellTemp;
    const maxCT = battery?.evBatteryCellMaxTemp ?? battery?.maxCellTemp;

    if (typeof minCV === 'number' && typeof maxCV === 'number') {
      setEl('min-cell-v', fmt(minCV, 4, 'V'));
      setEl('max-cell-v', fmt(maxCV, 4, 'V'));
      setEl('cell-spread', `${((maxCV - minCV) * 1000).toFixed(1)} mV`);
      setEl('min-cell-t', fmt(minCT, 1, '°F'));
      setEl('max-cell-t', fmt(maxCT, 1, '°F'));
      setEl('temp-spread', typeof minCT === 'number' && typeof maxCT === 'number'
        ? `${(maxCT - minCT).toFixed(1)} °F`
        : '-- °F');

      const spreadMV = (maxCV - minCV) * 1000;
      const scoreEl = refs['health-score'];
      if (spreadMV < 30) {
        scoreEl.textContent = 'Excellent';
        scoreEl.className = 'health-score health-good';
      } else if (spreadMV < 60) {
        scoreEl.textContent = 'Fair';
        scoreEl.className = 'health-score health-warn';
      } else {
        scoreEl.textContent = 'Attention Needed';
        scoreEl.className = 'health-score health-bad';
      }

      // Cell spread chart -- store real timestamps
      cellSpreadHistory.push({ ts: Date.now(), value: spreadMV });
      if (cellSpreadHistory.length > 30) cellSpreadHistory.shift();
      updateCellSpreadChart();
    }
  } else {
    const scoreEl = refs['health-score'];
    scoreEl.textContent = 'No data';
    scoreEl.className = 'health-score health-bad';
  }

  // Tires
  const tireIssues = [
    setTire('tire-fl', tires.frontLeft?.pressure ?? tires.FL?.pressure),
    setTire('tire-fr', tires.frontRight?.pressure ?? tires.FR?.pressure),
    setTire('tire-rl', tires.rearLeft?.pressure ?? tires.RL?.pressure),
    setTire('tire-rr', tires.rearRight?.pressure ?? tires.RR?.pressure)
  ].filter(Boolean);
  setBadge('badge-tire', tireIssues.length);

  // GPS
  setEl('lat', gps.latitude ?? '--');
  setEl('lon', gps.longitude ?? '--');
  setEl('alt', gps.altitude ? `${gps.altitude} ft` : '-- ft');
  setEl('heading', gps.heading != null ? `${gps.heading}°` : '--°');
  setEl('speed', gps.speed != null ? `${gps.speed} mph` : '-- mph');
  const acc = gps.acceleration;
  setEl('accel', acc ? `${acc.x}/${acc.y}/${acc.z} g` : '--/--/-- g');

  // Sub-renderers (all DOM-safe)
  const openDoorCount = renderDoors(doors);
  const activeAlertCount = renderAlerts(health?.data ?? health);

  setBadge('badge-vehicle', openDoorCount + activeAlertCount);
  renderTopAlerts(doors, health?.data ?? health, tireIssues);
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
function renderTopAlerts(doorsData, healthData, tireIssues) {
  const strip = refs['top-alerts'];
  if (!strip) return;
  strip.replaceChildren();

  const items = [];

  if (healthData?.alerts?.length) {
    for (const alert of healthData.alerts) {
      if (alert.severity === 'CRITICAL' || alert.severity === 'WARNING') {
        items.push({ severity: alert.severity, text: alert.description || alert.code || 'Vehicle alert' });
      }
    }
  }

  if (doorsData) {
    for (const [key, label] of Object.entries(DOOR_LABELS)) {
      if (doorsData[key] === 'OPEN') {
        items.push({ severity: 'WARNING', text: `${label} is open` });
      }
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
function renderDoors(data) {
  const grid = refs['doors-grid'];
  grid.replaceChildren();  // safer than innerHTML = ''

  if (!data) { grid.textContent = ''; return 0; }

  let any = false;
  let openCount = 0;
  for (const [key, label] of Object.entries(DOOR_LABELS)) {
    const status = data[key];
    if (!status) continue;
    any = true;
    if (status === 'OPEN') openCount++;
    const div = document.createElement('div');
    div.className = 'door-item ' + (status === 'OPEN' ? 'door-open' : status === 'CLOSED' ? 'door-closed' : 'door-locked');
    div.appendChild(document.createTextNode(label));
    div.appendChild(document.createElement('br'));
    div.appendChild(document.createTextNode(status));
    grid.appendChild(div);
  }

  if (!any) grid.textContent = 'No door data available.';
  return openCount;
}

// Returns the number of CRITICAL/WARNING alerts, for the Vehicle Status badge.
function renderAlerts(data) {
  const container = refs['health-alerts'];
  container.replaceChildren();

  if (!data?.alerts?.length) {
    const p = document.createElement('p');
    p.style.color = 'var(--text-dim)';
    p.textContent = 'No active alerts.';
    container.appendChild(p);
    return 0;
  }

  let activeCount = 0;
  for (const alert of data.alerts.slice(0, 10)) {
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

    const desc = alert.description || alert.code || 'Unknown alert';
    div.appendChild(document.createTextNode(' ' + desc));
    container.appendChild(div);
  }
  return activeCount;
}

// ===== CHART — create once, update in place =====
function updateCellSpreadChart() {
  const canvas = refs['cell-spread-chart'];
  if (!canvas) return;

  const labels = cellSpreadHistory.map(({ ts }) => {
    return new Date(ts).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
  });
  const values = cellSpreadHistory.map(({ value }) => value);

  if (!cellSpreadChart) {
    const accent = cssVar('--accent');
    const accentSoft = cssVar('--accent-soft');
    const tickColor = cssVar('--text-dim');
    const gridColor = cssVar('--border-soft');

    cellSpreadChart = new Chart(canvas.getContext('2d'), {
      type: 'line',
      data: {
        labels,
        datasets: [{
          label: 'Cell Voltage Spread (mV)',
          data: values,
          borderColor: accent,
          backgroundColor: accentSoft,
          fill: true,
          tension: 0.3,
          pointRadius: 3
        }]
      },
      options: {
        responsive: true,
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: tickColor, maxTicksLimit: 7 }, grid: { color: gridColor } },
          y: { ticks: { color: tickColor }, grid: { color: gridColor } }
        }
      }
    });
  } else {
    cellSpreadChart.data.labels = labels;
    cellSpreadChart.data.datasets[0].data = values;
    cellSpreadChart.update();
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
  cellSpreadHistory = [];
  if (cellSpreadChart) { cellSpreadChart.destroy(); cellSpreadChart = null; }
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
