// ===== Lightning Rod — Ford Telemetry Dashboard =====

// ===== CONFIG =====
const CLIENT_ID = 'YOUR_CLIENT_ID';
const REDIRECT_URI = window.location.origin + window.location.pathname;
const FORD_AUTH_URL = 'https://login.ford.com/as/authorization.oauth2';
const FORD_TOKEN_URL = 'https://login.ford.com/as/token.oauth2';
const API_BASE = 'https://api.vehicle.ford.com';
const REFRESH_KEY = 'ford_refresh';

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
  if (new URLSearchParams(window.location.search).has('code')) {
    handleCallback();
  } else {
    loadSession();
  }
});

function cacheDom() {
  const ids = [
    'login-screen','dashboard','refresh-bar','login-btn','logout-btn',
    'connection-status','soc-circle','soc-value','range-value','charge-status',
    'pack-voltage','battery-temp','charge-rate','vin-display',
    'health-score','min-cell-v','max-cell-v','cell-spread','min-cell-t','max-cell-t','temp-spread',
    'cabin-temp','target-temp','fan-speed','zone1-mode','zone2-mode','defrost',
    'lat','lon','alt','heading','speed','accel',
    'gen-speed','gen-torque','gen-current','gen-temp',
    'mot-speed','mot-torque','mot-current','mot-temp',
    'doors-grid','health-alerts','charging-log','ota-info','cell-spread-chart',
    'tire-fl','tire-fr','tire-rl','tire-rr',
    'last-update','top-alerts','badge-vehicle','badge-tire'
  ];
  for (const id of ids) refs[id] = document.getElementById(id);
}

function loadSession() {
  refreshToken = localStorage.getItem(REFRESH_KEY);
  if (refreshToken) {
    showDashboard();
    refreshData();
  } else {
    showLogin();
  }
}

// ===== AUTH =====
async function startLogin() {
  const state = generateState();
  const codeVerifier = generatePKCECodeVerifier();
  sessionStorage.setItem('code_verifier', codeVerifier);
  sessionStorage.setItem('auth_state', state);

  const codeChallenge = await generatePKCECodeChallenge(codeVerifier);

  const params = new URLSearchParams({
    response_type: 'code',
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    scope: 'openid profile vehicle_data',
    state: state,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256'
  });

  window.location.href = `${FORD_AUTH_URL}?${params.toString()}`;
}

function handleCallback() {
  const urlParams = new URLSearchParams(window.location.search);
  const code = urlParams.get('code');
  const state = urlParams.get('state');

  if (!code || !state) { loadSession(); return; }

  const savedState = sessionStorage.getItem('auth_state');
  if (state !== savedState) {
    showError('Invalid auth state — session may have expired. Please try again.');
    history.replaceState(null, '', window.location.pathname);
    loadSession();
    return;
  }

  const codeVerifier = sessionStorage.getItem('code_verifier');
  if (!codeVerifier) {
    showError('Missing code verifier — session may have expired. Please try again.');
    history.replaceState(null, '', window.location.pathname);
    loadSession();
    return;
  }

  sessionStorage.removeItem('code_verifier');
  sessionStorage.removeItem('auth_state');
  exchangeCodeForToken(code, codeVerifier);
}

async function exchangeCodeForToken(code, codeVerifier) {
  try {
    const resp = await fetch(FORD_TOKEN_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: REDIRECT_URI,
        client_id: CLIENT_ID,
        code_verifier: codeVerifier
      })
    });

    if (!resp.ok) {
      const body = await resp.text();
      throw new Error(`Token exchange failed (${resp.status}): ${body}`);
    }

    const data = await resp.json();
    accessToken = data.access_token;
    refreshToken = data.refresh_token;
    localStorage.setItem(REFRESH_KEY, refreshToken);
    history.replaceState(null, '', window.location.pathname);
    showDashboard();
    refreshData();
  } catch (err) {
    showError('Failed to authenticate: ' + err.message);
  }
}

// ===== PKCE =====
function generatePKCECodeVerifier() {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return btoa(String.fromCharCode(...array))
    .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

async function generatePKCECodeChallenge(verifier) {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return btoa(String.fromCharCode(...new Uint8Array(hash)))
    .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function generateState() {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  return Array.from(array, b => b.toString(16).padStart(2, '0')).join('');
}

// ===== TOKEN STORAGE — localStorage refresh token, no cookies =====
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
      const resp = await fetch(FORD_TOKEN_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: refreshToken,
          client_id: CLIENT_ID
        })
      });

      if (!resp.ok) throw new Error('Refresh failed');

      const data = await resp.json();
      accessToken = data.access_token;
      refreshToken = data.refresh_token;
      localStorage.setItem(REFRESH_KEY, refreshToken);
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
  setStatus('Updating...');
  toggleLoading(true);

  try {
    if (!vinCache) {
      const vehicles = await apiCall('/vehicles/v1/vehicles');
      if (!vehicles?.data?.length) {
        showError('No vehicles found');
        return;
      }
      vinCache = vehicles.data[0].vin;
    }

    refs['vin-display'].textContent = vinCache;

    const endpoints = [
      `ev/battery`, `tires`, `motors`, `hvac`, `doors`,
      `gps`, `vehiclehealth`, `charginghistory`, `ota`
    ];

    const results = await Promise.all(
      endpoints.map(e => apiCall(`/vehicles/v1/vehicles/${vinCache}/${e}`).catch(() => null))
    );

    const [battery, tires, motors, hvac, doors, gps, health, charging, ota] = results;

    vehicleData = {
      battery, tires, motors, hvac, doors, gps, health, charging, ota,
      vin: vinCache,
      fetchOk: {
        battery: !!battery, tires: !!tires, motors: !!motors,
        hvac: !!hvac, doors: !!doors, gps: !!gps,
        health: !!health, charging: !!charging, ota: !!ota
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
  const { battery, tires, motors, hvac, doors, gps, health, charging, ota, fetchOk } = vehicleData;

  // SOC Ring
  const soc = battery?.data?.stateOfCharge ?? battery?.data?.evBatteryStateOfCharge;
  const range = battery?.data?.estimatedRange ?? battery?.data?.evEstimatedRange;
  const circle = refs['soc-circle'];
  if (circle && typeof soc === 'number') {
    circle.style.strokeDashoffset = SOC_ARC_LENGTH - (soc / 100) * SOC_ARC_LENGTH;
    circle.style.stroke = soc > 20 ? 'var(--accent)' : soc > 10 ? 'var(--warn)' : 'var(--danger)';
  }
  setEl('soc-value', typeof soc === 'number' ? `${Math.round(soc)}%` : '--%');
  setEl('range-value', typeof range === 'number' ? `Range: ${Math.round(range)} mi` : 'Range: -- mi');

  // Charge status
  const chargeStatus = battery?.data?.chargeStatus ?? battery?.data?.evChargeStatus;
  const badge = refs['charge-status'];
  if (chargeStatus) {
    badge.textContent = chargeStatus.replace(/_/g, ' ');
    badge.style.background = chargeStatus.includes('CHARGING') ? 'var(--good-soft)' : 'var(--info-soft)';
    badge.style.color = chargeStatus.includes('CHARGING') ? 'var(--good)' : 'var(--info)';
  } else if (!fetchOk.battery) {
    badge.textContent = 'Data unavailable';
    badge.style.background = 'var(--danger-soft)';
    badge.style.color = 'var(--danger)';
  } else {
    badge.textContent = '—';
    badge.style.background = 'transparent';
    badge.style.color = 'var(--text-dim)';
  }

  // Pack overview
  setEl('pack-voltage', fmt(battery?.data?.evBatteryTotalVoltage ?? battery?.data?.batteryVoltage, 0, 'V'));
  setEl('battery-temp', fmt(battery?.data?.evBatteryTemperature ?? battery?.data?.batteryTemp, 0, '\u00B0F'));
  setEl('charge-rate', fmt(battery?.data?.evChargingRateKW ?? battery?.data?.chargeRate, 1, 'kW'));

  // Battery health — only render if battery data is present
  if (fetchOk.battery) {
    const minCV = battery?.data?.evBatteryCellMinVoltage ?? battery?.data?.minCellVoltage;
    const maxCV = battery?.data?.evBatteryCellMaxVoltage ?? battery?.data?.maxCellVoltage;
    const minCT = battery?.data?.evBatteryCellMinTemp ?? battery?.data?.minCellTemp;
    const maxCT = battery?.data?.evBatteryCellMaxTemp ?? battery?.data?.maxCellTemp;

    if (typeof minCV === 'number' && typeof maxCV === 'number') {
      setEl('min-cell-v', fmt(minCV, 4, 'V'));
      setEl('max-cell-v', fmt(maxCV, 4, 'V'));
      setEl('cell-spread', `${((maxCV - minCV) * 1000).toFixed(1)} mV`);
      setEl('min-cell-t', fmt(minCT, 1, '\u00B0F'));
      setEl('max-cell-t', fmt(maxCT, 1, '\u00B0F'));
      setEl('temp-spread', typeof minCT === 'number' && typeof maxCT === 'number'
        ? `${(maxCT - minCT).toFixed(1)} \u00B0F`
        : '-- \u00B0F');

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

      // Cell spread chart — store real timestamps
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
  let tireIssues = [];
  if (tires?.data) {
    const t = tires.data;
    tireIssues = [
      setTire('tire-fl', t.frontLeft?.pressure),
      setTire('tire-fr', t.frontRight?.pressure),
      setTire('tire-rl', t.rearLeft?.pressure),
      setTire('tire-rr', t.rearRight?.pressure)
    ].filter(Boolean);
  }
  setBadge('badge-tire', tireIssues.length);

  // Motors
  if (motors?.data) {
    setMotor('gen', motors.data.generator);
    setMotor('mot', motors.data.motor);
  }

  // HVAC
  if (hvac?.data) {
    const hd = hvac.data;
    setEl('cabin-temp', fmt(hd.cabinTemperature, 1, '\u00B0F'));
    setEl('target-temp', fmt(hd.targetTemperature, 1, '\u00B0F'));
    setEl('fan-speed', hd.fanSpeed ?? '--');
    setEl('zone1-mode', hd.zone1Mode ?? '--');
    setEl('zone2-mode', hd.zone2Mode ?? '--');
    setEl('defrost', hd.defrost ?? '--');
  }

  // GPS
  if (gps?.data) {
    const gd = gps.data;
    setEl('lat', gd.latitude ?? '--');
    setEl('lon', gd.longitude ?? '--');
    setEl('alt', gd.altitude ? `${gd.altitude} ft` : '-- ft');
    setEl('heading', gd.heading != null ? `${gd.heading}\u00B0` : '--\u00B0');
    setEl('speed', gd.speed != null ? `${gd.speed} mph` : '-- mph');
    const acc = gd.acceleration;
    setEl('accel', acc ? `${acc.x}/${acc.y}/${acc.z} g` : '--/--/-- g');
  }

  // Sub-renderers (all DOM-safe)
  const openDoorCount = renderDoors(doors?.data);
  const activeAlertCount = renderAlerts(health?.data);
  renderCharging(charging?.data);
  renderOTA(ota?.data);

  setBadge('badge-vehicle', openDoorCount + activeAlertCount);
  renderTopAlerts(doors?.data, health?.data, tireIssues);
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

function setMotor(prefix, data) {
  if (!data) return;
  setEl(`${prefix}-speed`, `${data.speed ?? '--'} RPM`);
  setEl(`${prefix}-torque`, `${data.torque ?? '--'} Nm`);
  setEl(`${prefix}-current`, `${data.current ?? '--'} A`);
  setEl(`${prefix}-temp`, fmt(data.controllerTemp, 1, '\u00B0F'));
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

function renderCharging(data) {
  const el = refs['charging-log'];
  el.replaceChildren();

  if (!data?.sessions?.length) {
    el.textContent = 'No charging sessions recorded.';
    return;
  }

  const table = document.createElement('table');
  table.style.cssText = 'width:100%;font-size:0.85rem;border-collapse:collapse';

  const thead = document.createElement('tr');
  thead.style.color = 'var(--text-dim)';
  ['Date','Type','Energy','Duration'].forEach(hdr => {
    const th = document.createElement('th');
    th.textContent = hdr;
    thead.appendChild(th);
  });
  table.appendChild(thead);

  for (const s of data.sessions.slice(0, 10)) {
    const tr = document.createElement('tr');
    tr.style.borderBottom = '1px solid var(--border)';

    const cells = [s.date, s.type, s.energyAdded, s.duration];
    cells.forEach(c => {
      const td = document.createElement('td');
      td.style.padding = '0.5rem 0';
      td.textContent = c ?? '--';
      tr.appendChild(td);
    });
    table.appendChild(tr);
  }

  const wrapper = document.createElement('div');
  wrapper.className = 'table-scroll';
  wrapper.appendChild(table);
  el.appendChild(wrapper);
}

function renderOTA(data) {
  const el = refs['ota-info'];
  el.replaceChildren();

  if (!data) { el.textContent = 'No OTA data available.'; return; }

  const fields = [
    ['Current Version', data.version],
    ['Update Available', data.availableVersion],
    ['Scheduled', data.schedule],
    ['Auto-opt-in', data.optIn != null ? (data.optIn ? 'Yes' : 'No') : null],
    ['Status', data.status]
  ];

  let any = false;
  for (const [label, value] of fields) {
    if (!value) continue;
    any = true;
    const div = document.createElement('div');
    const strong = document.createElement('strong');
    strong.textContent = label + ': ';
    div.appendChild(strong);
    div.appendChild(document.createTextNode(value));
    el.appendChild(div);
  }

  if (!any) el.textContent = 'No OTA data available.';
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
