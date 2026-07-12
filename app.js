// ===== Ford Dashboard App =====

// ===== CONFIG =====
const CLIENT_ID = 'YOUR_CLIENT_ID'; // Register at developer.ford.com
const REDIRECT_URI = encodeURIComponent(window.location.origin + window.location.pathname);
const FORD_AUTH_URL = 'https://login.ford.com/as/authorization.oauth2';
const FORD_TOKEN_URL = 'https://login.ford.com/as/token.oauth2';
const API_BASE = 'https://api.vehicle.ford.com';
const TOKEN_COOKIE = 'ford_token';
const REFRESH_COOKIE = 'ford_refresh';

// ===== STATE =====
let accessToken = null;
let refreshToken = null;
let vehicleData = {};
let cellSpreadHistory = [];

// ===== INIT =====
document.addEventListener('DOMContentLoaded', () => {
  const tokens = loadTokens();
  if (tokens?.access) {
    accessToken = tokens.access;
    refreshToken = tokens.refresh;
    showDashboard();
    refreshData();
  } else {
    showLogin();
  }
});

// ===== AUTH =====
function startLogin() {
  const state = generateState();
  const codeVerifier = generatePKCECodeVerifier();
  sessionStorage.setItem('code_verifier', codeVerifier);
  sessionStorage.setItem('auth_state', state);

  const params = new URLSearchParams({
    response_type: 'code',
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    scope: 'openid profile vehicle_data',
    state: state,
    code_challenge: generatePKCECodeChallenge(codeVerifier),
    code_challenge_method: 'S256'
  });

  window.location.href = `${FORD_AUTH_URL}?${params.toString()}`;
}

function handleCallback() {
  const urlParams = new URLSearchParams(window.location.search);
  const code = urlParams.get('code');
  const state = urlParams.get('state');

  if (!code || !state) return;

  const savedState = sessionStorage.getItem('auth_state');
  if (state !== savedState) {
    showError('Invalid auth state');
    return;
  }

  const codeVerifier = sessionStorage.getItem('code_verifier');
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
        redirect_uri: decodeURIComponent(REDIRECT_URI),
        client_id: CLIENT_ID,
        code_verifier: codeVerifier
      })
    });

    if (!resp.ok) throw new Error('Token exchange failed');

    const data = await resp.json();
    saveTokens(data.access_token, data.refresh_token);
    accessToken = data.access_token;
    refreshToken = data.refresh_token;
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
  return btoa(String.fromCharCode(...array)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
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

// ===== TOKEN STORAGE =====
function saveTokens(access, refresh) {
  document.cookie = `${TOKEN_COOKIE}=${access}; path=/; max-age=7200; Secure; SameSite=Lax`;
  document.cookie = `${REFRESH_COOKIE}=${refresh}; path=/; max-age=604800; Secure; SameSite=Lax`;
}

function loadTokens() {
  const getCookie = name => {
    const match = document.cookie.match(new RegExp('(^| )' + name + '=([^;]+)'));
    return match ? match[2] : null;
  };
  const access = getCookie(TOKEN_COOKIE);
  const refresh = getCookie(REFRESH_COOKIE);
  if (access && refresh) return { access, refresh };
  return null;
}

function clearTokens() {
  document.cookie = `${TOKEN_COOKIE}=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT`;
  document.cookie = `${REFRESH_COOKIE}=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT`;
}

// ===== API =====
async function apiCall(endpoint) {
  const resp = await fetch(`${API_BASE}${endpoint}`, {
    headers: { 'Authorization': `Bearer ${accessToken}`, 'Accept': 'application/json' }
  });

  if (resp.status === 401 && refreshToken) {
    await refreshAccessToken();
    return apiCall(endpoint);
  }

  if (!resp.ok) throw new Error(`API error: ${resp.status}`);
  return resp.json();
}

async function refreshAccessToken() {
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
    saveTokens(data.access_token, data.refresh_token);
    accessToken = data.access_token;
    refreshToken = data.refresh_token;
  } catch (err) {
    logout();
    throw err;
  }
}

// ===== DATA FETCHING =====
async function refreshData() {
  setStatus('Updating...');

  try {
    // Get vehicles list
    const vehicles = await apiCall('/vehicles/v1/vehicles');
    if (!vehicles?.data?.length) {
      showError('No vehicles found');
      return;
    }

    const vin = vehicles.data[0].vin;
    document.getElementById('vin-display').textContent = vin;

    // Fetch all telemetry endpoints in parallel
    const [battery, tires, motors, hvac, doors, gps, health, charging, ota] = await Promise.all([
      apiCall(`/vehicles/v1/vehicles/${vin}/ev/battery`).catch(() => ({})),
      apiCall(`/vehicles/v1/vehicles/${vin}/tires`).catch(() => ({})),
      apiCall(`/vehicles/v1/vehicles/${vin}/motors`).catch(() => ({})),
      apiCall(`/vehicles/v1/vehicles/${vin}/hvac`).catch(() => ({})),
      apiCall(`/vehicles/v1/vehicles/${vin}/doors`).catch(() => ({})),
      apiCall(`/vehicles/v1/vehicles/${vin}/gps`).catch(() => ({})),
      apiCall(`/vehicles/v1/vehicles/${vin}/vehiclehealth`).catch(() => ({})),
      apiCall(`/vehicles/v1/vehicles/${vin}/charginghistory`).catch(() => ({})),
      apiCall(`/vehicles/v1/vehicles/${vin}/ota`).catch(() => ({}))
    ]);

    vehicleData = { battery, tires, motors, hvac, doors, gps, health, charging, ota, vin };
    renderDashboard();
    setStatus('Updated just now');
  } catch (err) {
    console.error(err);
    setStatus('Error loading data');
  }
}

// ===== RENDERING =====
function renderDashboard() {
  const { battery, tires, motors, hvac, doors, gps, health, charging, ota } = vehicleData;

  // SOC Ring
  const soc = battery?.data?.stateOfCharge ?? battery?.data?.evBatteryStateOfCharge ?? 0;
  const range = battery?.data?.estimatedRange ?? battery?.data?.evEstimatedRange ?? 0;
  const circle = document.getElementById('soc-circle');
  const circumference = 2 * Math.PI * 85;
  const offset = circumference - (soc / 100) * circumference;
  circle.style.strokeDashoffset = offset;
  circle.style.stroke = soc > 20 ? '#00ff88' : soc > 10 ? '#ffaa00' : '#ff4444';
  document.getElementById('soc-value').textContent = `${Math.round(soc)}%`;
  document.getElementById('range-value').textContent = `Range: ${Math.round(range)} mi`;

  // Charge status
  const chargeStatus = battery?.data?.chargeStatus ?? battery?.data?.evChargeStatus ?? 'Unknown';
  const badge = document.getElementById('charge-status');
  badge.textContent = chargeStatus.replace(/_/g, ' ');
  badge.style.background = chargeStatus.includes('CHARGING') ? 'rgba(0,255,136,0.15)' : 'rgba(68,136,255,0.15)';
  badge.style.color = chargeStatus.includes('CHARGING') ? '#00ff88' : '#4488ff';

  // Pack overview
  const packV = battery?.data?.evBatteryTotalVoltage ?? battery?.data?.batteryVoltage ?? '--';
  const packT = battery?.data?.evBatteryTemperature ?? battery?.data?.batteryTemp ?? '--';
  const chargeRate = battery?.data?.evChargingRateKW ?? battery?.data?.chargeRate ?? '--';
  document.getElementById('pack-voltage').textContent = typeof packV === 'number' ? `${packV.toFixed(0)} V` : packV;
  document.getElementById('battery-temp').textContent = typeof packT === 'number' ? `${packT.toFixed(0)} °F` : packT;
  document.getElementById('charge-rate').textContent = typeof chargeRate === 'number' ? `${chargeRate.toFixed(1)} kW` : chargeRate;

  // Battery health
  const minCV = battery?.data?.evBatteryCellMinVoltage ?? battery?.data?.minCellVoltage ?? 0;
  const maxCV = battery?.data?.evBatteryCellMaxVoltage ?? battery?.data?.maxCellVoltage ?? 0;
  const minCT = battery?.data?.evBatteryCellMinTemp ?? battery?.data?.minCellTemp ?? 0;
  const maxCT = battery?.data?.evBatteryCellMaxTemp ?? battery?.data?.maxCellTemp ?? 0;

  const spreadMV = ((maxCV - minCV) * 1000).toFixed(1);
  const tempSpread = (maxCT - minCT).toFixed(1);

  document.getElementById('min-cell-v').textContent = `${minCV.toFixed(4)} V`;
  document.getElementById('max-cell-v').textContent = `${maxCV.toFixed(4)} V`;
  document.getElementById('cell-spread').textContent = `${spreadMV} mV`;
  document.getElementById('min-cell-t').textContent = `${typeof minCT === 'number' ? minCT.toFixed(1) : minCT} °F`;
  document.getElementById('max-cell-t').textContent = `${typeof maxCT === 'number' ? maxCT.toFixed(1) : maxCT} °F`;
  document.getElementById('temp-spread').textContent = `${tempSpread} °F`;

  // Health score
  const scoreEl = document.getElementById('health-score');
  const spreadNum = parseFloat(spreadMV);
  if (spreadNum < 30) {
    scoreEl.textContent = 'Excellent';
    scoreEl.className = 'health-score health-good';
  } else if (spreadNum < 60) {
    scoreEl.textContent = 'Fair';
    scoreEl.className = 'health-score health-warn';
  } else {
    scoreEl.textContent = 'Attention Needed';
    scoreEl.className = 'health-score health-bad';
  }

  // Cell spread chart
  cellSpreadHistory.push(parseFloat(spreadMV));
  if (cellSpreadHistory.length > 30) cellSpreadHistory.shift();
  updateCellSpreadChart();

  // Tires
  if (tires?.data) {
    const t = tires.data;
    setTire('tire-fl', t.frontLeft?.pressure ?? '--');
    setTire('tire-fr', t.frontRight?.pressure ?? '--');
    setTire('tire-rl', t.rearLeft?.pressure ?? '--');
    setTire('tire-rr', t.rearRight?.pressure ?? '--');
  }

  // Motors
  if (motors?.data) {
    const m = motors.data;
    if (m.generator) {
      document.getElementById('gen-speed').textContent = `${m.generator.speed ?? '--'} RPM`;
      document.getElementById('gen-torque').textContent = `${m.generator.torque ?? '--'} Nm`;
      document.getElementById('gen-current').textContent = `${m.generator.current ?? '--'} A`;
      document.getElementById('gen-temp').textContent = `${m.generator.controllerTemp ?? '--'} °F`;
    }
    if (m.motor) {
      document.getElementById('mot-speed').textContent = `${m.motor.speed ?? '--'} RPM`;
      document.getElementById('mot-torque').textContent = `${m.motor.torque ?? '--'} Nm`;
      document.getElementById('mot-current').textContent = `${m.motor.current ?? '--'} A`;
      document.getElementById('mot-temp').textContent = `${m.motor.controllerTemp ?? '--'} °F`;
    }
  }

  // HVAC
  if (hvac?.data) {
    const h = hvac.data;
    document.getElementById('cabin-temp').textContent = `${h.cabinTemperature ?? '--'} °F`;
    document.getElementById('target-temp').textContent = `${h.targetTemperature ?? '--'} °F`;
    document.getElementById('fan-speed').textContent = h.fanSpeed ?? '--';
    document.getElementById('zone1-mode').textContent = h.zone1Mode ?? '--';
    document.getElementById('zone2-mode').textContent = h.zone2Mode ?? '--';
    document.getElementById('defrost').textContent = h.defrost ?? '--';
  }

  // Doors
  renderDoors(doors?.data);

  // GPS
  if (gps?.data) {
    const g = gps.data;
    document.getElementById('lat').textContent = g.latitude ?? '--';
    document.getElementById('lon').textContent = g.longitude ?? '--';
    document.getElementById('alt').textContent = `${g.altitude ?? '--'} ft`;
    document.getElementById('heading').textContent = `${g.heading ?? '--'}°`;
    document.getElementById('speed').textContent = `${g.speed ?? '--'} mph`;
    const acc = g.acceleration;
    document.getElementById('accel').textContent = acc ? `${acc.x}/${acc.y}/${acc.z} g` : '--/--/-- g';
  }

  // Vehicle health alerts
  renderAlerts(health?.data);

  // Charging history
  renderCharging(charging?.data);

  // OTA
  renderOTA(ota?.data);
}

function setTire(id, val) {
  const el = document.getElementById(id);
  if (el) {
    el.querySelector('.tire-val').textContent = typeof val === 'number' ? `${val.toFixed(0)} PSI` : val;
  }
}

function renderDoors(data) {
  const grid = document.getElementById('doors-grid');
  if (!data) { grid.innerHTML = ''; return; }

  const doorMap = {
    driverFrontDoor: 'Driver Front',
    passengerFrontDoor: 'Passenger Front',
    driverRearDoor: 'Driver Rear',
    passengerRearDoor: 'Passenger Rear',
    liftgate: 'Liftgate',
    hood: 'Hood',
    fuelDoor: 'Fuel Door'
  };

  let html = '';
  for (const [key, label] of Object.entries(doorMap)) {
    const status = data[key];
    if (!status) continue;
    const cls = status === 'OPEN' ? 'door-open' : status === 'CLOSED' ? 'door-closed' : 'door-locked';
    html += `<div class="door-item ${cls}">${label}<br>${status}</div>`;
  }
  grid.innerHTML = html || 'No door data available.';
}

function renderAlerts(data) {
  const container = document.getElementById('health-alerts');
  if (!data?.alerts?.length) {
    container.innerHTML = '<p style="color:var(--text-dim)">No active alerts.</p>';
    return;
  }

  let html = '';
  for (const alert of data.alerts.slice(0, 10)) {
    const sevCls = alert.severity === 'CRITICAL' ? 'alert-critical' :
                   alert.severity === 'WARNING' ? 'alert-warning' : 'alert-info';
    html += `<div class="alert-item ${sevCls}">
      <strong>[${alert.severity}]</strong> ${alert.description || alert.code || 'Unknown alert'}
    </div>`;
  }
  container.innerHTML = html;
}

function renderCharging(data) {
  const el = document.getElementById('charging-log');
  if (!data?.sessions?.length) {
    el.innerHTML = 'No charging sessions recorded.';
    return;
  }

  let html = '<table style="width:100%;font-size:0.85rem;border-collapse:collapse">';
  html += '<tr style="color:var(--text-dim)"><th>Date</th><th>Type</th><th>Energy</th><th>Duration</th></tr>';
  for (const s of data.sessions.slice(0, 10)) {
    html += `<tr style="border-bottom:1px solid var(--border)">
      <td style="padding:0.5rem 0">${s.date || '--'}</td>
      <td>${s.type || '--'}</td>
      <td>${s.energyAdded ?? '--'}</td>
      <td>${s.duration ?? '--'}</td>
    </tr>`;
  }
  html += '</table>';
  el.innerHTML = html;
}

function renderOTA(data) {
  const el = document.getElementById('ota-info');
  if (!data) { el.innerHTML = 'No OTA data available.'; return; }

  let html = '';
  if (data.version) html += `<div><strong>Current Version:</strong> ${data.version}</div>`;
  if (data.availableVersion) html += `<div><strong>Update Available:</strong> ${data.availableVersion}</div>`;
  if (data.schedule) html += `<div><strong>Scheduled:</strong> ${data.schedule}</div>`;
  if (data.optIn) html += `<div><strong>Auto-opt-in:</strong> ${data.optIn ? 'Yes' : 'No'}</div>`;
  if (data.status) html += `<div><strong>Status:</strong> ${data.status}</div>`;
  el.innerHTML = html || 'No OTA data available.';
}

// ===== CHART =====
let cellSpreadChart = null;

function updateCellSpreadChart() {
  const ctx = document.getElementById('cell-spread-chart').getContext('2d');

  if (cellSpreadChart) cellSpreadChart.destroy();

  const labels = cellSpreadHistory.map((_, i) => {
    const d = new Date(Date.now() - (cellSpreadHistory.length - i) * 86400000);
    return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
  });

  cellSpreadChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels,
      datasets: [{
        label: 'Cell Voltage Spread (mV)',
        data: cellSpreadHistory,
        borderColor: '#00ff88',
        backgroundColor: 'rgba(0,255,136,0.1)',
        fill: true,
        tension: 0.3,
        pointRadius: 3
      }]
    },
    options: {
      responsive: true,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: '#8888aa', maxTicksLimit: 7 }, grid: { color: 'rgba(255,255,255,0.05)' } },
        y: { ticks: { color: '#8888aa' }, grid: { color: 'rgba(255,255,255,0.05)' } }
      }
    }
  });
}

// ===== UI HELPERS =====
function showLogin() {
  document.getElementById('login-screen').classList.add('active');
  document.getElementById('dashboard').classList.remove('active');
  document.getElementById('refresh-bar').style.display = 'none';
  document.getElementById('login-btn').style.display = 'inline-block';
  document.getElementById('logout-btn').style.display = 'none';
}

function showDashboard() {
  document.getElementById('login-screen').classList.remove('active');
  document.getElementById('dashboard').classList.add('active');
  document.getElementById('refresh-bar').style.display = 'block';
  document.getElementById('login-btn').style.display = 'none';
  document.getElementById('logout-btn').style.display = 'inline-block';
}

function logout() {
  clearTokens();
  accessToken = null;
  refreshToken = null;
  showLogin();
}

function toggleSection(btn) {
  const content = btn.nextElementSibling;
  content.classList.toggle('open');
  btn.textContent = content.classList.contains('open')
    ? btn.textContent.replace('▾', '▴')
    : btn.textContent.replace('▴', '▾');
}

function setStatus(msg) {
  document.getElementById('connection-status').textContent = msg;
}

function showError(msg) {
  const div = document.createElement('div');
  div.className = 'error-msg';
  div.textContent = msg;
  document.querySelector('.container').prepend(div);
  setTimeout(() => div.remove(), 5000);
}

// Handle OAuth callback on page load
if (window.location.search.includes('code=')) {
  handleCallback();
}