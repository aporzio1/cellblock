const FORD_TOKEN_URL = 'https://api.vehicle.ford.com/dah2vb2cprod.onmicrosoft.com/oauth2/v2.0/token?p=B2C_1A_FCON_AUTHORIZE';
const FORD_TELEMETRY_URL = 'https://api.vehicle.ford.com/fcon-query/v1/telemetry';
const REGISTERED_REDIRECT_URI = 'https://cellblock.cc/';
const AUTHORIZATION_INDEX_KEY = 'ford-authorization-index';
const MIN_CHARGING_POWER_KW = 0.5;
const FAST_CHARGING_POWER_KW = 25;

function base64UrlEncode(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function base64Decode(value) {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(value.length / 4) * 4, '=');
  return Uint8Array.from(atob(normalized), character => character.charCodeAt(0));
}

export function validateVIN(vin) {
  return typeof vin === 'string' && /^[A-Z0-9]{17}$/.test(vin);
}

export async function encryptValue(value, encodedKey) {
  let keyBytes;
  try { keyBytes = base64Decode(encodedKey); } catch { throw new Error('Invalid encryption key'); }
  if (keyBytes.byteLength !== 32) throw new Error('Invalid encryption key');
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(value));
  return JSON.stringify({ algorithm: 'AES-GCM', iv: base64UrlEncode(iv), ciphertext: base64UrlEncode(new Uint8Array(ciphertext)) });
}

export async function decryptValue(ciphertext, encodedKey) {
  let keyBytes;
  try { keyBytes = base64Decode(encodedKey); } catch { throw new Error('Invalid encryption key'); }
  if (keyBytes.byteLength !== 32) throw new Error('Invalid encryption key');
  let envelope;
  try { envelope = JSON.parse(ciphertext); } catch { throw new Error('Invalid ciphertext'); }
  if (envelope?.algorithm !== 'AES-GCM' || typeof envelope.iv !== 'string' || typeof envelope.ciphertext !== 'string') {
    throw new Error('Invalid ciphertext');
  }
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt']);
  const clear = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: base64Decode(envelope.iv) }, key, base64Decode(envelope.ciphertext)
  );
  return new TextDecoder().decode(clear);
}

function sha256Hex(value) {
  return crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)).then(bytes =>
    Array.from(new Uint8Array(bytes), byte => byte.toString(16).padStart(2, '0')).join('')
  );
}

function metricValue(metrics, name) {
  const item = metrics?.[name];
  if (item && typeof item === 'object' && 'value' in item) return item.value;
  return item;
}

function numberValue(value) {
  const number = typeof value === 'number' ? value : Number(value);
  return Number.isFinite(number) ? number : null;
}

function stringValue(value) { return typeof value === 'string' ? value.toUpperCase() : ''; }

export function decodeTelemetry(body) {
  const metrics = body?.metrics || {};
  const displayStatus = stringValue(metricValue(metrics, 'xevBatteryChargeDisplayStatus'));
  const plugStatus = stringValue(metricValue(metrics, 'xevPlugChargerStatus'));
  const voltage = numberValue(metricValue(metrics, 'xevBatteryChargerVoltageOutput'));
  const current = numberValue(metricValue(metrics, 'xevBatteryChargerCurrentOutput'));
  const powerKW = voltage !== null && current !== null ? (voltage * current) / 1000 : null;
  const explicitCharging = displayStatus === 'CHARGING' || displayStatus === 'IN_PROGRESS' ||
    plugStatus === 'CHARGING' || plugStatus === 'IN_PROGRESS';
  const explicitUnplugged = ['UNPLUGGED', 'DISCONNECTED', 'NOT_CHARGING', 'UNPLUGGED_STATUS'].includes(displayStatus) ||
    ['UNPLUGGED', 'DISCONNECTED', 'NOT_CHARGING'].includes(plugStatus);
  const sourceTimestamp = body?.timestamp || body?.sourceTimestamp || body?.lastUpdated || new Date().toISOString();
  return {
    charging: !explicitUnplugged && (explicitCharging || (powerKW !== null && powerKW >= MIN_CHARGING_POWER_KW)),
    powerKW,
    socPercent: numberValue(metricValue(metrics, 'xevBatteryStateOfCharge')),
    rangeKm: numberValue(metricValue(metrics, 'xevBatteryRange')),
    etaMinutes: numberValue(metricValue(metrics, 'xevBatteryTimeToFullCharge')),
    sourceTimestamp: typeof sourceTimestamp === 'string' ? sourceTimestamp : new Date(sourceTimestamp).toISOString()
  };
}

function modeAllowsCharging(mode, telemetry) {
  if (!telemetry.charging) return false;
  if (mode === 'fast') return telemetry.powerKW !== null && telemetry.powerKW >= FAST_CHARGING_POWER_KW;
  if (mode === 'allAC' || mode === 'home') return telemetry.powerKW !== null && telemetry.powerKW < FAST_CHARGING_POWER_KW;
  return mode === 'both' || !mode;
}

function installationKey(id) { return `ford-authorization:${id}`; }
function enrollmentKey(id, hash) { return `live-activity:${id}:${hash}`; }
async function tokenKey(id, hash, kind) { return `live-activity-token:${id}:${hash}:${await sha256Hex(kind)}`; }

async function updateAuthorization(env, key, record, changes) {
  await env.INSTALLATIONS.put(key, JSON.stringify({ ...record, ...changes }));
}

async function exchangeRefreshToken(env, refreshToken, fetchImpl) {
  const scope = `${env.CLIENT_ID} offline_access openid`;
  const response = await fetchImpl(FORD_TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'refresh_token', refresh_token: refreshToken,
      redirect_uri: REGISTERED_REDIRECT_URI, client_id: env.CLIENT_ID, client_secret: env.CLIENT_SECRET, scope
    })
  });
  let body = {};
  try { body = await response.json(); } catch { /* response is intentionally discarded */ }
  if (response.status === 401 || body.error === 'invalid_grant' || !response.ok) {
    const error = new Error(response.status === 401 || body.error === 'invalid_grant' ? 'authorization expired' : 'token exchange failed');
    error.authorizationExpired = response.status === 401 || body.error === 'invalid_grant';
    error.retryable = response.status === 429 || response.status >= 500;
    throw error;
  }
  if (typeof body.access_token !== 'string' || body.access_token.length === 0) throw new Error('token exchange failed');
  return body.access_token;
}

function parsePEM(pem) {
  const body = String(pem || '').replace(/-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----/g, '').replace(/\s+/g, '');
  return base64Decode(body);
}

async function apnsJWT(env, now) {
  if (!env.APNS_TEAM_ID || !env.APNS_KEY_ID || !env.APNS_PRIVATE_KEY_P8 || !env.APNS_TOPIC) return null;
  const header = base64UrlEncode(new TextEncoder().encode(JSON.stringify({ alg: 'ES256', kid: env.APNS_KEY_ID })));
  const payload = base64UrlEncode(new TextEncoder().encode(JSON.stringify({ iss: env.APNS_TEAM_ID, iat: Math.floor(now / 1000) })));
  const input = `${header}.${payload}`;
  const key = await crypto.subtle.importKey('pkcs8', parsePEM(env.APNS_PRIVATE_KEY_P8), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, new TextEncoder().encode(input));
  return `${input}.${base64UrlEncode(new Uint8Array(signature))}`;
}

function contentState(telemetry, state, now) {
  const swiftDate = value => {
    const milliseconds = typeof value === 'number' ? value : Date.parse(value);
    if (!Number.isFinite(milliseconds)) return (now - 978307200000) / 1000;
    return (milliseconds > 10_000_000_000 ? milliseconds / 1000 : milliseconds) - 978307200;
  };
  return {
    phase: telemetry.charging ? 'active' : 'completed',
    powerKW: telemetry.charging ? telemetry.powerKW : null,
    socPercent: telemetry.socPercent,
    rangeKm: telemetry.rangeKm,
    timeToFullMinutes: telemetry.etaMinutes === null ? null : Math.round(telemetry.etaMinutes),
    startedAt: swiftDate(state.startedAt || now),
    lastSourceUpdatedAt: swiftDate(telemetry.sourceTimestamp),
    isStale: false
  };
}

function apnsPayload(event, telemetry, state, now) {
  const aps = { timestamp: Math.floor(now / 1000), event, 'content-state': contentState(telemetry, state, now) };
  if (event === 'start') {
    aps['attributes-type'] = 'ChargingActivityAttributes';
    aps.attributes = { sessionID: state.enrollmentID || 'background', vehicleDisplayName: 'Your vehicle' };
  }
  return { aps };
}

async function sendAPNs(env, environment, token, event, telemetry, state, now, fetchImpl) {
  const jwt = await apnsJWT(env, now);
  if (!jwt || !token) return 'apnsUnavailable';
  const host = environment === 'production' ? 'api.push.apple.com' : 'api.sandbox.push.apple.com';
  const topic = `${env.APNS_TOPIC}.push-type.liveactivity`;
  const response = await fetchImpl(`https://${host}/3/device/${encodeURIComponent(token)}`, {
    method: 'POST',
    headers: {
      authorization: `bearer ${jwt}`,
      'apns-topic': topic,
      'apns-push-type': 'liveactivity',
      'content-type': 'application/json'
    },
    body: JSON.stringify(apnsPayload(event, telemetry, state, now))
  });
  if (response.status === 400 || response.status === 410) return 'invalidToken';
  if (!response.ok) return 'retryable';
  return 'sent';
}

async function monitorAuthorization(env, key, record, fetchImpl, now) {
  const installationID = key.slice('ford-authorization:'.length);
  const storeMonitoringError = async (code, status) => {
    const previous = record.monitoringError;
    if (previous?.code === code && previous?.status === status) return;
    const monitoringError = { code, updatedAt: now };
    if (status !== undefined) monitoringError.status = status;
    await updateAuthorization(env, key, record, { monitoringError });
  };
  if (record?.status === 'reauthorizationRequired') return;
  if (!record?.refreshTokenCiphertext || !record?.vinCiphertext || !record?.opaqueVehicleIDHash) return;
  let refreshToken;
  let vin;
  try {
    refreshToken = await decryptValue(record.refreshTokenCiphertext, env.INSTALLATION_ENCRYPTION_KEY);
    vin = await decryptValue(record.vinCiphertext, env.INSTALLATION_ENCRYPTION_KEY);
  } catch {
    await storeMonitoringError('invalidStoredAuthorization');
    return;
  }
  let accessToken;
  try { accessToken = await exchangeRefreshToken(env, refreshToken, fetchImpl); }
  catch (error) {
    if (error.authorizationExpired) await updateAuthorization(env, key, record, { status: 'reauthorizationRequired' });
    else await storeMonitoringError(error.retryable ? 'retryableUpstream' : 'tokenExchangeFailed');
    return;
  }
  const telemetryURL = new URL(FORD_TELEMETRY_URL);
  telemetryURL.searchParams.set('vin', vin);
  const telemetryResponse = await fetchImpl(telemetryURL, { headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/json' } });
  if (telemetryResponse.status === 401) {
    await updateAuthorization(env, key, record, { status: 'reauthorizationRequired' });
    return;
  }
  if (telemetryResponse.status === 429 || telemetryResponse.status >= 500) {
    await storeMonitoringError('retryableUpstream', telemetryResponse.status);
    return;
  }
  if (!telemetryResponse.ok) {
    await storeMonitoringError('telemetryFailed', telemetryResponse.status);
    return;
  }
  let body;
  try { body = await telemetryResponse.json(); } catch {
    await storeMonitoringError('invalidTelemetry');
    return;
  }
  const telemetry = decodeTelemetry(body);
  const enrollmentRaw = await env.INSTALLATIONS.get(enrollmentKey(installationID, record.opaqueVehicleIDHash));
  if (!enrollmentRaw) return;
  let enrollment;
  try { enrollment = JSON.parse(enrollmentRaw); } catch { return; }
  const charging = modeAllowsCharging(enrollment.chargingMode, telemetry);
  const previous = record.lastState || { charging: false };
  const current = { charging, socPercent: telemetry.socPercent, etaMinutes: telemetry.etaMinutes, sourceTimestamp: telemetry.sourceTimestamp, startedAt: previous.startedAt };
  const started = !previous.charging && charging;
  const ended = previous.charging && !charging;
  const meaningfulUpdate = previous.charging && charging &&
    ((telemetry.socPercent !== null && telemetry.socPercent !== previous.socPercent) ||
      (telemetry.etaMinutes !== null && telemetry.etaMinutes !== previous.etaMinutes));
  const event = started ? 'start' : ended ? 'end' : meaningfulUpdate ? 'update' : null;
  const nextState = { ...current, startedAt: started ? new Date(now).toISOString() : previous.startedAt };
  if (!record.lastState || event) {
    await updateAuthorization(env, key, record, { lastState: nextState, lastSourceTimestamp: telemetry.sourceTimestamp });
  }
  if (!event) return;
  const kind = event === 'start' ? 'pushToStart' : 'activity';
  const tokenRaw = await env.INSTALLATIONS.get(await tokenKey(installationID, record.opaqueVehicleIDHash, kind));
  let tokenRecord;
  try { tokenRecord = tokenRaw ? JSON.parse(tokenRaw) : null; } catch { tokenRecord = null; }
  let token;
  try { token = tokenRecord?.tokenCiphertext ? await decryptValue(tokenRecord.tokenCiphertext, env.INSTALLATION_ENCRYPTION_KEY) : null; } catch { token = null; }
  const result = await sendAPNs(env, enrollment.apnsEnvironment, token, event, { ...telemetry, charging }, { ...nextState, enrollmentID: enrollment.enrollmentID }, now, fetchImpl);
  const tokenStorageKey = await tokenKey(installationID, record.opaqueVehicleIDHash, kind);
  if (result === 'invalidToken') await env.INSTALLATIONS.delete(tokenStorageKey);
  if (result === 'apnsUnavailable') await updateAuthorization(env, key, { ...record, lastState: nextState }, { monitoringError: { code: 'apnsUnavailable', updatedAt: now } });
  else if (result === 'retryable') await updateAuthorization(env, key, { ...record, lastState: nextState }, { monitoringError: { code: 'apnsRetryable', updatedAt: now } });
}

export async function runScheduledMonitoring(env, options = {}) {
  const fetchImpl = options.fetchImpl || fetch;
  const now = options.now || Date.now();
  if (!env?.INSTALLATIONS || typeof env.INSTALLATIONS.get !== 'function') return;
  let keys;
  try {
    keys = JSON.parse(await env.INSTALLATIONS.get(AUTHORIZATION_INDEX_KEY) || '[]');
  } catch {
    keys = [];
  }
  if (!Array.isArray(keys)) return;
  for (const key of keys) {
    if (typeof key !== 'string' || !key.startsWith('ford-authorization:')) continue;
    try {
      const raw = await env.INSTALLATIONS.get(key);
      if (raw) await monitorAuthorization(env, key, JSON.parse(raw), fetchImpl, now);
    } catch {
      // A bad record must not prevent the remaining installations from running.
    }
  }
}
