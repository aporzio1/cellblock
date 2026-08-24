const MAX_BODY_BYTES = 64 * 1024;
const MAX_AUTHORIZATION_BYTES = 8 * 1024;
const REGISTERED_REDIRECT_URI = 'https://cellblock.cc/';
const AUTHORIZATION_INDEX_KEY = 'ford-authorization-index';
import { encryptValue, validateVIN } from './monitoring.js';

class BadRequest extends Error {}

function corsHeaders(env, request) {
  const allowed = (env.ALLOWED_ORIGIN || '*').split(',').map(value => value.trim());
  const requestOrigin = request.headers.get('origin');
  const matched = allowed.includes('*') ? '*' : (allowed.includes(requestOrigin) ? requestOrigin : allowed[0]);
  return {
    'Access-Control-Allow-Origin': matched,
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Vary': 'Origin'
  };
}

function response(env, request, status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders(env, request) }
  });
}

function configurationError(env, request) {
  return response(env, request, 503, { error: 'Installation storage is not configured' });
}

function hasKv(env) {
  return Boolean(env && env.INSTALLATIONS &&
    typeof env.INSTALLATIONS.get === 'function' &&
    typeof env.INSTALLATIONS.put === 'function');
}

function parseBearer(request) {
  const authorization = request.headers.get('authorization');
  if (!authorization || new TextEncoder().encode(authorization).byteLength > MAX_AUTHORIZATION_BYTES) {
    return null;
  }
  const match = /^Bearer ([^ ]+)$/.exec(authorization);
  return match ? match[1] : null;
}

async function readJson(request) {
  const bytes = new TextEncoder().encode(await request.text());
  if (bytes.byteLength > MAX_BODY_BYTES) throw new BadRequest('Request body is too large');
  if (bytes.byteLength === 0) throw new BadRequest('Request body is required');
  let body;
  try {
    body = JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    throw new BadRequest('Request body must be valid JSON');
  }
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    throw new BadRequest('Request body must be a JSON object');
  }
  return body;
}

function stringField(body, name, limit) {
  const value = body[name];
  if (typeof value !== 'string' || value.length === 0 || value.length > limit) {
    throw new BadRequest(`${name} must be a non-empty string of at most ${limit} characters`);
  }
  return value;
}

function optionalStringField(body, name, limit) {
  if (body[name] === undefined) return undefined;
  return stringField(body, name, limit);
}

function base64UrlEncode(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function base64Decode(value) {
  let binary;
  try {
    binary = atob(value);
  } catch {
    throw new Error('Invalid encryption key');
  }
  return Uint8Array.from(binary, character => character.charCodeAt(0));
}

function hex(bytes) {
  return Array.from(new Uint8Array(bytes), byte => byte.toString(16).padStart(2, '0')).join('');
}

async function sha256(value) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return hex(digest);
}

function equalStrings(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string' || left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  }
  return difference === 0;
}

function randomToken() {
  return base64UrlEncode(crypto.getRandomValues(new Uint8Array(32)));
}

async function installationCredentialFromBearer(env, request) {
  const token = parseBearer(request);
  if (!token) return { error: response(env, request, 401, { error: 'Installation authorization is required' }) };

  const tokenHash = await sha256(token);
  const installationID = await env.INSTALLATIONS.get('credential:' + tokenHash);
  if (!installationID || installationID.length > 128) {
    return { error: response(env, request, 401, { error: 'Invalid installation authorization' }) };
  }

  const raw = await env.INSTALLATIONS.get(installationID);
  if (!raw) return { error: response(env, request, 401, { error: 'Invalid installation authorization' }) };

  let record;
  try {
    record = JSON.parse(raw);
  } catch {
    return { error: response(env, request, 401, { error: 'Invalid installation authorization' }) };
  }
  if (!equalStrings(record.tokenHash, tokenHash)) {
    return { error: response(env, request, 401, { error: 'Invalid installation authorization' }) };
  }
  return { installationID, record };
}

async function encryptRefreshToken(refreshToken, encodedKey) {
  let keyBytes;
  try {
    keyBytes = base64Decode(encodedKey);
  } catch {
    throw new Error('Invalid encryption key');
  }
  if (keyBytes.byteLength !== 32) throw new Error('Invalid encryption key');

  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    new TextEncoder().encode(refreshToken)
  );
  return JSON.stringify({
    algorithm: 'AES-GCM',
    iv: base64UrlEncode(iv),
    ciphertext: base64UrlEncode(new Uint8Array(ciphertext))
  });
}

async function bootstrap(env, request) {
  const fordToken = parseBearer(request);
  if (!fordToken) return response(env, request, 401, { error: 'Ford authorization is required' });
  if (!hasKv(env)) return configurationError(env, request);

  const installationID = crypto.randomUUID();
  const token = randomToken();
  const tokenHash = await sha256(token);
  await env.INSTALLATIONS.put(installationID, JSON.stringify({
    tokenHash,
    subjectHash: await sha256(fordToken)
  }));
  await env.INSTALLATIONS.put('credential:' + tokenHash, installationID);
  return response(env, request, 200, { installationID, token });
}

function vehicleKey(installationID, opaqueVehicleHash) {
  return `live-activity:${installationID}:${opaqueVehicleHash}`;
}

async function vehicleHash(body) {
  return sha256(stringField(body, 'opaqueVehicleID', 512));
}

function pathIdentifier(pathname, prefix) {
  if (!pathname.startsWith(prefix)) throw new BadRequest('Invalid route identifier');
  const encoded = pathname.slice(prefix.length);
  if (!encoded || encoded.includes('/')) throw new BadRequest('Invalid route identifier');
  try {
    return decodeURIComponent(encoded);
  } catch {
    throw new BadRequest('Invalid route identifier');
  }
}

async function enrollmentRecord(env, installationID, opaqueVehicleID) {
  const hash = await sha256(opaqueVehicleID);
  const key = vehicleKey(installationID, hash);
  const raw = await env.INSTALLATIONS.get(key);
  if (!raw) return { hash, key, record: null };
  try {
    return { hash, key, record: JSON.parse(raw) };
  } catch {
    return { hash, key, record: null };
  }
}

async function enroll(env, request) {
  if (!hasKv(env)) return configurationError(env, request);
  const credential = await installationCredentialFromBearer(env, request);
  if (credential.error) return credential.error;
  try {
    const body = await readJson(request);
    const opaqueVehicleID = stringField(body, 'opaqueVehicleID', 512);
    const apnsEnvironment = stringField(body, 'apnsEnvironment', 64);
    const chargingMode = stringField(body, 'chargingMode', 64);
    const existing = await enrollmentRecord(env, credential.installationID, opaqueVehicleID);
    const enrollmentID = existing.record?.enrollmentID || crypto.randomUUID();
    await env.INSTALLATIONS.put(existing.key, JSON.stringify({
      subjectHash: credential.record.subjectHash,
      opaqueVehicleIDHash: existing.hash,
      apnsEnvironment,
      chargingMode,
      enrollmentID
    }));
    return response(env, request, 200, { status: 'enrolled', enrollmentID });
  } catch (error) {
    if (error instanceof BadRequest) return response(env, request, 400, { error: error.message });
    throw error;
  }
}

async function deleteEnrollment(env, request, pathname) {
  if (!hasKv(env)) return configurationError(env, request);
  const credential = await installationCredentialFromBearer(env, request);
  if (credential.error) return credential.error;
  try {
    const opaqueVehicleID = stringField(
      { opaqueVehicleID: pathIdentifier(pathname, '/api/live-activities/enroll/') },
      'opaqueVehicleID',
      512
    );
    const hash = await sha256(opaqueVehicleID);
    if (typeof env.INSTALLATIONS.delete !== 'function') return configurationError(env, request);
    await env.INSTALLATIONS.delete(vehicleKey(credential.installationID, hash));
    return response(env, request, 200, {});
  } catch (error) {
    if (error instanceof BadRequest) return response(env, request, 400, { error: error.message });
    throw error;
  }
}

async function registerToken(env, request) {
  if (!hasKv(env)) return configurationError(env, request);
  const credential = await installationCredentialFromBearer(env, request);
  if (credential.error) return credential.error;
  try {
    const body = await readJson(request);
    const opaqueVehicleID = stringField(body, 'opaqueVehicleID', 512);
    const tokenKind = stringField(body, 'tokenKind', 128);
    const token = stringField(body, 'token', 4096);
    const apnsEnvironment = stringField(body, 'apnsEnvironment', 64);
    const activityID = optionalStringField(body, 'activityID', 256);
    const opaqueVehicleHash = await sha256(opaqueVehicleID);
    const tokenCiphertext = await encryptValue(token, env.INSTALLATION_ENCRYPTION_KEY);
    await env.INSTALLATIONS.put(
      `live-activity-token:${credential.installationID}:${opaqueVehicleHash}:${await sha256(tokenKind)}`,
      JSON.stringify({
        subjectHash: credential.record.subjectHash,
        tokenHash: await sha256(token),
        tokenCiphertext,
        tokenKind,
        apnsEnvironment,
        ...(activityID === undefined ? {} : { activityID })
      })
    );
    return response(env, request, 200, {});
  } catch (error) {
    if (error instanceof BadRequest) return response(env, request, 400, { error: error.message });
    throw error;
  }
}

async function updatePreferences(env, request, pathname) {
  if (!hasKv(env)) return configurationError(env, request);
  const credential = await installationCredentialFromBearer(env, request);
  if (credential.error) return credential.error;
  try {
    const opaqueVehicleID = stringField(
      { opaqueVehicleID: pathIdentifier(pathname, '/api/live-activities/preferences/') },
      'opaqueVehicleID',
      512
    );
    const chargingMode = stringField(await readJson(request), 'chargingMode', 64);
    const existing = await enrollmentRecord(env, credential.installationID, opaqueVehicleID);
    if (!existing.record) return response(env, request, 404, { error: 'Enrollment not found' });
    await env.INSTALLATIONS.put(existing.key, JSON.stringify({
      ...existing.record,
      chargingMode
    }));
    return response(env, request, 200, { chargingMode });
  } catch (error) {
    if (error instanceof BadRequest) return response(env, request, 400, { error: error.message });
    throw error;
  }
}

async function capability(env, request, pathname) {
  if (!hasKv(env)) return configurationError(env, request);
  const credential = await installationCredentialFromBearer(env, request);
  if (credential.error) return credential.error;
  try {
    const opaqueVehicleID = stringField(
      { opaqueVehicleID: pathIdentifier(pathname, '/api/live-activities/capability/') },
      'opaqueVehicleID',
      512
    );
    const existing = await enrollmentRecord(env, credential.installationID, opaqueVehicleID);
    return existing.record?.enrollmentID
      ? response(env, request, 200, { status: 'enrolled', enrollmentID: existing.record.enrollmentID })
      : response(env, request, 200, { status: 'eligible' });
  } catch (error) {
    if (error instanceof BadRequest) return response(env, request, 400, { error: error.message });
    throw error;
  }
}

async function authorize(env, request) {
  if (!hasKv(env)) return configurationError(env, request);
  const credential = await installationCredentialFromBearer(env, request);
  if (credential.error) return credential.error;
  try {
    const body = await readJson(request);
    const opaqueVehicleID = stringField(body, 'opaqueVehicleID', 512);
    const vin = stringField(body, 'vin', 17);
    if (!validateVIN(vin)) throw new BadRequest('vin must be 17 uppercase alphanumeric characters');
    const refreshToken = stringField(body, 'refreshToken', 4096);
    const redirectURI = stringField(body, 'redirectURI', 2048);
    if (redirectURI !== REGISTERED_REDIRECT_URI) throw new BadRequest('Invalid redirectURI');
    if (typeof env.INSTALLATION_ENCRYPTION_KEY !== 'string' || env.INSTALLATION_ENCRYPTION_KEY.length === 0) {
      return response(env, request, 503, { error: 'Installation encryption is not configured' });
    }
    const refreshTokenCiphertext = await encryptRefreshToken(refreshToken, env.INSTALLATION_ENCRYPTION_KEY);
    const vinCiphertext = await encryptValue(vin, env.INSTALLATION_ENCRYPTION_KEY);
    const authorizationKey = `ford-authorization:${credential.installationID}`;
    await env.INSTALLATIONS.put(
      authorizationKey,
      JSON.stringify({
        subjectHash: credential.record.subjectHash,
        opaqueVehicleIDHash: await sha256(opaqueVehicleID),
        redirectURI,
        refreshTokenCiphertext,
        vinCiphertext,
        status: 'authorized'
      })
    );
    let authorizationKeys = [];
    try {
      authorizationKeys = JSON.parse(await env.INSTALLATIONS.get(AUTHORIZATION_INDEX_KEY) || '[]');
    } catch {
      authorizationKeys = [];
    }
    if (!Array.isArray(authorizationKeys)) authorizationKeys = [];
    if (!authorizationKeys.includes(authorizationKey)) {
      authorizationKeys.push(authorizationKey);
      await env.INSTALLATIONS.put(AUTHORIZATION_INDEX_KEY, JSON.stringify(authorizationKeys));
    }
    return response(env, request, 200, { status: 'authorized' });
  } catch (error) {
    if (error instanceof BadRequest) return response(env, request, 400, { error: error.message });
    if (error instanceof Error && error.message === 'Invalid encryption key') {
      return response(env, request, 503, { error: 'Installation encryption is not configured' });
    }
    throw error;
  }
}

export async function handleInstallationRequest(request, env) {
  const { pathname } = new URL(request.url);
  const installationRoute = pathname === '/api/installations/bootstrap';
  const enrollmentRoute = pathname === '/api/live-activities/enroll';
  const deleteEnrollmentRoute = pathname.startsWith('/api/live-activities/enroll/');
  const tokenRoute = pathname === '/api/live-activities/tokens';
  const preferencesRoute = pathname.startsWith('/api/live-activities/preferences/');
  const capabilityRoute = pathname.startsWith('/api/live-activities/capability/');
  const authorizationRoute = pathname === '/api/ford/authorize';
  const scopedRoute = installationRoute || enrollmentRoute || deleteEnrollmentRoute || tokenRoute ||
    preferencesRoute || capabilityRoute || authorizationRoute ||
    pathname.startsWith('/api/installations/') || pathname.startsWith('/api/live-activities/') ||
    pathname.startsWith('/api/ford/');

  if (!scopedRoute) return null;
  if ((installationRoute || enrollmentRoute || authorizationRoute) && request.method !== 'POST') {
    return response(env, request, 404, { error: 'Not found' });
  }
  if (deleteEnrollmentRoute && request.method !== 'DELETE') return response(env, request, 404, { error: 'Not found' });
  if (tokenRoute && request.method !== 'PUT') return response(env, request, 404, { error: 'Not found' });
  if (preferencesRoute && request.method !== 'PUT') return response(env, request, 404, { error: 'Not found' });
  if (capabilityRoute && request.method !== 'GET') return response(env, request, 404, { error: 'Not found' });

  try {
    if (installationRoute) return bootstrap(env, request);
    if (enrollmentRoute) return enroll(env, request);
    if (deleteEnrollmentRoute) return deleteEnrollment(env, request, pathname);
    if (tokenRoute) return registerToken(env, request);
    if (preferencesRoute) return updatePreferences(env, request, pathname);
    if (capabilityRoute) return capability(env, request, pathname);
    if (authorizationRoute) return authorize(env, request);
    return response(env, request, 404, { error: 'Not found' });
  } catch {
    return response(env, request, 502, { error: 'Installation request failed' });
  }
}

export { REGISTERED_REDIRECT_URI };
