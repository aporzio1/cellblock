import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';

if (!globalThis.crypto) globalThis.crypto = webcrypto;

import { handleInstallationRequest } from '../installations.js';

class MemoryKV {
  constructor() {
    this.values = new Map();
  }

  async put(key, value) {
    this.values.set(key, value);
  }

  async get(key) {
    return this.values.get(key) ?? null;
  }

  async delete(key) {
    this.values.delete(key);
  }
}

const encryptionKey = btoa(String.fromCharCode(...new Uint8Array(32).fill(7)));

function env(overrides = {}) {
  return {
    INSTALLATIONS: new MemoryKV(),
    INSTALLATION_ENCRYPTION_KEY: encryptionKey,
    ...overrides
  };
}

function request(path, { method = 'POST', headers = {}, body } = {}) {
  return new Request('https://cellblock.cc' + path, {
    method,
    headers: body === undefined ? headers : { 'Content-Type': 'application/json', ...headers },
    body: body === undefined ? undefined : JSON.stringify(body)
  });
}

async function bootstrap(targetEnv = env(), fordToken = 'ford-access-token') {
  const response = await handleInstallationRequest(request('/api/installations/bootstrap', {
    headers: { Authorization: 'Bearer ' + fordToken },
    body: {}
  }), targetEnv);
  assert.equal(response.status, 200);
  return { data: await response.json(), fordToken };
}

function installationRequest(path, token, options = {}) {
  return request(path, {
    ...options,
    headers: { Authorization: 'Bearer ' + token, ...options.headers }
  });
}

test('enrollment uses the iOS payload and returns a stable enrollment ID', async () => {
  const targetEnv = env();
  const { data } = await bootstrap(targetEnv);
  const payload = {
    opaqueVehicleID: 'opaque-vehicle',
    apnsEnvironment: 'sandbox',
    chargingMode: 'scheduled'
  };

  const first = await handleInstallationRequest(installationRequest(
    '/api/live-activities/enroll', data.token, { body: payload }
  ), targetEnv);
  assert.equal(first.status, 200);
  const firstBody = await first.json();
  assert.equal(firstBody.status, 'enrolled');
  assert.equal(typeof firstBody.enrollmentID, 'string');
  assert.deepEqual(Object.keys(firstBody).sort(), ['enrollmentID', 'status']);

  const second = await handleInstallationRequest(installationRequest(
    '/api/live-activities/enroll', data.token, { body: payload }
  ), targetEnv);
  assert.deepEqual(await second.json(), firstBody);
});

test('capability reports eligibility before enrollment and enrollment after it', async () => {
  const targetEnv = env();
  const { data } = await bootstrap(targetEnv);
  const path = '/api/live-activities/capability/opaque-vehicle';

  const eligible = await handleInstallationRequest(installationRequest(path, data.token, {
    method: 'GET'
  }), targetEnv);
  assert.deepEqual(await eligible.json(), { status: 'eligible' });

  const enrollment = await handleInstallationRequest(installationRequest(
    '/api/live-activities/enroll', data.token, {
      body: { opaqueVehicleID: 'opaque-vehicle', apnsEnvironment: 'production', chargingMode: 'immediate' }
    }
  ), targetEnv);
  const { enrollmentID } = await enrollment.json();

  const enrolled = await handleInstallationRequest(installationRequest(path, data.token, {
    method: 'GET'
  }), targetEnv);
  assert.deepEqual(await enrolled.json(), { status: 'enrolled', enrollmentID });
});

test('token registration accepts the iOS payload and never stores the raw token', async () => {
  const targetEnv = env();
  const { data } = await bootstrap(targetEnv);
  const token = 'apns-device-token-secret';
  await handleInstallationRequest(installationRequest('/api/live-activities/enroll', data.token, {
    body: { opaqueVehicleID: 'opaque-vehicle', apnsEnvironment: 'sandbox', chargingMode: 'scheduled' }
  }), targetEnv);

  const response = await handleInstallationRequest(installationRequest('/api/live-activities/tokens', data.token, {
    method: 'PUT',
    body: {
      opaqueVehicleID: 'opaque-vehicle',
      tokenKind: 'pushToStart',
      token,
      apnsEnvironment: 'sandbox',
      activityID: 'activity-123'
    }
  }), targetEnv);
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), {});
  for (const value of targetEnv.INSTALLATIONS.values.values()) {
    assert.ok(!String(value).includes(token));
  }
});

test('preferences update and return the charging mode', async () => {
  const targetEnv = env();
  const { data } = await bootstrap(targetEnv);
  await handleInstallationRequest(installationRequest('/api/live-activities/enroll', data.token, {
    body: { opaqueVehicleID: 'opaque-vehicle', apnsEnvironment: 'production', chargingMode: 'immediate' }
  }), targetEnv);

  const response = await handleInstallationRequest(installationRequest(
    '/api/live-activities/preferences/opaque-vehicle', data.token, {
      method: 'PUT', body: { chargingMode: 'scheduled' }
    }
  ), targetEnv);
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { chargingMode: 'scheduled' });
});

test('deleting enrollment returns an empty object and makes the vehicle eligible', async () => {
  const targetEnv = env();
  const { data } = await bootstrap(targetEnv);
  await handleInstallationRequest(installationRequest('/api/live-activities/enroll', data.token, {
    body: { opaqueVehicleID: 'opaque-vehicle', apnsEnvironment: 'sandbox', chargingMode: 'scheduled' }
  }), targetEnv);

  const deleted = await handleInstallationRequest(installationRequest(
    '/api/live-activities/enroll/opaque-vehicle', data.token, { method: 'DELETE' }
  ), targetEnv);
  assert.equal(deleted.status, 200);
  assert.deepEqual(await deleted.json(), {});

  const capability = await handleInstallationRequest(installationRequest(
    '/api/live-activities/capability/opaque-vehicle', data.token, { method: 'GET' }
  ), targetEnv);
  assert.deepEqual(await capability.json(), { status: 'eligible' });
});

test('Ford authorization returns status while encrypting the refresh token', async () => {
  const targetEnv = env();
  const { data } = await bootstrap(targetEnv);
  const refreshToken = 'ford-refresh-secret';
  const response = await handleInstallationRequest(installationRequest('/api/ford/authorize', data.token, {
    body: {
      opaqueVehicleID: 'opaque-vehicle',
      refreshToken,
      redirectURI: 'https://cellblock.cc/'
    }
  }), targetEnv);
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { status: 'authorized' });
  for (const value of targetEnv.INSTALLATIONS.values.values()) {
    assert.ok(!String(value).includes(refreshToken));
  }
});

test('all live activity routes require the installation credential', async () => {
  const routes = [
    ['/api/live-activities/enroll', 'POST', {}],
    ['/api/live-activities/enroll/opaque-vehicle', 'DELETE'],
    ['/api/live-activities/tokens', 'PUT', {}],
    ['/api/live-activities/preferences/opaque-vehicle', 'PUT', {}],
    ['/api/live-activities/capability/opaque-vehicle', 'GET']
  ];
  for (const [path, method, body] of routes) {
    const response = await handleInstallationRequest(request(path, { method, body }), env());
    assert.equal(response.status, 401, path);
  }
});

test('live activity payload fields must be bounded strings', async () => {
  const targetEnv = env();
  const { data } = await bootstrap(targetEnv);
  const invalid = [
    { opaqueVehicleID: 42, apnsEnvironment: 'sandbox', chargingMode: 'scheduled' },
    { opaqueVehicleID: 'vehicle', apnsEnvironment: '', chargingMode: 'scheduled' },
    { opaqueVehicleID: 'vehicle', apnsEnvironment: 'sandbox', chargingMode: 42 }
  ];
  for (const body of invalid) {
    const response = await handleInstallationRequest(installationRequest('/api/live-activities/enroll', data.token, { body }), targetEnv);
    assert.equal(response.status, 400);
  }
});

test('unknown routes remain 404 and missing installation configuration is explicit', async () => {
  const unknown = await handleInstallationRequest(request('/api/live-activities/unknown', { body: {} }), env());
  assert.equal(unknown.status, 404);
  const missing = await handleInstallationRequest(request('/api/installations/bootstrap', {
    headers: { Authorization: 'Bearer ford-token' }, body: {}
  }), env({ INSTALLATIONS: undefined }));
  assert.equal(missing.status, 503);
});
