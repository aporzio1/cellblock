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
    headers: { 'Content-Type': 'application/json', ...headers },
    body: body === undefined ? undefined : JSON.stringify(body)
  });
}

async function bootstrap(targetEnv = env(), fordToken = 'ford-access-token') {
  const response = await handleInstallationRequest(request('/api/installations/bootstrap', {
    headers: { Authorization: 'Bearer ' + fordToken },
    body: {}
  }), targetEnv);
  assert.equal(response.status, 200);
  return { response, data: await response.json(), fordToken };
}

test('bootstrap returns an installation credential and persists only hashes', async () => {
  const targetEnv = env();
  const { data, fordToken } = await bootstrap(targetEnv);
  assert.equal(typeof data.installationID, 'string');
  assert.equal(typeof data.token, 'string');
  assert.ok(data.token.length >= 32);

  const stored = JSON.parse(await targetEnv.INSTALLATIONS.get(data.installationID));
  const tokenHash = await webcrypto.subtle.digest('SHA-256', new TextEncoder().encode(data.token));
  const subjectHash = await webcrypto.subtle.digest('SHA-256', new TextEncoder().encode(fordToken));
  const hex = bytes => Array.from(new Uint8Array(bytes), byte => byte.toString(16).padStart(2, '0')).join('');
  assert.deepEqual(stored, { tokenHash: hex(tokenHash), subjectHash: hex(subjectHash) });
  assert.ok(!JSON.stringify(stored).includes(data.token));
  assert.ok(!JSON.stringify(stored).includes(fordToken));
});

test('enrollment rejects requests without a valid installation credential', async () => {
  const response = await handleInstallationRequest(request('/api/live-activities/enroll', {
    body: { vehicleID: 'vehicle', pushToken: 'push', activityID: 'activity' }
  }), env());
  assert.equal(response.status, 401);
});

test('enrollment succeeds after bootstrap with the returned installation credential', async () => {
  const targetEnv = env();
  const { data } = await bootstrap(targetEnv);
  const response = await handleInstallationRequest(request('/api/live-activities/enroll', {
    headers: { Authorization: 'Bearer ' + data.token },
    body: { vehicleID: 'vehicle', pushToken: 'push-token', activityID: 'activity' }
  }), targetEnv);
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { ok: true });
});

test('authorized Ford storage never exposes or stores the raw refresh token', async () => {
  const targetEnv = env();
  const { data } = await bootstrap(targetEnv);
  const refreshToken = 'ford-refresh-secret';
  const response = await handleInstallationRequest(request('/api/ford/authorize', {
    headers: { Authorization: 'Bearer ' + data.token },
    body: {
      opaqueVehicleID: 'opaque-vehicle',
      refreshToken,
      redirectURI: 'https://cellblock.cc/'
    }
  }), targetEnv);
  assert.equal(response.status, 200);
  const responseText = await response.text();
  assert.ok(!responseText.includes(refreshToken));
  assert.deepEqual(JSON.parse(responseText), { ok: true });
  for (const value of targetEnv.INSTALLATIONS.values.values()) {
    assert.ok(!String(value).includes(refreshToken));
  }
});

test('missing installation binding or encryption secret returns explicit 503', async () => {
  const missingBinding = await handleInstallationRequest(request('/api/installations/bootstrap', {
    headers: { Authorization: 'Bearer ford-token' },
    body: {}
  }), env({ INSTALLATIONS: undefined }));
  assert.equal(missingBinding.status, 503);

  const targetEnv = env();
  const { data } = await bootstrap(targetEnv);
  const missingSecret = await handleInstallationRequest(request('/api/ford/authorize', {
    headers: { Authorization: 'Bearer ' + data.token },
    body: {
      opaqueVehicleID: 'opaque-vehicle',
      refreshToken: 'refresh-token',
      redirectURI: 'https://cellblock.cc/'
    }
  }), { ...targetEnv, INSTALLATION_ENCRYPTION_KEY: undefined });
  assert.equal(missingSecret.status, 503);
});

test('bad JSON fields are rejected and unknown routes return 404', async () => {
  const invalid = await handleInstallationRequest(request('/api/live-activities/enroll', {
    headers: { Authorization: 'Bearer installation-token' },
    body: { vehicleID: 42, pushToken: 'push', activityID: 'activity' }
  }), env());
  assert.equal(invalid.status, 400);

  const unknown = await handleInstallationRequest(request('/api/live-activities/unknown', {
    body: {}
  }), env());
  assert.equal(unknown.status, 404);
});
