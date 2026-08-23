import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';

if (!globalThis.crypto) globalThis.crypto = webcrypto;

import { runScheduledMonitoring } from '../monitoring.js';
import { handleInstallationRequest } from '../installations.js';

class MemoryKV {
  constructor(values = {}) { this.values = new Map(Object.entries(values)); }
  async get(key) { return this.values.get(key) ?? null; }
  async put(key, value) { this.values.set(key, value); }
  async delete(key) { this.values.delete(key); }
  async list({ prefix = '', limit = 1000, cursor } = {}) {
    const keys = [...this.values.keys()].filter(key => key.startsWith(prefix)).sort();
    const offset = cursor ? Number(cursor) : 0;
    const page = keys.slice(offset, offset + limit);
    const next = offset + page.length < keys.length ? String(offset + page.length) : undefined;
    return { keys: page.map(name => ({ name })), list_complete: !next, cursor: next };
  }
}

function makeEnv(values = {}, overrides = {}) {
  return {
    INSTALLATIONS: new MemoryKV(values),
    INSTALLATION_ENCRYPTION_KEY: btoa(String.fromCharCode(...new Uint8Array(32).fill(7))),
    CLIENT_ID: 'client-id',
    CLIENT_SECRET: 'client-secret',
    APNS_TEAM_ID: 'team',
    APNS_KEY_ID: 'key',
    APNS_PRIVATE_KEY_P8: '',
    APNS_TOPIC: 'com.example.app',
    ...overrides
  };
}

function request(path, { method = 'POST', token, body } = {}) {
  return new Request('https://cellblock.cc' + path, {
    method,
    headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body)
  });
}

async function enrolledEnvironment(chargingMode = 'home', overrides = {}) {
  const targetEnv = makeEnv({}, overrides);
  const bootstrapResponse = await handleInstallationRequest(request('/api/installations/bootstrap', {
    token: 'ford-access', body: {}
  }), targetEnv);
  const bootstrap = await bootstrapResponse.json();
  await handleInstallationRequest(request('/api/live-activities/enroll', {
    token: bootstrap.token,
    body: { opaqueVehicleID: 'opaque-vehicle', apnsEnvironment: 'sandbox', chargingMode }
  }), targetEnv);
  await handleInstallationRequest(request('/api/ford/authorize', {
    token: bootstrap.token,
    body: { opaqueVehicleID: 'opaque-vehicle', vin: '1FTVW1ELXPWG00001', refreshToken: 'refresh-secret', redirectURI: 'https://cellblock.cc/' }
  }), targetEnv);
  return { targetEnv, installationID: bootstrap.installationID, token: bootstrap.token };
}

test('scheduled monitoring is isolated when one authorization fails', async () => {
  const env = makeEnv({
    'ford-authorization:bad': JSON.stringify({ opaqueVehicleIDHash: 'missing', refreshTokenCiphertext: '{}' }),
    'ford-authorization:good': JSON.stringify({ opaqueVehicleIDHash: 'missing', refreshTokenCiphertext: '{}' })
  });
  const calls = [];
  await assert.doesNotReject(() => runScheduledMonitoring(env, {
    fetchImpl: async (...args) => { calls.push(args); return new Response('{}', { status: 500 }); }
  }));
  assert.equal(calls.length, 0);
});

test('scheduled monitoring only fetches telemetry once per installation', async () => {
  const env = makeEnv();
  const calls = [];
  await runScheduledMonitoring(env, {
    fetchImpl: async (...args) => { calls.push(args); return new Response('{}', { status: 500 }); }
  });
  assert.equal(calls.filter(([url]) => String(url).includes('/telemetry')).length, 0);
});

test('scheduled monitoring emits one APNs start and dedupes the next minute poll', async () => {
  const { targetEnv, installationID, token } = await enrolledEnvironment('home');
  await handleInstallationRequest(request('/api/live-activities/tokens', {
    method: 'PUT', token,
    body: { opaqueVehicleID: 'opaque-vehicle', tokenKind: 'pushToStart', token: 'push-token', apnsEnvironment: 'sandbox' }
  }), targetEnv);
  const keyPair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', keyPair.privateKey));
  const pem = `-----BEGIN PRIVATE KEY-----\n${btoa(String.fromCharCode(...pkcs8))}\n-----END PRIVATE KEY-----`;
  Object.assign(targetEnv, { APNS_PRIVATE_KEY_P8: pem });
  const calls = [];
  const fakeFetch = async (url, options = {}) => {
    calls.push({ url: String(url), options });
    if (String(url).includes('/oauth2/')) return new Response(JSON.stringify({ access_token: 'access' }), { status: 200 });
    if (String(url).includes('/telemetry')) return new Response(JSON.stringify({
      timestamp: '2026-08-22T15:00:00Z', metrics: {
        xevBatteryChargeDisplayStatus: { value: 'CHARGING' },
        xevPlugChargerStatus: { value: 'CHARGING' },
        xevBatteryStateOfCharge: { value: 40 },
        xevBatteryRange: { value: 120 },
        xevBatteryTimeToFullCharge: { value: 80 },
        xevBatteryChargerVoltageOutput: { value: 400 },
        xevBatteryChargerCurrentOutput: { value: 10 }
      }
    }), { status: 200 });
    return new Response('{}', { status: 200 });
  };
  await runScheduledMonitoring(targetEnv, { fetchImpl: fakeFetch, now: 1_000_000 });
  await runScheduledMonitoring(targetEnv, { fetchImpl: fakeFetch, now: 1_000_030 });
  assert.equal(calls.filter(call => call.url.includes('/telemetry')).length, 2);
  const apns = calls.find(call => call.url.includes('push.apple.com'));
  assert.match(apns.options.headers.authorization, /^bearer /);
  assert.equal(apns.options.headers['apns-push-type'], 'liveactivity');
  assert.equal(apns.options.headers['apns-topic'], 'com.example.app.push-type.liveactivity');
  assert.equal(JSON.parse(apns.options.body).aps.event, 'start');
  const stored = JSON.parse(await targetEnv.INSTALLATIONS.get(`ford-authorization:${installationID}`));
  assert.equal(stored.lastState.charging, true);
});

test('steady noncharging telemetry causes no authorization KV puts after initialization', async () => {
  const { targetEnv } = await enrolledEnvironment('home');
  const originalPut = targetEnv.INSTALLATIONS.put.bind(targetEnv.INSTALLATIONS);
  let puts = 0;
  targetEnv.INSTALLATIONS.put = async (...args) => { puts += 1; return originalPut(...args); };
  const fakeFetch = async (url) => {
    if (String(url).includes('/oauth2/')) return new Response(JSON.stringify({ access_token: 'access' }), { status: 200 });
    if (String(url).includes('/telemetry')) return new Response(JSON.stringify({
      timestamp: '2026-08-22T15:00:00Z', metrics: {
        xevBatteryChargeDisplayStatus: { value: 'NOT_CHARGING' },
        xevPlugChargerStatus: { value: 'UNPLUGGED' },
        xevBatteryStateOfCharge: { value: 40 }
      }
    }), { status: 200 });
    return new Response('{}', { status: 200 });
  };
  await runScheduledMonitoring(targetEnv, { fetchImpl: fakeFetch, now: 4_000_000 });
  assert.equal(puts, 1);
  puts = 0;
  await runScheduledMonitoring(targetEnv, { fetchImpl: fakeFetch, now: 4_060_000 });
  assert.equal(puts, 0);
});

test('fast mode gates telemetry below 25kW', async () => {
  const { targetEnv } = await enrolledEnvironment('fast');
  let apnsCalls = 0;
  const fakeFetch = async (url) => {
    if (String(url).includes('/oauth2/')) return new Response(JSON.stringify({ access_token: 'access' }), { status: 200 });
    if (String(url).includes('/telemetry')) return new Response(JSON.stringify({ metrics: {
      xevBatteryChargeDisplayStatus: { value: 'CHARGING' },
      xevBatteryChargerVoltageOutput: { value: 400 }, xevBatteryChargerCurrentOutput: { value: 10 },
      xevBatteryStateOfCharge: { value: 40 }
    } }), { status: 200 });
    apnsCalls += 1;
    return new Response('{}', { status: 200 });
  };
  await runScheduledMonitoring(targetEnv, { fetchImpl: fakeFetch, now: 2_000_000 });
  assert.equal(apnsCalls, 0);
});

test('allAC mode gates telemetry at or above 25kW', async () => {
  const { targetEnv } = await enrolledEnvironment('allAC');
  let apnsCalls = 0;
  const fakeFetch = async (url) => {
    if (String(url).includes('/oauth2/')) return new Response(JSON.stringify({ access_token: 'access' }), { status: 200 });
    if (String(url).includes('/telemetry')) return new Response(JSON.stringify({ metrics: {
      xevBatteryChargeDisplayStatus: { value: 'CHARGING' },
      xevBatteryChargerVoltageOutput: { value: 400 }, xevBatteryChargerCurrentOutput: { value: 62.5 },
      xevBatteryStateOfCharge: { value: 40 }
    } }), { status: 200 });
    apnsCalls += 1;
    return new Response('{}', { status: 200 });
  };
  await runScheduledMonitoring(targetEnv, { fetchImpl: fakeFetch, now: 2_500_000 });
  assert.equal(apnsCalls, 0);
});

test('invalid Ford grant marks authorization for reauthorization', async () => {
  const { targetEnv } = await enrolledEnvironment('home');
  await runScheduledMonitoring(targetEnv, {
    now: 3_000_000,
    fetchImpl: async () => new Response(JSON.stringify({ error: 'invalid_grant' }), { status: 400 })
  });
  const auth = [...targetEnv.INSTALLATIONS.values.entries()].find(([key]) => key.startsWith('ford-authorization:'));
  assert.equal(JSON.parse(auth[1]).status, 'reauthorizationRequired');
});
