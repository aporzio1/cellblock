import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';

if (!globalThis.crypto) globalThis.crypto = webcrypto;

import { runScheduledMonitoring, MonitoringCoordinatorCore } from '../monitoring.js';
import { handleInstallationRequest } from '../installations.js';

class MemoryKV {
  constructor(values = {}) { this.values = new Map(Object.entries(values)); }
  async get(key) { return this.values.get(key) ?? null; }
  async put(key, value) {
    if (typeof key === 'object') for (const [k, v] of Object.entries(key)) this.values.set(k, v);
    else this.values.set(key, value);
  }
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

// Hermetic garage stub: bootstrap now verifies the bearer with Ford, so test
// environments must simulate a verified account instead of reaching the real
// API (which would reject the fixture bearer and burn a real request).
const verifiedGarageFetch = async () => new Response(
  JSON.stringify({ vehicles: [{ vin: '1FTVW1ELXPWG00001' }] }),
  { status: 200, headers: { 'Content-Type': 'application/json' } }
);

async function enrolledEnvironment(chargingMode = 'home', overrides = {}) {
  const targetEnv = makeEnv({}, overrides);
  const bootstrapResponse = await handleInstallationRequest(request('/api/installations/bootstrap', {
    token: 'ford-access', body: {}
  }), targetEnv, { fetchImpl: verifiedGarageFetch });
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

test('cron telemetry reads route through the shared Ford proxy', async () => {
  const { targetEnv } = await enrolledEnvironment('home');
  const calls = [];
  const fakeFetch = async (url) => {
    calls.push(String(url));
    if (String(url).includes('/oauth2/')) return new Response(JSON.stringify({ access_token: 'access' }), { status: 200 });
    return new Response(JSON.stringify({ timestamp: '2026-08-22T15:00:00Z', metrics: {} }), { status: 200 });
  };
  await runScheduledMonitoring(targetEnv, { fetchImpl: fakeFetch, now: 5_000_000 });
  const telemetry = calls.find(url => url.includes('/telemetry'));
  assert.ok(telemetry, 'expected a telemetry call');
  assert.ok(telemetry.startsWith('https://proxy.cellblock.cc/api/data/telemetry'), telemetry);
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

test('duplicate vehicle registrations: poll once and push via the token-holding one', async () => {
  // Real phone (has a push-to-start token) + a stale re-registration of the SAME
  // vehicle that has none. Reproduce production where the token-less id sorts
  // first in the index: cron must still deliver to the token holder, not silently
  // drop the event by polling the dead registration.
  const { targetEnv, installationID, token } = await enrolledEnvironment('home');
  await handleInstallationRequest(request('/api/live-activities/tokens', {
    method: 'PUT', token,
    body: { opaqueVehicleID: 'opaque-vehicle', tokenKind: 'pushToStart', token: 'push-token', apnsEnvironment: 'sandbox' }
  }), targetEnv);
  const keyPair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', keyPair.privateKey));
  const pem = `-----BEGIN PRIVATE KEY-----\n${btoa(String.fromCharCode(...pkcs8))}\n-----END PRIVATE KEY-----`;
  Object.assign(targetEnv, { APNS_PRIVATE_KEY_P8: pem });

  // Clone the real authorization into a token-less stale registration whose id
  // sorts FIRST, sharing the same opaqueVehicleIDHash.
  const staleID = '00000000-0000-0000-0000-000000000000';
  const realKey = `ford-authorization:${installationID}`;
  const real = JSON.parse(targetEnv.INSTALLATIONS.values.get(realKey));
  targetEnv.INSTALLATIONS.values.set(`ford-authorization:${staleID}`, JSON.stringify(real));
  targetEnv.INSTALLATIONS.values.set('ford-authorization-index',
    JSON.stringify([`ford-authorization:${staleID}`, realKey]));

  // Clone the real token too, but deliberately omit the stale enrollment. This
  // models a KV index containing a token-bearing orphan ahead of the real phone.
  const existingTokenKey = [...targetEnv.INSTALLATIONS.values.keys()].find(k => k.startsWith('live-activity-token:'));
  const staleTokenKey = existingTokenKey.replace(installationID, staleID);
  targetEnv.INSTALLATIONS.values.set(staleTokenKey, targetEnv.INSTALLATIONS.values.get(existingTokenKey));
  const staleBefore = targetEnv.INSTALLATIONS.values.get(staleTokenKey);

  const calls = [];
  const fakeFetch = async (url, options = {}) => {
    calls.push({ url: String(url), options });
    if (String(url).includes('/oauth2/')) return new Response(JSON.stringify({ access_token: 'access' }), { status: 200 });
    if (String(url).includes('/telemetry')) return new Response(JSON.stringify({
      timestamp: '2026-09-21T01:38:08Z', metrics: {
        xevBatteryChargeDisplayStatus: { value: 'CHARGING' },
        xevPlugChargerStatus: { value: 'CHARGING' },
        xevBatteryStateOfCharge: { value: 95 },
        xevBatteryChargerVoltageOutput: { value: 240 },
        xevBatteryChargerCurrentOutput: { value: 30 }
      }
    }), { status: 200 });
    return new Response('{}', { status: 200 });
  };
  await runScheduledMonitoring(targetEnv, { fetchImpl: fakeFetch, now: 9_000_000 });

  assert.equal(calls.filter(c => c.url.includes('/telemetry')).length, 1, 'one telemetry read per vehicle');
  const apns = calls.find(c => c.url.includes('push.apple.com'));
  assert.ok(apns, 'push must be delivered to the token-holding registration');
  assert.equal(JSON.parse(apns.options.body).aps.event, 'start');
  assert.equal(targetEnv.INSTALLATIONS.values.get(staleTokenKey), staleBefore, 'orphan token must not be invalidated');
});

async function apnsResponseScenario(status, reason, rotate = false) {
  const { targetEnv, installationID, token } = await enrolledEnvironment('home');
  await handleInstallationRequest(request('/api/live-activities/tokens', {
    method: 'PUT', token,
    body: { opaqueVehicleID: 'opaque-vehicle', tokenKind: 'pushToStart', token: 'push-token', apnsEnvironment: 'sandbox' }
  }), targetEnv);
  const keyPair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', keyPair.privateKey));
  const pem = `-----BEGIN PRIVATE KEY-----\n${btoa(String.fromCharCode(...pkcs8))}\n-----END PRIVATE KEY-----`;
  Object.assign(targetEnv, { APNS_PRIVATE_KEY_P8: pem });
  let rotatedRecord;
  const fakeFetch = async (url) => {
    if (String(url).includes('/oauth2/')) return new Response(JSON.stringify({ access_token: 'access' }), { status: 200 });
    if (String(url).includes('push.apple.com')) {
      if (rotate) {
        const response = await handleInstallationRequest(request('/api/live-activities/tokens', {
          method: 'PUT', token,
          body: { opaqueVehicleID: 'opaque-vehicle', tokenKind: 'pushToStart', token: 'rotated-token', apnsEnvironment: 'sandbox' }
        }), targetEnv);
        assert.equal(response.status, 200);
        rotatedRecord = [...targetEnv.INSTALLATIONS.values.entries()].find(([key]) => key.startsWith('live-activity-token:'))[1];
      }
      return new Response(JSON.stringify({ reason }), { status });
    }
    if (String(url).includes('/telemetry')) return new Response(JSON.stringify({
      timestamp: '2026-09-21T02:00:00Z', metrics: {
        xevBatteryChargeDisplayStatus: { value: 'CHARGING' }, xevPlugChargerStatus: { value: 'CHARGING' },
        xevBatteryStateOfCharge: { value: 95 }, xevBatteryChargerVoltageOutput: { value: 240 }, xevBatteryChargerCurrentOutput: { value: 30 }
      }
    }), { status: 200 });
    return new Response('{}', { status: 200 });
  };
  await runScheduledMonitoring(targetEnv, { fetchImpl: fakeFetch, now: 11_000_000 });
  const tokenKeys = [...targetEnv.INSTALLATIONS.values.keys()].filter(k => k.startsWith('live-activity-toke' + 'n:'));
  const auth = JSON.parse(targetEnv.INSTALLATIONS.values.get(`ford-authorization:${installationID}`));
  return { targetEnv, tokenKeys, rotatedRecord, monitoringError: auth.monitoringError };
}

test('diagnostics identify APNs event and token kind without arbitrary response text', async () => {
  const logs = [];
  const original = console.log;
  console.log = (...args) => logs.push(args);
  try { await apnsResponseScenario(410, 'sensitive-untrusted-response'); }
  finally { console.log = original; }
  const diagnostic = logs.filter(entry => entry[0] === 'charging-diagnostic').map(entry => JSON.parse(entry[1]));
  const apns = diagnostic.find(entry => entry.stage === 'apns');
  assert.deepEqual(apns, { stage: 'apns', event: 'start', kind: 'pushToStart', outcome: 'invalidToken', status: 410, reason: null, tokenPresent: true });
  assert.ok(diagnostic.some(entry => entry.stage === 'state' && entry.previousCharging === false && entry.currentCharging === true));
  assert.ok(!JSON.stringify(logs).includes('sensitive-untrusted-response'));
  assert.ok(!JSON.stringify(logs).includes('push-token'));
});

test('APNs 400 keeps the push token and records the reason', async () => {
  const { tokenKeys, monitoringError } = await apnsResponseScenario(400, 'BadMessage');
  assert.equal(tokenKeys.length, 1, 'a 400 must NOT delete the push-to-start token');
  assert.equal(monitoringError.status, 400);
  assert.equal(monitoringError.reason, 'BadMessage');
});

test('APNs 410 cannot delete a token rotated while the request was in flight', async () => {
  const { targetEnv, tokenKeys, rotatedRecord, monitoringError } = await apnsResponseScenario(410, 'Unregistered', true);
  assert.ok(rotatedRecord);
  assert.equal(tokenKeys.length, 1, 'KV cannot safely delete the token after an asynchronous send');
  assert.equal(targetEnv.INSTALLATIONS.values.get(tokenKeys[0]), rotatedRecord);
  assert.equal(monitoringError.code, 'apnsUnregistered');
  assert.equal(monitoringError.reason, 'Unregistered');
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

function testPem(keyPair) {
  return async () => {
    const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', keyPair.privateKey));
    const body = Buffer.from(pkcs8).toString('base64').replace(/(.{64})/g, '$1\n');
    return `-----BEGIN PRIVATE KEY-----\n${body}\n-----END PRIVATE KEY-----`;
  };
}

test('content-state carries the enrolled units preference to the widget', async () => {
  const { targetEnv, token } = await enrolledEnvironment('home');
  // Re-enroll with an explicit units preference (enroll is idempotent).
  await handleInstallationRequest(request('/api/live-activities/enroll', {
    token,
    body: { opaqueVehicleID: 'opaque-vehicle', apnsEnvironment: 'sandbox', chargingMode: 'home', units: 'imperial' }
  }), targetEnv);
  await handleInstallationRequest(request('/api/live-activities/tokens', {
    method: 'PUT', token,
    body: { opaqueVehicleID: 'opaque-vehicle', tokenKind: 'pushToStart', token: 'push-token', apnsEnvironment: 'sandbox' }
  }), targetEnv);
  Object.assign(targetEnv, { APNS_PRIVATE_KEY_P8: await (await testPem(await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign'])))() });
  const calls = [];
  const fakeFetch = async (url, options = {}) => {
    calls.push({ url: String(url), options });
    if (String(url).includes('/oauth2/')) return new Response(JSON.stringify({ access_token: 'access' }), { status: 200 });
    if (String(url).includes('/telemetry')) return new Response(JSON.stringify({
      timestamp: '2026-08-22T15:00:00Z',
      metrics: {
        xevBatteryChargeDisplayStatus: { value: 'CHARGING' },
        xevBatteryStateOfCharge: { value: 40 },
        xevBatteryChargerVoltageOutput: { value: 400 },
        xevBatteryChargerCurrentOutput: { value: 10 }
      }
    }), { status: 200 });
    return new Response('{}', { status: 200 });
  };
  await runScheduledMonitoring(targetEnv, { fetchImpl: fakeFetch, now: 12_000_000 });
  const apns = calls.find(call => call.url.includes('push.apple.com'));
  assert.ok(apns, 'expected one APNs push');
  assert.equal(JSON.parse(apns.options.body).aps['content-state'].units, 'imperial');
});

test('failed end remains pending until APNs accepts it', async () => {
  const { targetEnv, installationID, token } = await enrolledEnvironment('home');
  await handleInstallationRequest(request('/api/live-activities/tokens', {
    method: 'PUT', token, body: { opaqueVehicleID: 'opaque-vehicle', tokenKind: 'activity', token: 'activity-token', apnsEnvironment: 'sandbox' }
  }), targetEnv);
  targetEnv.APNS_PRIVATE_KEY_P8 = await (await testPem(await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign'])))();
  const key = `ford-authorization:${installationID}`;
  const auth = JSON.parse(await targetEnv.INSTALLATIONS.get(key));
  auth.lastState = { charging: true, startedAt: '2026-08-22T15:00:00Z' };
  await targetEnv.INSTALLATIONS.put(key, JSON.stringify(auth));
  let attempts = 0;
  const fakeFetch = async url => {
    if (String(url).includes('/oauth2/')) return new Response(JSON.stringify({ access_token: 'access' }));
    if (String(url).includes('/telemetry')) return new Response(JSON.stringify({ metrics: { xevPlugChargerStatus: { value: 'UNPLUGGED' } } }));
    return new Response('{}', { status: ++attempts === 1 ? 503 : 200 });
  };
  await runScheduledMonitoring(targetEnv, { fetchImpl: fakeFetch, now: 1000000 });
  assert.equal(JSON.parse(await targetEnv.INSTALLATIONS.get(key)).lastState.charging, true);
  await runScheduledMonitoring(targetEnv, { fetchImpl: fakeFetch, now: 1060000 });
  assert.equal(JSON.parse(await targetEnv.INSTALLATIONS.get(key)).lastState.charging, false);
  assert.equal(attempts, 2);
});

test('failed and ambiguous APNs starts retry without consuming the edge', async () => {
  for (const failure of ['http', 'network', 'unavailable']) {
    const { targetEnv, installationID, token } = await enrolledEnvironment('home');
    if (failure !== 'unavailable') await handleInstallationRequest(request('/api/live-activities/tokens', {
      method: 'PUT', token, body: { opaqueVehicleID: 'opaque-vehicle', tokenKind: 'pushToStart', token: 'push-token', apnsEnvironment: 'sandbox' }
    }), targetEnv);
    targetEnv.APNS_PRIVATE_KEY_P8 = await (await testPem(await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign'])))();
    let attempts = 0;
    const fakeFetch = async url => {
      if (String(url).includes('/oauth2/')) return new Response(JSON.stringify({ access_token: 'access' }));
      if (String(url).includes('/telemetry')) return new Response(JSON.stringify({ metrics: {
        xevBatteryChargeDisplayStatus: { value: 'CHARGING' },
        xevBatteryChargerVoltageOutput: { value: 240 }, xevBatteryChargerCurrentOutput: { value: 30 }
      } }));
      attempts++;
      if (attempts === 1 && failure === 'network') throw new Error('connection lost');
      if (attempts === 1 && failure === 'http') return new Response('{}', { status: 503 });
      return new Response('{}');
    };
    await runScheduledMonitoring(targetEnv, { fetchImpl: fakeFetch, now: 1000000 });
    let record = JSON.parse(await targetEnv.INSTALLATIONS.get(`ford-authorization:${installationID}`));
    assert.notEqual(record.lastState?.charging, true, failure);
    assert.ok(record.monitoringError, failure);
    if (failure === 'unavailable') await handleInstallationRequest(request('/api/live-activities/tokens', {
      method: 'PUT', token, body: { opaqueVehicleID: 'opaque-vehicle', tokenKind: 'pushToStart', token: 'push-token', apnsEnvironment: 'sandbox' }
    }), targetEnv);
    await runScheduledMonitoring(targetEnv, { fetchImpl: fakeFetch, now: 1060000 });
    record = JSON.parse(await targetEnv.INSTALLATIONS.get(`ford-authorization:${installationID}`));
    assert.equal(record.lastState.charging, true, failure);
    assert.equal(record.monitoringError, null, failure);
    assert.equal(attempts, failure === 'unavailable' ? 1 : 2, failure);
  }
});

test('content-state units stays null for an enrollment made without units', async () => {
  const { targetEnv, token } = await enrolledEnvironment('home');
  await handleInstallationRequest(request('/api/live-activities/tokens', {
    method: 'PUT', token,
    body: { opaqueVehicleID: 'opaque-vehicle', tokenKind: 'pushToStart', token: 'push-token', apnsEnvironment: 'sandbox' }
  }), targetEnv);
  Object.assign(targetEnv, { APNS_PRIVATE_KEY_P8: await (await testPem(await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign'])))() });
  const calls = [];
  const fakeFetch = async (url, options = {}) => {
    calls.push({ url: String(url), options });
    if (String(url).includes('/oauth2/')) return new Response(JSON.stringify({ access_token: 'access' }), { status: 200 });
    if (String(url).includes('/telemetry')) return new Response(JSON.stringify({
      timestamp: '2026-08-22T15:00:00Z',
      metrics: {
        xevBatteryChargeDisplayStatus: { value: 'CHARGING' },
        xevBatteryStateOfCharge: { value: 40 },
        xevBatteryChargerVoltageOutput: { value: 400 },
        xevBatteryChargerCurrentOutput: { value: 10 }
      }
    }), { status: 200 });
    return new Response('{}', { status: 200 });
  };
  await runScheduledMonitoring(targetEnv, { fetchImpl: fakeFetch, now: 13_000_000 });
  const apns = calls.find(call => call.url.includes('push.apple.com'));
  assert.ok(apns, 'expected one APNs push');
  assert.equal(JSON.parse(apns.options.body).aps['content-state'].units, null);
});

test('coordinator serializes overlapping cron, survives restart and bounds ambiguous retries', async () => {
  const { targetEnv, installationID, token } = await enrolledEnvironment('home');
  await handleInstallationRequest(request('/api/live-activities/tokens', {
    method: 'PUT', token, body: { opaqueVehicleID: 'opaque-vehicle', tokenKind: 'pushToStart', token: 'push-token', apnsEnvironment: 'sandbox' }
  }), targetEnv);
  targetEnv.APNS_PRIVATE_KEY_P8 = await (await testPem(await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign'])))();
  const key = `ford-authorization:${installationID}`;
  let attempts = 0, release, entered;
  const blocked = new Promise(resolve => { release = resolve; });
  const reached = new Promise(resolve => { entered = resolve; });
  const fakeFetch = async url => {
    if (String(url).includes('/oauth2/')) return new Response(JSON.stringify({ access_token: 'access' }));
    if (String(url).includes('/telemetry')) return new Response(JSON.stringify({ metrics: {
      xevBatteryChargeDisplayStatus: { value: 'CHARGING' },
      xevBatteryChargerVoltageOutput: { value: 240 }, xevBatteryChargerCurrentOutput: { value: 30 }
    } }));
    attempts++;
    if (attempts === 1) { entered(); await blocked; }
    throw new Error('ambiguous APNs failure');
  };
  const storage = new MemoryKV();
  let coordinator = new MonitoringCoordinatorCore(storage, targetEnv, fakeFetch);
  const first = coordinator.run([key], 1_000_000);
  await reached;
  assert.deepEqual(await coordinator.run([key], 1_000_000), { skipped: true });
  release();
  await first;
  assert.notEqual(JSON.parse(await targetEnv.INSTALLATIONS.get(key)).lastState?.charging, true);
  coordinator = new MonitoringCoordinatorCore(storage, targetEnv, fakeFetch);
  await coordinator.run([key], 1_060_000);
  await coordinator.run([key], 1_120_000);
  await coordinator.run([key], 1_180_000);
  assert.equal(attempts, 3);
  await coordinator.run([key], 1_900_000);
  assert.equal(attempts, 4);
});

test('single invalid enrollment never dispatches APNs', async () => {
  const { targetEnv, installationID, token } = await enrolledEnvironment('home');
  await handleInstallationRequest(request('/api/live-activities/tokens', {
    method: 'PUT', token, body: { opaqueVehicleID: 'opaque-vehicle', tokenKind: 'pushToStart', token: 'push-token', apnsEnvironment: 'sandbox' }
  }), targetEnv);
  const enrollmentKey = [...targetEnv.INSTALLATIONS.values.keys()].find(k => k.startsWith('live-activity:'));
  const enrollment = JSON.parse(await targetEnv.INSTALLATIONS.get(enrollmentKey));
  enrollment.chargingMode = 'bogus';
  await targetEnv.INSTALLATIONS.put(enrollmentKey, JSON.stringify(enrollment));
  let apns = 0;
  const fakeFetch = async url => {
    if (String(url).includes('/oauth2/')) return new Response(JSON.stringify({ access_token: 'access' }));
    if (String(url).includes('/telemetry')) return new Response(JSON.stringify({ metrics: { xevBatteryChargeDisplayStatus: { value: 'CHARGING' } } }));
    apns++; return new Response('{}');
  };
  await new MonitoringCoordinatorCore(new MemoryKV(), targetEnv, fakeFetch).run([`ford-authorization:${installationID}`]);
  assert.equal(apns, 0);
});

test('successful start remains deduplicated after coordinator restart with stale KV', async () => {
  const { targetEnv, installationID, token } = await enrolledEnvironment('home');
  await handleInstallationRequest(request('/api/live-activities/tokens', {
    method: 'PUT', token, body: { opaqueVehicleID: 'opaque-vehicle', tokenKind: 'pushToStart', token: 'push-token', apnsEnvironment: 'sandbox' }
  }), targetEnv);
  targetEnv.APNS_PRIVATE_KEY_P8 = await (await testPem(await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign'])))();
  const key = `ford-authorization:${installationID}`;
  const oldAuth = await targetEnv.INSTALLATIONS.get(key);
  let sends = 0;
  const fakeFetch = async url => {
    if (String(url).includes('/oauth2/')) return new Response(JSON.stringify({ access_token: 'access' }));
    if (String(url).includes('/telemetry')) return new Response(JSON.stringify({ metrics: {
      xevBatteryChargeDisplayStatus: { value: 'CHARGING' },
      xevBatteryChargerVoltageOutput: { value: 240 }, xevBatteryChargerCurrentOutput: { value: 30 }
    } }));
    sends++; return new Response('{}');
  };
  const storage = new MemoryKV();
  await new MonitoringCoordinatorCore(storage, targetEnv, fakeFetch).run([key], 1_000_000);
  await targetEnv.INSTALLATIONS.put(key, oldAuth);
  await new MonitoringCoordinatorCore(storage, targetEnv, fakeFetch).run([key], 1_060_000);
  assert.equal(sends, 1);
});
