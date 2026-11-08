import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { handleInstallationRequest } from '../installations.js';
if (!globalThis.crypto) globalThis.crypto = webcrypto;

class KV {
  values = new Map();
  async get(k) { return this.values.get(k) ?? null; }
  async put(k, v) { this.values.set(k, v); }
  async delete(k) { this.values.delete(k); }
}
const req = (path, token, body, method = 'POST') => new Request('https://example.test' + path, {
  method, headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
  ...(body === undefined ? {} : { body: JSON.stringify(body) })
});
const garage = async () => new Response('{}', { headers: { 'Content-Type': 'application/json' } });
async function setup() {
  const keys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const bytes = new Uint8Array(await crypto.subtle.exportKey('pkcs8', keys.privateKey));
  const env = { INSTALLATIONS: new KV(), INSTALLATION_ENCRYPTION_KEY: btoa(String.fromCharCode(...new Uint8Array(32).fill(7))),
    APNS_TEAM_ID: 'team', APNS_KEY_ID: 'key', APNS_TOPIC: 'com.example.app',
    APNS_PRIVATE_KEY_P8: `-----BEGIN PRIVATE KEY-----\n${btoa(String.fromCharCode(...bytes))}\n-----END PRIVATE KEY-----` };
  const bootstrap = await (await handleInstallationRequest(req('/api/installations/bootstrap', 'ford', {}), env, { fetchImpl: garage })).json();
  await handleInstallationRequest(req('/api/live-activities/enroll', bootstrap.token,
    { opaqueVehicleID: 'vehicle', apnsEnvironment: 'sandbox', chargingMode: 'both', units: 'metric' }), env);
  return { env, token: bootstrap.token };
}
async function register(env, credential, kind, value) {
  const r = await handleInstallationRequest(req('/api/live-activities/tokens', credential,
    { opaqueVehicleID: 'vehicle', tokenKind: kind, token: value, apnsEnvironment: 'sandbox' }, 'PUT'), env);
  assert.equal(r.status, 200);
}
const path = '/api/live-activities/test';

test('synthetic route authenticates, validates, isolates installations and requires enrollment and correct token', async () => {
  const { env, token } = await setup();
  assert.equal((await handleInstallationRequest(req(path, null, {}), env)).status, 401);
  assert.equal((await handleInstallationRequest(req(path, 'invalid', {}), env)).status, 401);
  assert.equal((await handleInstallationRequest(req(path, token, { opaqueVehicleID: 'vehicle', action: 'oops' }), env)).status, 400);
  assert.equal((await handleInstallationRequest(req(path, token, { action: 'start' }), env)).status, 400);
  assert.equal((await handleInstallationRequest(req(path, token, { opaqueVehicleID: 'other', action: 'start' }), env)).status, 409);
  const other = await (await handleInstallationRequest(req('/api/installations/bootstrap', 'ford', {}), env, { fetchImpl: garage })).json();
  assert.equal((await handleInstallationRequest(req(path, other.token, { opaqueVehicleID: 'vehicle', action: 'start' }), env)).status, 409);
  const missing = await handleInstallationRequest(req(path, token, { opaqueVehicleID: 'vehicle', action: 'update' }), env);
  assert.equal(missing.status, 409); assert.equal((await missing.json()).error, 'noActivityToken');
  const missingStart = await handleInstallationRequest(req(path, token, { opaqueVehicleID: 'vehicle', action: 'start' }), env);
  assert.equal((await missingStart.json()).error, 'noPushToStartToken');
  assert.equal((await handleInstallationRequest(req(path, token, undefined, 'GET'), env)).status, 404);
});

test('synthetic actions send only to corresponding APNs token without Ford or authorization-state changes', async () => {
  const { env, token } = await setup();
  await register(env, token, 'pushToStart', 'start-token'); await register(env, token, 'activity', 'activity-token');
  const before = new Map(env.INSTALLATIONS.values); const calls = [];
  for (const action of ['start', 'update', 'end']) {
    const r = await handleInstallationRequest(req(path, token, { opaqueVehicleID: 'vehicle', action }), env,
      { fetchImpl: async (url, options) => { calls.push({ url, options }); return new Response(null, { status: 200 }); } });
    assert.equal(r.status, 200); assert.equal((await r.json()).action, action);
  }
  assert.deepEqual(env.INSTALLATIONS.values, before);
  for (let i = 0; i < calls.length; i++) {
    assert.equal(calls[i].url, `https://api.sandbox.push.apple.com/3/device/${i === 0 ? 'start-token' : 'activity-token'}`);
    const aps = JSON.parse(calls[i].options.body).aps;
    assert.equal(aps.event, ['start', 'update', 'end'][i]); assert.equal(aps['content-state'].units, 'metric');
    assert.equal(aps['content-state'].phase, i === 2 ? 'completed' : 'active');
    if (i === 0) assert.equal(aps['attributes-type'], 'ChargingActivityAttributes');
  }
});

test('APNs rejection and network failures are not reported as success or leak reason', async () => {
  const { env, token } = await setup(); await register(env, token, 'activity', 'activity-token');
  const before = new Map(env.INSTALLATIONS.values);
  for (const code of [400, 410, 500]) {
    const r = await handleInstallationRequest(req(path, token, { opaqueVehicleID: 'vehicle', action: 'update' }), env,
      { fetchImpl: async () => new Response(JSON.stringify({ reason: 'sensitive' }), { status: code }) });
    assert.equal(r.status, 502); const body = await r.text(); assert.ok(!body.includes('sensitive'));
  }
  const r = await handleInstallationRequest(req(path, token, { opaqueVehicleID: 'vehicle', action: 'end' }), env,
    { fetchImpl: async () => { throw new Error('network'); } });
  assert.equal(r.status, 502); assert.deepEqual(env.INSTALLATIONS.values, before);
});
