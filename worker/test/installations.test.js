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

// F02 regression fixtures: bootstrap must prove the bearer to Ford's garage
// endpoint before minting any installation credential. The garage contract
// mirrors the D1 backend (src/index.js): GET with the raw Ford access token as
// a Bearer scheme; 200 + JSON object is the only accepted success shape.
const VALID_GARAGE = JSON.stringify({
  vehicles: [{ vin: '1FTVW1ELXPWG00001', year: 2020, make: 'Ford', model: 'F-150' }]
});

function garageFetch(status = 200, body = VALID_GARAGE, extraHeaders = {}) {
  const calls = [];
  const headers = { 'Content-Type': 'application/json', ...extraHeaders };
  const fetchImpl = async (url, options) => {
    calls.push({ url: String(url), options });
    return new Response(body, { status, headers });
  };
  return { fetchImpl, calls };
}

// Flexible garage stub: full control over status, Content-Type, body and an
// optional (possibly misleading) Content-Length. contentType: null omits the
// header entirely (Node then defaults to text/plain, which is non-JSON).
function garageStub({ status = 200, contentType = 'application/json', body = VALID_GARAGE, contentLength } = {}) {
  const calls = [];
  const headers = {};
  if (contentType !== null) headers['Content-Type'] = contentType;
  if (contentLength !== undefined) headers['Content-Length'] = String(contentLength);
  const fetchImpl = async (url, options) => {
    calls.push({ url: String(url), options });
    return new Response(body, { status, headers });
  };
  return { fetchImpl, calls };
}

// Garage stub that exposes the abort signal passed to fetch and a spy on the
// body's cancel(), so tests can assert a rejected response is deterministically
// released (signal aborted + body cancelled) while a verified success is not.
function observableGarageStub({ status = 200, contentType = 'application/json', body = VALID_GARAGE, contentLength } = {}) {
  const calls = [];
  const observation = { signal: null, cancelCalls: 0 };
  const headers = {};
  if (contentType !== null) headers['Content-Type'] = contentType;
  if (contentLength !== undefined) headers['Content-Length'] = String(contentLength);
  const fetchImpl = (url, options) => {
    calls.push({ url: String(url), options });
    observation.signal = options?.signal;
    const stream = new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode(body));
        controller.close();
      }
    });
    const response = new Response(stream, { status, headers });
    const originalCancel = response.body.cancel.bind(response.body);
    response.body.cancel = (reason) => {
      observation.cancelCalls += 1;
      return originalCancel(reason);
    };
    return Promise.resolve(response);
  };
  return { fetchImpl, calls, observation };
}

// Headers arrive only after delayMs; the abort signal cancels the pending
// response. Exercises the deadline covering the response (headers) phase.
function slowResponseGarageFetch({ delayMs = 50 } = {}) {
  const calls = [];
  const fetchImpl = (url, options) => {
    calls.push({ url: String(url), options });
    const signal = options?.signal;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        resolve(new Response(VALID_GARAGE, { status: 200, headers: { 'Content-Type': 'application/json' } }));
      }, delayMs);
      if (signal) {
        signal.addEventListener('abort', () => {
          clearTimeout(timer);
          reject(new DOMException('The operation was aborted.', 'AbortError'));
        });
      }
    });
  };
  return { fetchImpl, calls };
}

// Headers arrive immediately, but the body is delayed by bodyDelayMs. The
// abort signal errors the body stream mid-read. Exercises the deadline
// covering the body-consumption phase.
function slowBodyGarageFetch({ bodyDelayMs = 50 } = {}) {
  const calls = [];
  const fetchImpl = (url, options) => {
    calls.push({ url: String(url), options });
    const signal = options?.signal;
    const stream = new ReadableStream({
      start(controller) {
        const timer = setTimeout(() => {
          controller.enqueue(new TextEncoder().encode(VALID_GARAGE));
          controller.close();
        }, bodyDelayMs);
        if (signal) {
          signal.addEventListener('abort', () => {
            clearTimeout(timer);
            controller.error(new DOMException('The operation was aborted.', 'AbortError'));
          });
        }
      }
    });
    return Promise.resolve(new Response(stream, { status: 200, headers: { 'Content-Type': 'application/json' } }));
  };
  return { fetchImpl, calls };
}

// A body stream that delivers totalBytes (no Content-Length), so the cap must
// be enforced while consuming the stream.
function oversizedStreamGarageFetch({ chunkSize = 16 * 1024, totalBytes = 64 * 1024 + 100 } = {}) {
  const calls = [];
  const fetchImpl = (url, options) => {
    calls.push({ url: String(url), options });
    const stream = new ReadableStream({
      start(controller) {
        let sent = 0;
        while (sent < totalBytes) {
          const size = Math.min(chunkSize, totalBytes - sent);
          controller.enqueue(new Uint8Array(size).fill(0x78));
          sent += size;
        }
        controller.close();
      }
    });
    return Promise.resolve(new Response(stream, { status: 200, headers: { 'Content-Type': 'application/json' } }));
  };
  return { fetchImpl, calls };
}

function bootstrapRequest(fordToken) {
  return request('/api/installations/bootstrap', {
    headers: fordToken === undefined ? {} : { Authorization: 'Bearer ' + fordToken },
    body: {}
  });
}

async function bootstrap(targetEnv = env(), fordToken = 'ford-access-token') {
  const { fetchImpl } = garageFetch();
  const response = await handleInstallationRequest(bootstrapRequest(fordToken), targetEnv, { fetchImpl });
  assert.equal(response.status, 200);
  return { data: await response.json(), fordToken };
}

function installationRequest(path, token, options = {}) {
  return request(path, {
    ...options,
    headers: { Authorization: 'Bearer ' + token, ...options.headers }
  });
}

async function sha256(value) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('');
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
      vin: '1FTVW1ELXPWG00001',
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

test('Ford authorization validates and encrypts the selected VIN', async () => {
  const targetEnv = env();
  const { data } = await bootstrap(targetEnv);
  const vin = '1FTVW1ELXPWG00001';
  const response = await handleInstallationRequest(installationRequest('/api/ford/authorize', data.token, {
    body: {
      opaqueVehicleID: 'opaque-vehicle',
      vin,
      refreshToken: 'ford-refresh-secret',
      redirectURI: 'https://cellblock.cc/'
    }
  }), targetEnv);
  assert.equal(response.status, 200);
  for (const value of targetEnv.INSTALLATIONS.values.values()) {
    assert.ok(!String(value).includes(vin));
  }
  const invalid = await handleInstallationRequest(installationRequest('/api/ford/authorize', data.token, {
    body: {
      opaqueVehicleID: 'opaque-vehicle',
      vin: '1ftvw1elxpwg00001',
      refreshToken: 'ford-refresh-secret',
      redirectURI: 'https://cellblock.cc/'
    }
  }), targetEnv);
  assert.equal(invalid.status, 400);
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

// F02 — bootstrap must verify the bearer with Ford before minting credentials.
// Every failure path below must return before random ID/token generation and
// leave the KV namespace untouched.

test('bootstrap rejects a bearer Ford rejects (401) and writes nothing', async () => {
  const targetEnv = env();
  const { fetchImpl, calls } = garageFetch(401, JSON.stringify({ error: 'invalid_token' }));
  const response = await handleInstallationRequest(
    bootstrapRequest('invalid-ford-token'), targetEnv, { fetchImpl });
  assert.equal(response.status, 401);
  assert.deepEqual(await response.json(), { error: 'Ford authorization required' });
  assert.equal(targetEnv.INSTALLATIONS.values.size, 0);
  assert.equal(calls.length, 1);
});

test('bootstrap rejects a bearer Ford rejects (403) and writes nothing', async () => {
  const targetEnv = env();
  const { fetchImpl } = garageFetch(403, JSON.stringify({ error: 'access_denied' }));
  const response = await handleInstallationRequest(
    bootstrapRequest('forbidden-ford-token'), targetEnv, { fetchImpl });
  assert.equal(response.status, 401);
  assert.deepEqual(await response.json(), { error: 'Ford authorization required' });
  assert.equal(targetEnv.INSTALLATIONS.values.size, 0);
});

test('bootstrap fails closed when the garage endpoint returns 5xx and writes nothing', async () => {
  const targetEnv = env();
  const { fetchImpl } = garageFetch(500, 'upstream exploded');
  const response = await handleInstallationRequest(
    bootstrapRequest('ford-access-token'), targetEnv, { fetchImpl });
  assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), { error: 'Authorization service unavailable' });
  assert.equal(targetEnv.INSTALLATIONS.values.size, 0);
});

test('bootstrap preserves Ford rate limits and Retry-After while failing closed', async () => {
  const targetEnv = env();
  const { fetchImpl } = garageFetch(429, '', { 'Retry-After': '60' });
  const response = await handleInstallationRequest(
    bootstrapRequest('ford-access-token'), targetEnv, { fetchImpl });
  assert.equal(response.status, 429);
  assert.equal(response.headers.get('Retry-After'), '60');
  assert.deepEqual(await response.json(), { error: 'Authorization service unavailable' });
  assert.equal(targetEnv.INSTALLATIONS.values.size, 0);
});

test('bootstrap fails closed when the garage endpoint is unreachable and writes nothing', async () => {
  const targetEnv = env();
  const calls = [];
  const fetchImpl = async (url) => {
    calls.push(String(url));
    throw new Error('network unreachable');
  };
  const response = await handleInstallationRequest(
    bootstrapRequest('ford-access-token'), targetEnv, { fetchImpl });
  assert.equal(response.status, 503);
  assert.equal(targetEnv.INSTALLATIONS.values.size, 0);
  assert.equal(calls.length, 1);
});

test('bootstrap fails closed on a malformed garage response and writes nothing', async () => {
  const malformed = [
    'not-json-at-all',
    JSON.stringify(null),
    JSON.stringify(['1FTVW1ELXPWG00001']),
    JSON.stringify('garage')
  ];
  for (const body of malformed) {
    const targetEnv = env();
    const { fetchImpl } = garageFetch(200, body);
    const response = await handleInstallationRequest(
      bootstrapRequest('ford-access-token'), targetEnv, { fetchImpl });
    assert.equal(response.status, 503, `body: ${body}`);
    assert.deepEqual(await response.json(), { error: 'Invalid authorization response' });
    assert.equal(targetEnv.INSTALLATIONS.values.size, 0, `body: ${body}`);
  }
});

test('bootstrap mints installation state only after verified Ford authorization', async () => {
  const targetEnv = env();
  const fordToken = 'verified-ford-access-token';
  const { fetchImpl, calls } = garageFetch();
  const response = await handleInstallationRequest(
    bootstrapRequest(fordToken), targetEnv, { fetchImpl });
  assert.equal(response.status, 200);
  const { installationID, token } = await response.json();
  assert.equal(typeof installationID, 'string');
  assert.equal(typeof token, 'string');

  // Exactly the two intended entries: the installation record and the
  // credential index. Nothing else may be written.
  assert.equal(targetEnv.INSTALLATIONS.values.size, 2);
  const record = JSON.parse(targetEnv.INSTALLATIONS.values.get(installationID));
  const tokenHash = await sha256(token);
  assert.equal(record.tokenHash, tokenHash);
  assert.equal(record.subjectHash, await sha256(fordToken));
  assert.equal(targetEnv.INSTALLATIONS.values.get('credential:' + tokenHash), installationID);
  assert.equal(calls.length, 1);
});

for (const garage of [
  { vin: '1FTVW1ELXPWG00001' },
  [{ vin: '1FTVW1ELXPWG00001' }],
  { data: [{ vin: '1FTVW1ELXPWG00001' }] }
]) {
  test(`bootstrap accepts Ford garage shape ${JSON.stringify(garage).replace('1FTVW1ELXPWG00001', '<VIN>')}`, async () => {
    const targetEnv = env();
    const { fetchImpl } = garageFetch(200, JSON.stringify(garage));
    const response = await handleInstallationRequest(
      bootstrapRequest('verified-ford-access-token'), targetEnv, { fetchImpl });
    assert.equal(response.status, 200);
    assert.equal(targetEnv.INSTALLATIONS.values.size, 2);
  });
}

test('bootstrap sends the raw Ford bearer to the garage endpoint with the Bearer scheme', async () => {
  const targetEnv = env();
  const fordToken = 'contract-check-token';
  const { fetchImpl, calls } = garageFetch();
  await handleInstallationRequest(bootstrapRequest(fordToken), targetEnv, { fetchImpl });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, 'https://api.vehicle.ford.com/fcon-query/v1/garage');
  const headers = new Headers(calls[0].options?.headers || {});
  assert.equal(headers.get('authorization'), 'Bearer ' + fordToken);
  assert.equal(headers.get('accept'), 'application/json');
});

test('bootstrap without a bearer never contacts Ford and writes nothing', async () => {
  const targetEnv = env();
  const { fetchImpl, calls } = garageFetch();
  const response = await handleInstallationRequest(
    bootstrapRequest(undefined), targetEnv, { fetchImpl });
  assert.equal(response.status, 401);
  assert.deepEqual(await response.json(), { error: 'Ford authorization is required' });
  assert.equal(targetEnv.INSTALLATIONS.values.size, 0);
  assert.equal(calls.length, 0);
});

// F02 code-quality remediation: never follow redirects, bound the upstream deadline
// and body, and enforce the exact 200 + JSON contract. Redirects indicate that
// Ford requires reauthentication; every other non-200 fails closed.

test('bootstrap maps Ford redirects to authentication required without following them', async () => {
  const targetEnv = env();
  const { fetchImpl, calls } = garageStub({ status: 302, contentType: 'application/json', body: VALID_GARAGE });
  const response = await handleInstallationRequest(
    bootstrapRequest('ford-access-token'), targetEnv, { fetchImpl });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].options?.redirect, 'manual');
  assert.equal(response.status, 401);
  assert.deepEqual(await response.json(), { error: 'Ford authorization required' });
  assert.equal(targetEnv.INSTALLATIONS.values.size, 0);
});

test('bootstrap fails closed when the garage request itself fails and writes nothing', async () => {
  const targetEnv = env();
  const calls = [];
  const fetchImpl = async (url, options) => {
    calls.push({ url: String(url), options });
    assert.equal(options?.redirect, 'manual');
    throw new TypeError('simulated upstream network failure');
  };
  const response = await handleInstallationRequest(
    bootstrapRequest('ford-access-token'), targetEnv, { fetchImpl });
  assert.equal(response.status, 503);
  assert.equal(targetEnv.INSTALLATIONS.values.size, 0);
  assert.equal(calls.length, 1);
});

test('bootstrap fails closed when the garage response exceeds the deadline (headers) and writes nothing', async () => {
  const targetEnv = env();
  const { fetchImpl } = slowResponseGarageFetch({ delayMs: 50 });
  const response = await handleInstallationRequest(
    bootstrapRequest('ford-access-token'), targetEnv, { fetchImpl, fordTimeoutMs: 10 });
  assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), { error: 'Authorization service unavailable' });
  assert.equal(targetEnv.INSTALLATIONS.values.size, 0);
});

test('bootstrap fails closed when the garage body exceeds the deadline and writes nothing', async () => {
  const targetEnv = env();
  const { fetchImpl } = slowBodyGarageFetch({ bodyDelayMs: 50 });
  const response = await handleInstallationRequest(
    bootstrapRequest('ford-access-token'), targetEnv, { fetchImpl, fordTimeoutMs: 10 });
  assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), { error: 'Authorization service unavailable' });
  assert.equal(targetEnv.INSTALLATIONS.values.size, 0);
});

test('bootstrap clears the upstream deadline timer after a fast success', async () => {
  const targetEnv = env();
  const { fetchImpl, calls } = garageFetch();
  const response = await handleInstallationRequest(
    bootstrapRequest('ford-access-token'), targetEnv, { fetchImpl, fordTimeoutMs: 20 });
  assert.equal(response.status, 200);
  const signal = calls[0].options?.signal;
  assert.ok(signal instanceof AbortSignal, 'fetch must be given an abort signal');
  // Wait past the deadline. If the timer were not cleared, the signal would
  // have been aborted by now.
  await new Promise(resolve => setTimeout(resolve, 40));
  assert.equal(signal.aborted, false);
});

test('bootstrap fails closed when the garage body exceeds 64 KiB (stream, no Content-Length) and writes nothing', async () => {
  const targetEnv = env();
  const { fetchImpl } = oversizedStreamGarageFetch();
  const response = await handleInstallationRequest(
    bootstrapRequest('ford-access-token'), targetEnv, { fetchImpl });
  assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), { error: 'Authorization service unavailable' });
  assert.equal(targetEnv.INSTALLATIONS.values.size, 0);
});

test('bootstrap fails closed on a misleading Content-Length with an oversized body and writes nothing', async () => {
  const targetEnv = env();
  // Claim a tiny Content-Length but actually stream a body over the cap; the
  // cap must still be enforced while consuming the stream.
  const calls = [];
  const stream = new ReadableStream({
    start(controller) {
      let sent = 0;
      const total = 64 * 1024 + 100;
      while (sent < total) {
        const size = Math.min(16 * 1024, total - sent);
        controller.enqueue(new Uint8Array(size).fill(0x78));
        sent += size;
      }
      controller.close();
    }
  });
  const fetchImpl = async (url, options) => {
    calls.push({ url: String(url), options });
    return new Response(stream, {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Content-Length': '10' }
    });
  };
  const response = await handleInstallationRequest(
    bootstrapRequest('ford-access-token'), targetEnv, { fetchImpl });
  assert.equal(response.status, 503);
  assert.equal(targetEnv.INSTALLATIONS.values.size, 0);
  assert.equal(calls.length, 1);
});

test('bootstrap fails closed when Content-Length exceeds 64 KiB and writes nothing', async () => {
  const targetEnv = env();
  // Content-Length claims a body over the cap, but the actual body is small.
  // Only the Content-Length fast-reject path yields a 503 here: if the cap
  // were enforced solely while reading the stream, the small body would pass
  // the limit and the request would succeed (200).
  const stream = new ReadableStream({
    pull(controller) {
      controller.enqueue(new TextEncoder().encode(VALID_GARAGE));
      controller.close();
    }
  });
  const fetchImpl = async () => new Response(stream, {
    status: 200,
    headers: { 'Content-Type': 'application/json', 'Content-Length': String(64 * 1024 + 100) }
  });
  const response = await handleInstallationRequest(
    bootstrapRequest('ford-access-token'), targetEnv, { fetchImpl });
  assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), { error: 'Authorization service unavailable' });
  assert.equal(targetEnv.INSTALLATIONS.values.size, 0);
});

test('bootstrap rejects a 202 garage response and writes nothing', async () => {
  const targetEnv = env();
  const { fetchImpl } = garageStub({ status: 202, contentType: 'application/json', body: VALID_GARAGE });
  const response = await handleInstallationRequest(
    bootstrapRequest('ford-access-token'), targetEnv, { fetchImpl });
  assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), { error: 'Authorization service unavailable' });
  assert.equal(targetEnv.INSTALLATIONS.values.size, 0);
});

test('bootstrap rejects a non-JSON media type and writes nothing', async () => {
  const targetEnv = env();
  const { fetchImpl } = garageStub({ status: 200, contentType: 'text/html', body: VALID_GARAGE });
  const response = await handleInstallationRequest(
    bootstrapRequest('ford-access-token'), targetEnv, { fetchImpl });
  assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), { error: 'Authorization service unavailable' });
  assert.equal(targetEnv.INSTALLATIONS.values.size, 0);
});

test('bootstrap rejects a response with no JSON Content-Type and writes nothing', async () => {
  const targetEnv = env();
  // No explicit Content-Type: Node defaults to text/plain, which is non-JSON.
  const { fetchImpl } = garageStub({ status: 200, contentType: null, body: VALID_GARAGE });
  const response = await handleInstallationRequest(
    bootstrapRequest('ford-access-token'), targetEnv, { fetchImpl });
  assert.equal(response.status, 503);
  assert.equal(targetEnv.INSTALLATIONS.values.size, 0);
});

test('bootstrap accepts a structured +json media type and mints credentials', async () => {
  const targetEnv = env();
  const { fetchImpl } = garageStub({ status: 200, contentType: 'application/vnd.ford.garage+json', body: VALID_GARAGE });
  const response = await handleInstallationRequest(
    bootstrapRequest('ford-access-token'), targetEnv, { fetchImpl });
  assert.equal(response.status, 200);
  const { installationID, token } = await response.json();
  assert.equal(typeof installationID, 'string');
  assert.equal(typeof token, 'string');
  assert.equal(targetEnv.INSTALLATIONS.values.size, 2);
});

// F02 re-review: the JSON media type must be a syntactically valid
// type/subtype (optionally +json). A bare string that merely ends in +json is
// malformed and must fail closed (503) with zero KV writes.
test('bootstrap rejects malformed JSON media types and writes nothing', async () => {
  const malformed = [
    'not-a-media-type+json',
    'application/+json',
    'application/json+',
    '/json',
    'application/',
    'application/ json',
    'application/json/extra'
  ];
  for (const contentType of malformed) {
    const targetEnv = env();
    const { fetchImpl } = garageStub({ status: 200, contentType, body: VALID_GARAGE });
    const response = await handleInstallationRequest(
      bootstrapRequest('ford-access-token'), targetEnv, { fetchImpl });
    assert.equal(response.status, 503, `content-type: ${contentType}`);
    assert.deepEqual(await response.json(), { error: 'Authorization service unavailable' }, `content-type: ${contentType}`);
    assert.equal(targetEnv.INSTALLATIONS.values.size, 0, `content-type: ${contentType}`);
  }
});

// F02 re-review: every early rejection must deterministically release the
// upstream response — abort the fetch signal and cancel the unconsumed body —
// so the connection is returned to the pool. A verified success must not.
test('bootstrap aborts the signal and cancels the body on a non-200 status', async () => {
  const targetEnv = env();
  const { fetchImpl, observation } = observableGarageStub({ status: 500, contentType: 'application/json', body: VALID_GARAGE });
  const response = await handleInstallationRequest(
    bootstrapRequest('ford-access-token'), targetEnv, { fetchImpl });
  assert.equal(response.status, 503);
  assert.equal(targetEnv.INSTALLATIONS.values.size, 0);
  assert.ok(observation.signal instanceof AbortSignal, 'fetch must be given an abort signal');
  assert.equal(observation.signal.aborted, true, 'signal must be aborted on rejection');
  assert.ok(observation.cancelCalls >= 1, 'body cancel() must be called on rejection');
});

test('bootstrap aborts the signal and cancels the body when Ford rejects the bearer (401)', async () => {
  const targetEnv = env();
  const { fetchImpl, observation } = observableGarageStub({ status: 401, contentType: 'application/json', body: JSON.stringify({ error: 'invalid_token' }) });
  const response = await handleInstallationRequest(
    bootstrapRequest('invalid-ford-token'), targetEnv, { fetchImpl });
  assert.equal(response.status, 401);
  assert.deepEqual(await response.json(), { error: 'Ford authorization required' });
  assert.equal(targetEnv.INSTALLATIONS.values.size, 0);
  assert.equal(observation.signal.aborted, true, 'signal must be aborted on rejection');
  assert.ok(observation.cancelCalls >= 1, 'body cancel() must be called on rejection');
});

test('bootstrap aborts the signal and cancels the body on a non-JSON media type', async () => {
  const targetEnv = env();
  const { fetchImpl, observation } = observableGarageStub({ status: 200, contentType: 'text/html', body: VALID_GARAGE });
  const response = await handleInstallationRequest(
    bootstrapRequest('ford-access-token'), targetEnv, { fetchImpl });
  assert.equal(response.status, 503);
  assert.equal(targetEnv.INSTALLATIONS.values.size, 0);
  assert.equal(observation.signal.aborted, true, 'signal must be aborted on rejection');
  assert.ok(observation.cancelCalls >= 1, 'body cancel() must be called on rejection');
});

test('bootstrap aborts the signal and cancels the body when Content-Length exceeds 64 KiB', async () => {
  const targetEnv = env();
  const { fetchImpl, observation } = observableGarageStub({ status: 200, contentType: 'application/json', body: VALID_GARAGE, contentLength: 64 * 1024 + 100 });
  const response = await handleInstallationRequest(
    bootstrapRequest('ford-access-token'), targetEnv, { fetchImpl });
  assert.equal(response.status, 503);
  assert.equal(targetEnv.INSTALLATIONS.values.size, 0);
  assert.equal(observation.signal.aborted, true, 'signal must be aborted on rejection');
  assert.ok(observation.cancelCalls >= 1, 'body cancel() must be called on rejection');
});

test('bootstrap does not abort the signal or cancel the body on a verified success', async () => {
  const targetEnv = env();
  const { fetchImpl, observation } = observableGarageStub({ status: 200, contentType: 'application/json', body: VALID_GARAGE });
  const response = await handleInstallationRequest(
    bootstrapRequest('ford-access-token'), targetEnv, { fetchImpl });
  assert.equal(response.status, 200);
  assert.equal(targetEnv.INSTALLATIONS.values.size, 2);
  assert.equal(observation.signal.aborted, false, 'signal must not be aborted on success');
  assert.equal(observation.cancelCalls, 0, 'body must not be cancelled on success');
});
