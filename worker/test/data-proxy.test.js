import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, webcrypto } from 'node:crypto';
import { registerHooks } from 'node:module';

if (!globalThis.crypto) globalThis.crypto = webcrypto;
// Exercise the real Worker entrypoint and DO methods with only the runtime
// base class replaced. No production source transformations or network calls.
const hooks = registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === 'cloudflare:workers') return {
      url: 'data:text/javascript,export class DurableObject {}', shortCircuit: true
    };
    return nextResolve(specifier, context);
  }
});
const { default: worker, FordRateLimiter } = await import('../index.js');
hooks.deregister();

const VIN = '1FTVW1ELXPWG00001';
const OTHER_VIN = '1FTVW1ELXPWG00002';
const TOKEN = 'dummy.owner.token';
const hash = value => createHash('sha256').update(value).digest('hex');
const vehicleKey = hash(`vehicle:${VIN}`);
const membershipKey = (token = TOKEN, vin = VIN) => hash(`vin-authorization:${JSON.stringify([token, vin])}`);

function fixture(t, { garageStatus = 200, garageBody = { vehicles: [{ vin: VIN }] }, garageRetryAfter, telemetryStatus = 200, telemetryRetryAfter, telemetryRedirect = false, telemetryNetworkError = false, networkError = false } = {}) {
  let now = 1_800_000_000_000;
  t.mock.method(Date, 'now', () => now);
  const objects = new Map();
  const lookups = [];
  const calls = [];
  const env = {
    CLIENT_ID: 'dummy-client', ALLOWED_ORIGIN: 'https://cellblock.cc',
    // Installation routes still receive their normal KV binding; this gate
    // deliberately never writes membership proofs to eventually consistent KV.
    INSTALLATIONS: {
      async get() { throw new Error('unexpected installation KV access'); },
      async put() { throw new Error('unexpected installation KV access'); }
    },
    FORD_RATE_LIMITER: {
      idFromName(key) { lookups.push(key); return key; },
      get(key) {
        if (!objects.has(key)) {
          const values = new Map();
          const operations = [];
          const kv = {
            get(k) { operations.push(['get', k]); return values.get(k); },
            put(k, v) { operations.push(['put', k, v]); values.set(k, v); },
            delete(k) { operations.push(['delete', k]); values.delete(k); }
          };
          objects.set(key, { object: new FordRateLimiter({ storage: { kv } }, env), values, operations });
        }
        return objects.get(key).object;
      }
    }
  };
  const state = { garageStatus, garageBody, garageRetryAfter, telemetryStatus, telemetryRetryAfter, telemetryRedirect, telemetryNetworkError, networkError };
  t.mock.method(globalThis, 'fetch', async (url, options) => {
    calls.push({ url: String(url), options });
    if (String(url).endsWith('/garage')) {
      if (state.networkError) throw new Error('dummy network failure');
      const headers = { 'Content-Type': 'application/json' };
      if (state.garageRetryAfter) headers['Retry-After'] = state.garageRetryAfter;
      return new Response(typeof state.garageBody === 'string' ? state.garageBody : JSON.stringify(state.garageBody), {
        status: state.garageStatus, headers
      });
    }
    if (state.telemetryRedirect) {
      return new Response(null, { status: 302, headers: { Location: 'https://login.ford.example/' } });
    }
    if (state.telemetryNetworkError) throw new Error('dummy telemetry upstream network failure');
    const headers = { 'Content-Type': 'application/json' };
    if (state.telemetryRetryAfter) headers['Retry-After'] = state.telemetryRetryAfter;
    return new Response('{}', { status: state.telemetryStatus, headers });
  });
  const send = ({ auth = `Bearer ${TOKEN}`, query = `vin=${VIN}`, path = 'vehicle', ip = '192.0.2.1', forwarded } = {}) => {
    const headers = { Origin: 'https://cellblock.cc' };
    if (auth !== null) headers.Authorization = auth;
    if (ip !== null) headers['CF-Connecting-IP'] = ip;
    if (forwarded) headers['X-Forwarded-For'] = forwarded;
    return worker.fetch(new Request(`https://cellblock.cc/api/data/${path}${query ? '?' + query : ''}`, { headers }), env);
  };
  return {
    env, state, objects, lookups, calls, send,
    advance(ms = 30_001) { now += ms; },
    garageCalls() { return calls.filter(call => call.url.endsWith('/garage')); },
    telemetryCalls() { return calls.filter(call => !call.url.endsWith('/garage')); },
    untouched() {
      assert.equal(lookups.includes(vehicleKey), false, 'must not even look up shared VIN bucket');
      assert.equal(this.telemetryCalls().length, 0);
      assert.equal(objects.get(membershipKey())?.values.has('authorizedUntil') || false, false);
    }
  };
}

for (const auth of [null, 'garbage', 'Basic dummy', 'Bearer', 'Bearer dummy token', 'Bearer  dummy', 'Bearer dummy,other', `Bearer ${'x'.repeat(8193)}`]) {
  test(`malformed bearer rejected locally (${String(auth).slice(0, 30)})`, async t => {
    const f = fixture(t);
    assert.equal((await f.send({ auth })).status, 401);
    assert.equal(f.lookups.length, 0);
    assert.equal(f.calls.length, 0);
  });
}

for (const query of ['vin=', 'vin=short', `vin=${VIN.toLowerCase()}`, 'vin=1FTVW1ELXPWG0000I', `vin=${VIN}&vin=${OTHER_VIN}`]) {
  test(`invalid or ambiguous VIN rejected: ${query}`, async t => {
    const f = fixture(t);
    assert.equal((await f.send({ query })).status, 400);
    assert.equal(f.lookups.length, 0);
    assert.equal(f.calls.length, 0);
  });
}

for (const [garageStatus, expected] of [[401, 401], [403, 401], [429, 429], [500, 503], [503, 503], [302, 401], [202, 503]]) {
  test(`Ford garage ${garageStatus} fails closed`, async t => {
    const f = fixture(t, { garageStatus });
    const response = await f.send();
    assert.equal(response.status, expected);
    assert.equal(response.headers.get('Access-Control-Allow-Origin'), 'https://cellblock.cc');
    assert.equal(f.garageCalls().length, 1);
    assert.equal(f.garageCalls()[0].options.redirect, 'manual');
    f.untouched();
  });
}

for (const status of [429, 503]) {
  test(`Ford garage ${status} preserves Retry-After before telemetry`, async t => {
    const f = fixture(t, { garageStatus: status, garageRetryAfter: '60' });
    const response = await f.send();
    assert.equal(response.status, status);
    assert.equal(response.headers.get('Retry-After'), '60');
    assert.deepEqual(await response.json(), { error: 'Authorization service unavailable' });
    assert.equal(f.telemetryCalls().length, 0);
    f.untouched();
  });
}

for (const garageBody of ['{broken', null, [], {}, { vehicles: {} }, { vehicles: [null] }, { vehicles: [{ vin: 1 }] }]) {
  test(`malformed garage fails closed: ${JSON.stringify(garageBody)}`, async t => {
    const f = fixture(t, { garageBody });
    assert.equal((await f.send()).status, 503);
    f.untouched();
  });
}

test('network failure and unavailable authorization storage fail closed', async t => {
  const f = fixture(t, { networkError: true });
  assert.equal((await f.send()).status, 503);
  f.untouched();
  f.env.FORD_RATE_LIMITER.get = () => { throw new Error('storage unavailable'); };
  assert.equal((await f.send()).status, 503);
  f.untouched();
});

for (const vehicles of [[], [{ vin: OTHER_VIN }]]) {
  test(`verified bearer without exact VIN membership returns 403: ${JSON.stringify(vehicles)}`, async t => {
    const f = fixture(t, { garageBody: { vehicles } });
    assert.equal((await f.send()).status, 403);
    f.untouched();
  });
}

test('owner is verified before shared VIN access; cache is hashed, positive-only and expires', async t => {
  const f = fixture(t);
  assert.equal((await f.send()).status, 200);
  assert.equal(f.calls[0].url.endsWith('/garage'), true);
  assert.equal(f.calls[1].url.includes(`vin=${VIN}`), true);
  assert.equal(f.calls[1].options.headers.Authorization, `Bearer ${TOKEN}`);
  assert.equal(f.calls[1].options.redirect, 'manual');
  assert.ok(f.lookups.indexOf(membershipKey()) < f.lookups.indexOf(vehicleKey));
  assert.equal(f.objects.get(vehicleKey).values.has('nextAllowedAt'), true);
  assert.equal((await f.send()).status, 429);
  f.advance();
  assert.equal((await f.send()).status, 200);
  assert.equal(f.garageCalls().length, 1, 'positive cache avoids garage on repeated request');
  assert.equal(f.telemetryCalls().length, 2);
  const persisted = JSON.stringify([...f.objects].map(([key, value]) => [key, [...value.values]]));
  assert.equal(persisted.includes(TOKEN), false);
  assert.equal(persisted.includes(VIN), false);
  assert.ok(f.lookups.every(key => /^[a-f0-9]{64}$/.test(key)));
  f.advance(5 * 60_000);
  f.state.garageStatus = 401;
  const previousLookups = f.lookups.filter(key => key === vehicleKey).length;
  assert.equal((await f.send()).status, 401);
  assert.equal(f.garageCalls().length, 2);
  assert.equal(f.lookups.filter(key => key === vehicleKey).length, previousLookups);
});

test('Ford auth redirect is returned as 401 without forwarding its destination', async t => {
  const f = fixture(t, { telemetryRedirect: true });
  const response = await f.send();

  assert.equal(response.status, 401);
  assert.deepEqual(await response.json(), {
    error: 'Ford authorization required',
    code: 'ford_auth_redirect'
  });
  assert.equal(response.headers.get('Location'), null);
  assert.equal(f.calls.at(-1).options.redirect, 'manual');
  assert.equal(f.objects.get(membershipKey()).values.has('authorizedUntil'), false);
  assert.equal(f.telemetryCalls().length, 1);
});

test('upstream gateway response and Retry-After are passed through for client backoff', async t => {
  const f = fixture(t, { telemetryStatus: 502, telemetryRetryAfter: '45' });
  const response = await f.send();

  assert.equal(response.status, 502);
  assert.equal(response.headers.get('Retry-After'), '45');
  assert.equal(await response.text(), '{}');
  assert.equal(f.calls.at(-1).options.redirect, 'manual');
});

test('telemetry transport exception becomes a generic proxy 502 without leaking details', async t => {
  const f = fixture(t, { telemetryNetworkError: true });
  const response = await f.send();

  assert.equal(response.status, 502);
  assert.deepEqual(await response.json(), { error: 'Proxy request failed' });
  assert.equal(f.calls.at(-1).options.redirect, 'manual');
});

test('different verified owner tokens share the original VIN bucket', async t => {
  const f = fixture(t);
  assert.equal((await f.send()).status, 200);
  assert.equal((await f.send({ auth: 'Bearer dummy.second.owner', ip: '192.0.2.2' })).status, 429);
  assert.equal(f.garageCalls().length, 2);
  assert.equal(f.telemetryCalls().length, 1);
  assert.equal(f.lookups.filter(key => key === vehicleKey).length, 2);
});

for (const ip of ['192.0.2.1', null]) {
  test(`validation budget is independent and cannot be rotated by token/VIN/XFF (${ip})`, async t => {
    const f = fixture(t, { garageStatus: 401 });
    assert.equal((await f.send({ ip })).status, 401);
    const response = await f.send({ ip, auth: 'Bearer dummy.rotated', query: `vin=${OTHER_VIN}`, forwarded: '192.0.2.99' });
    assert.equal(response.status, 429);
    assert.equal(response.headers.get('Retry-After'), '30');
    assert.equal(f.garageCalls().length, 1);
    f.untouched();
    assert.equal(f.lookups.includes(hash(`vehicle:${OTHER_VIN}`)), false);
    // Failed credentials did not consume the legitimate owner's VIN budget.
    f.state.garageStatus = 200;
    assert.equal((await f.send({ ip: '192.0.2.3' })).status, 200);
  });
}

for (const telemetryStatus of [401, 403]) {
  test(`telemetry ${telemetryStatus} evicts proof before the next request`, async t => {
    const f = fixture(t, { telemetryStatus });
    assert.equal((await f.send()).status, telemetryStatus);
    assert.equal(f.objects.get(membershipKey()).values.has('authorizedUntil'), false);
    f.advance();
    f.state.garageStatus = 401;
    const count = f.lookups.filter(key => key === vehicleKey).length;
    assert.equal((await f.send()).status, 401);
    assert.equal(f.garageCalls().length, 2);
    assert.equal(f.telemetryCalls().length, 1);
    assert.equal(f.lookups.filter(key => key === vehicleKey).length, count);
  });
}

test('non-VIN routes retain per-token limiter and image bypasses authorization', async t => {
  const f = fixture(t);
  assert.equal((await f.send({ path: 'garage', query: '' })).status, 200);
  assert.deepEqual(f.lookups, [hash(`token:Bearer ${TOKEN}`)]);
  assert.equal((await f.send({ path: 'garage', query: '' })).status, 429);
  const lookupCount = f.lookups.length;
  assert.equal((await f.send({ path: 'vehicle-image', auth: null })).status, 200);
  assert.equal(f.lookups.length, lookupCount);
  assert.ok(f.calls.at(-1).url.startsWith('https://build.ford.com/'));
});
