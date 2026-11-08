import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { Miniflare } from 'miniflare';
import { encryptValue } from '../monitoring.js';

const encryptionKey = Buffer.alloc(32, 7).toString('base64');
const pem = generateKeyPairSync('ec', { namedCurve: 'prime256v1', privateKeyEncoding: { type: 'pkcs8', format: 'pem' }, publicKeyEncoding: { type: 'spki', format: 'pem' } }).privateKey;
const hash = s => createHash('sha256').update(s).digest('hex');
const key = id => `ford-authorization:${id}`;
const enrollmentKey = id => `live-activity:${id}:vehicle`;
const tokenKey = id => `live-activity-token:${id}:vehicle:${hash('pushToStart')}`;

test('real workerd SQLite limiter serializes simultaneous reservations', async t => {
  const mf = new Miniflare({
    modules: true, modulesRoot: '.', modulesRules: [{ type: 'ESModule', include: ['**/*.js'] }],
    scriptPath: 'test/runtime-harness.js', compatibilityDate: '2025-04-01',
    durableObjects: { LIMITER: { className: 'FordRateLimiter', useSQLite: true } }
  });
  t.after(() => mf.dispose());
  const ns = await mf.getDurableObjectNamespace('LIMITER');
  const stub = ns.get(ns.idFromName('synthetic:token:example:start'));
  const results = await Promise.all(Array.from({ length: 20 }, () => stub.allow()));
  assert.equal(results.filter(result => result.allowed).length, 1);
  assert.ok(results.filter(result => !result.allowed).every(result => result.retryAfterMs > 0));
  const separate = ns.get(ns.idFromName('synthetic:token:example:end'));
  assert.equal((await separate.allow()).allowed, true);
});

test('real workerd coordinator: stale index, opt-out, concurrency and retry', async t => {
  let sends = 0, failures = 0, gate, entered;
  const mf = new Miniflare({
    modules: true, modulesRoot: '.', modulesRules: [{ type: 'ESModule', include: ['**/*.js'] }], scriptPath: 'test/runtime-harness.js', compatibilityDate: '2025-04-01',
    durableObjects: { COORD: { className: 'TestCoordinator', useSQLite: true } },
    kvNamespaces: ['INSTALLATIONS'],
    bindings: { INSTALLATION_ENCRYPTION_KEY: encryptionKey, CLIENT_ID: 'client', CLIENT_SECRET: 'secret', APNS_PRIVATE_KEY_P8: pem, APNS_TEAM_ID: 'team', APNS_KEY_ID: 'key', APNS_TOPIC: 'app' },
    outboundService: async request => {
      const url = request.url;
      if (url.includes('/oauth2/')) return Response.json({ access_token: 'access' });
      if (url.includes('/telemetry')) return Response.json({ metrics: { xevBatteryChargeDisplayStatus: { value: 'CHARGING' }, xevBatteryChargerVoltageOutput: { value: 240 }, xevBatteryChargerCurrentOutput: { value: 30 } } });
      if (url.includes('push.apple.com')) {
        sends++;
        if (entered) { entered(); entered = null; await gate; }
        if (failures-- > 0) return new Response('{}', { status: 503 });
        return new Response('{}');
      }
      throw Error(`unexpected outbound ${url}`);
    }
  });
  t.after(() => mf.dispose());
  const kv = await mf.getKVNamespace('INSTALLATIONS');
  const ns = await mf.getDurableObjectNamespace('COORD');
  const stub = ns.get(ns.idFromName('vehicle'));
  const record = { status: 'authorized', opaqueVehicleIDHash: 'vehicle', refreshTokenCiphertext: await encryptValue('refresh', encryptionKey), vinCiphertext: await encryptValue('1FTVW1ELXPWG00001', encryptionKey) };
  for (const id of ['a', 'b']) {
    await kv.put(key(id), JSON.stringify(record));
    await kv.put(enrollmentKey(id), JSON.stringify({ enrollmentID: id, apnsEnvironment: 'sandbox', chargingMode: 'both' }));
    await kv.put(tokenKey(id), JSON.stringify({ tokenCiphertext: await encryptValue('push-token', encryptionKey), apnsEnvironment: 'sandbox' }));
  }
  // A successful start chooses a. When it disappears from the index, the
  // object must read it directly and not issue a duplicate start to b.
  await stub.run([key('a')], 1_000_000);
  assert.equal(sends, 1);
  await stub.run([key('b')], 1_060_000);
  assert.equal(sends, 1);
  assert.equal((await stub.owner()).key, key('a'));

  const savedA = await kv.get(key('a'));
  await kv.delete(key('a'));
  assert.equal((await stub.run([key('b')], 1_070_000)).skipped, true);
  await kv.put(key('a'), savedA);
  await stub.run([key('b')], 1_080_000);
  assert.equal((await stub.owner()).unavailableSince, undefined);
  assert.equal(sends, 1);

  // A removal is indistinguishable from a transient missing KV read: wait the
  // full grace period, including across requests, then transfer ownership.
  await kv.delete(key('a')); await kv.delete(enrollmentKey('a'));
  assert.equal((await stub.run([key('b')], 1_120_000)).skipped, true);
  assert.equal((await stub.run([key('b')], 2_019_999)).skipped, true);
  assert.equal(sends, 1);
  await stub.run([key('b')], 2_020_000);
  assert.equal(sends, 2);
  assert.equal((await stub.owner()).key, key('b'));

  // Separate object identity, failed ambiguous dispatch and real concurrent
  // RPCs: only one can enter the outbound request at a time.
  const other = ns.get(ns.idFromName('retry-vehicle'));
  await kv.put(key('b'), JSON.stringify(record));
  let release; gate = new Promise(resolve => { release = resolve; });
  const waiting = new Promise(resolve => { entered = resolve; });
  failures = 1;
  const first = other.run([key('a'), key('b')], 3_000_000);
  await waiting;
  assert.equal((await other.run([key('b')], 3_000_000)).skipped, true);
  release(); await first;
  assert.equal(sends, 3);
  await other.run([key('b')], 3_060_000);
  assert.equal(sends, 4);
  await other.run([key('b')], 3_120_000);
  assert.equal(sends, 4);
});
