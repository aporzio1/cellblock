import test from 'node:test';
import assert from 'node:assert/strict';
import { apnsPayload } from '../monitoring.js';
const now = 1789960000000;
const telemetry = { charging: true, powerKW: 7, socPercent: 41, rangeKm: 120, etaMinutes: 97, sourceTimestamp: now };
test('push-to-start uses declared attributes type and visible alert', () => {
  const { aps } = apnsPayload('start', telemetry, { startedAt: now, enrollmentID: 'diagnostic' }, now);
  assert.equal(aps['attributes-type'], 'ChargingActivityAttributes');
  assert.ok(aps.alert.title);
  assert.ok(aps.alert.body);
  assert.equal(aps.attributes.sessionID, 'diagnostic');
  assert.equal(aps['content-state'].startedAt, now / 1000 - 978307200);
  assert.equal(aps.timestamp, now / 1000);
});
test('ordinary updates do not add start attributes or alert', () => {
  const { aps } = apnsPayload('update', telemetry, {}, now);
  assert.equal(aps.alert, undefined);
  assert.equal(aps['attributes-type'], undefined);
});
