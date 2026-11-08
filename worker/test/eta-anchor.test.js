import test from 'node:test';
import assert from 'node:assert/strict';
import { decodeTelemetry, apnsPayload } from '../monitoring.js';

const now = Date.parse('2026-08-04T12:02:00Z');
const observed = '2026-08-04T12:00:30Z';
function state(metric, event = 'start') {
  const telemetry = decodeTelemetry({ timestamp: '2026-08-04T12:02:00Z', metrics: {
    xevBatteryChargeDisplayStatus: { value: 'CHARGING' },
    xevBatteryTimeToFullCharge: metric
  }});
  return apnsPayload(event, telemetry, {}, now).aps['content-state'];
}

test('metric updateTime reaches APNs as Swift reference-date seconds', () => {
  for (const event of ['start', 'update']) {
    const content = state({ value: 90, updateTime: observed }, event);
    assert.equal(content.timeToFullMinutes, 90);
    assert.equal(content.timeToFullObservedAt, Date.parse(observed) / 1000 - 978307200);
  }
});

test('missing, invalid, future, or stale metric timestamp never borrows envelope time', () => {
  for (const metric of [
    { value: 90 }, { value: 90, updateTime: 'invalid' },
    { value: 90, updateTime: '2026-08-04T11:56:59Z' },
    { value: 90, updateTime: '2026-08-04T12:02:01Z' },
    { value: null, updateTime: observed }, { value: -1, updateTime: observed },
    90, null
  ]) assert.equal(state(metric).timeToFullObservedAt, null);
  assert.notEqual(state({ value: 90, updateTime: '2026-08-04T11:57:00Z' }).timeToFullObservedAt, null);
});
