import test from 'node:test';
import assert from 'node:assert/strict';
import { createECDH, createDecipheriv, hkdfSync, createPublicKey, verify } from 'node:crypto';
import { pushEndpointError, localInstants, nextReminder, buildPushRequest } from '../src/push.js';

// Public, fixed test-only keys. These must never be deployment secrets.
const testKey = n => {
  const ecdh = createECDH('prime256v1');
  ecdh.setPrivateKey(Buffer.alloc(32, n));
  return ecdh;
};
const vapid = testKey(1);
const recipient = testKey(2);
const env = {
  VAPID_PUBLIC_KEY: vapid.getPublicKey().toString('base64url'),
  VAPID_PRIVATE_KEY: vapid.getPrivateKey().toString('base64url'),
  VAPID_SUBJECT: 'mailto:test@example.com',
};
const subscription = { endpoint: 'https://fcm.googleapis.com/fcm/send/test-only', keys: {
  p256dh: recipient.getPublicKey().toString('base64url'), auth: Buffer.alloc(16, 7).toString('base64url'),
} };

function decrypt(body) {
  const salt = body.subarray(0, 16);
  const length = body[20];
  const serverPublic = body.subarray(21, 21 + length);
  const secret = recipient.computeSecret(serverPublic);
  const ikm = Buffer.from(hkdfSync('sha256', secret, Buffer.alloc(16, 7),
    Buffer.concat([Buffer.from('WebPush: info\0'), recipient.getPublicKey(), serverPublic]), 32));
  const cek = Buffer.from(hkdfSync('sha256', ikm, salt, Buffer.from('Content-Encoding: aes128gcm\0'), 16));
  const nonce = Buffer.from(hkdfSync('sha256', ikm, salt, Buffer.from('Content-Encoding: nonce\0'), 12));
  const cipher = body.subarray(21 + length);
  const decipher = createDecipheriv('aes-128-gcm', cek, nonce);
  decipher.setAuthTag(cipher.subarray(-16));
  const padded = Buffer.concat([decipher.update(cipher.subarray(0, -16)), decipher.final()]);
  assert.equal(padded.at(-1), 2);
  return JSON.parse(padded.subarray(0, -1).toString());
}

// Shared by integration tests to validate the ciphertext emitted inside actual workerd.
export { env as testVapid, subscription as testSubscription, decrypt };

test('provider allowlist rejects localhost, metadata, credentials, redirects targets and suffix tricks', () => {
  for (const endpoint of [
    'http://fcm.googleapis.com/send', 'https://127.0.0.1/a', 'https://[::1]/a',
    'https://169.254.169.254/latest/meta-data', 'https://localhost/a', 'https://example.com/a',
    'https://fcm.googleapis.com.evil.example/a', 'https://evilexampleweb.push.apple.com/a',
    'https://updates.push.services.mozilla.com.evil.example/a',
    'https://user:secret@fcm.googleapis.com/send', 'https://fcm.googleapis.com:8443/a',
    'https://fcm.googleapis.com/send#fragment',
  ]) assert.ok(pushEndpointError(endpoint), endpoint);
  for (const endpoint of [
    'https://fcm.googleapis.com/fcm/send/abc', 'https://updates.push.services.mozilla.com/wpush/v2/a',
    'https://web.push.apple.com/Q/a', 'https://abc.web.push.apple.com/Q/a',
    'https://abc.notify.windows.com/w/?token=x',
  ]) assert.equal(pushEndpointError(endpoint), null, endpoint);
});

test('actual web-push encryption decrypts as RFC 8291 aes128gcm and VAPID signature verifies', () => {
  const payload = { title: 'Rest over 💪', body: 'Next set', tag: 'rest-timer' };
  const details = buildPushRequest(env, subscription, payload);
  assert.equal(details.method, 'POST');
  assert.equal(details.headers['Content-Encoding'], 'aes128gcm');
  assert.equal(details.headers.Urgency, 'high');
  assert.equal(details.headers.TTL, 60);
  assert.deepEqual(decrypt(Buffer.from(details.body)), payload);
  const auth = details.headers.Authorization;
  assert.match(auth, /^vapid t=/);
  const token = auth.match(/t=([^,]+)/)[1];
  const [header, claims, signature] = token.split('.');
  const jwt = JSON.parse(Buffer.from(claims, 'base64url').toString());
  assert.equal(jwt.aud, 'https://fcm.googleapis.com');
  assert.equal(jwt.sub, env.VAPID_SUBJECT);
  const raw = vapid.getPublicKey();
  const key = createPublicKey({ key: { kty: 'EC', crv: 'P-256',
    x: raw.subarray(1, 33).toString('base64url'), y: raw.subarray(33).toString('base64url') }, format: 'jwk' });
  assert.equal(verify('sha256', Buffer.from(header + '.' + claims), { key, dsaEncoding: 'ieee-p1363' }, Buffer.from(signature, 'base64url')), true);
  assert.throws(() => buildPushRequest({}, subscription, payload), /disabled/);
  assert.throws(() => buildPushRequest({ ...env, VAPID_PUBLIC_KEY: recipient.getPublicKey().toString('base64url') }, subscription, payload), /disabled/);
});

test('local reminder time handles non-integral offsets, DST gaps and repeated hours', () => {
  assert.deepEqual(localInstants('2026-10-04', '09:00', 'Asia/Kathmandu'), [Date.parse('2026-10-04T03:15:00Z')]);
  assert.deepEqual(localInstants('2026-03-08', '02:30', 'America/New_York'), []);
  assert.deepEqual(localInstants('2026-11-01', '01:30', 'America/New_York'), [
    Date.parse('2026-11-01T05:30:00Z'), Date.parse('2026-11-01T06:30:00Z'),
  ]);
  assert.deepEqual(localInstants('2026-10-04', '09:00', 'Not/A_Zone'), []);
});

test('daily schedule catches up for fifteen minutes, deduplicates local dates, never crosses midnight', () => {
  const reminder = { on: true, time: '09:00', tz: 'UTC' };
  assert.deepEqual(nextReminder(reminder, null, Date.parse('2026-10-04T08:00:00Z')), {
    dueAt: Date.parse('2026-10-04T09:00:00Z'), localDate: '2026-10-04',
  });
  assert.equal(nextReminder(reminder, null, Date.parse('2026-10-04T09:14:59Z')).localDate, '2026-10-04');
  assert.equal(nextReminder(reminder, null, Date.parse('2026-10-04T09:15:01Z')).localDate, '2026-10-05');
  assert.equal(nextReminder(reminder, '2026-10-04', Date.parse('2026-10-04T09:05:00Z')).localDate, '2026-10-05');
  assert.equal(nextReminder({ ...reminder, time: '23:55' }, null, Date.parse('2026-10-05T00:05:00Z')).localDate, '2026-10-05');
  assert.equal(nextReminder({ ...reminder, on: false }), null);
  assert.equal(nextReminder({ ...reminder, time: '25:90' }), null);
  assert.equal(nextReminder({ ...reminder, tz: 'Mars/Olympus' }), null);
});

// These cases execute the production bundle in workerd with real D1 and DO alarms.
// Provider calls are mocked and all network access is disabled.
// Miniflare 5's outboundService is a fetch handler. Keep every provider request
// inside this in-process mock; unexpected requests fail without touching the network.
function createFetchMock() {
  const pending = [];
  const calls = [];
  return {
    calls,
    disableNetConnect() {},
    get(origin) { return { intercept(match) { return { reply(reply, data = '', options = {}) {
      pending.push({ origin, match, reply, data, options });
    } }; } }; },
    async fetch(request) {
      calls.push(request.url);
      const url = new URL(request.url);
      const index = pending.findIndex(row => row.origin === url.origin && row.match.method === request.method && row.match.path === url.pathname + url.search);
      if (index < 0) throw new Error('Unexpected outbound request blocked by test');
      const row = pending.splice(index, 1)[0];
      const result = typeof row.reply === 'function' ? row.reply({ body: Buffer.from(await request.arrayBuffer()), headers: Object.fromEntries(request.headers) })
        : { statusCode: row.reply, data: row.data, headers: row.options.headers };
      return new Response(result.data, { status: result.statusCode, headers: result.headers });
    },
    assertNoPendingInterceptors() { assert.equal(pending.length, 0); },
  };
}
import { makeSession } from '../src/auth.js';
import { createHarness } from './helpers.js';

const SESSION = { ORIGIN: 'https://gym.example', RP_ID: 'gym.example', SESSION_SECRET: 'public-test-only-push-session-secret-at-least-32-characters' };
async function setup(t, vapidEnabled = true) {
  const fetchMock = createFetchMock();
  fetchMock.disableNetConnect();
  const harness = await createHarness({ bindings: { ...SESSION, ...(vapidEnabled ? env : {}) }, outboundService: request => fetchMock.fetch(request) });
  t.after(() => harness.close());
  await harness.db.prepare(`INSERT INTO users(id,name,name_key,created,sv,admin,disabled)
    VALUES('pushuser','Push Test','push test',?,0,0,0)`).bind(new Date().toISOString()).run();
  const headers = { Cookie: '__Host-gymsid=' + makeSession({ id: 'pushuser', sv: 0 }, SESSION) };
  const call = (path, body, extra = {}) => harness.request(path, {
    method: body === undefined ? 'GET' : 'POST', ...(body === undefined ? {} : { body }), headers, ...extra,
  });
  const subscribe = (deviceId = 'device_123', endpoint = subscription.endpoint) => call('/api/push/subscribe', {
    subscription: { ...subscription, endpoint }, deviceId,
  });
  return Object.assign(harness, { fetchMock, call, subscribe, headers });
}
async function eventually(check, timeout = 8000) {
  const end = Date.now() + timeout;
  while (Date.now() < end) {
    const value = await check();
    if (value) return value;
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  assert.fail('condition did not become true before timeout');
}

test('workerd reports optional push disabled, rejects unauthenticated calls, permits cleanup', async t => {
  const h = await setup(t, false);
  let response = await h.call('/api/push/public-key');
  assert.equal(response.status, 503);
  assert.equal((await response.json()).enabled, false);
  response = await h.request('/api/push/rest-timer', { method: 'POST', body: { seconds: 5 } });
  assert.equal(response.status, 401);
  assert.equal((await h.subscribe()).status, 503);
  assert.equal((await h.call('/api/push/rest-timer', { seconds: 5 })).status, 503);
  assert.equal((await h.call('/api/push/rest-timer/cancel', {})).status, 200);
});

test('workerd subscription ownership, validation, device timers, replacement and cancellation', async t => {
  const h = await setup(t);
  assert.equal((await h.subscribe()).status, 200);
  assert.equal((await (await h.call('/api/push/status?endpoint=' + encodeURIComponent(subscription.endpoint))).json()).subscribed, true);
  assert.equal((await h.subscribe('device_123', 'https://127.0.0.1/private')).status, 400);
  for (const seconds of [null, 0, -5, 'abc', {}, []]) assert.equal((await h.call('/api/push/rest-timer', { seconds })).status, 400);
  assert.equal((await h.call('/api/push/rest-timer', { seconds: 120, deviceId: 'device_123' })).status, 200);
  assert.equal((await h.call('/api/push/rest-timer', { seconds: 240, deviceId: 'device_123' })).status, 200);
  assert.equal((await h.call('/api/push/rest-timer', { seconds: 180, deviceId: 'device_456' })).status, 200);
  const tasks = await h.db.prepare("SELECT * FROM push_tasks WHERE kind='rest' ORDER BY due_at").all();
  assert.equal(tasks.results.length, 2);
  assert.equal(tasks.results[0].device_id, 'device_456');
  assert.equal((await h.call('/api/push/rest-timer/cancel', { deviceId: 'device_456' })).status, 200);
  assert.equal((await h.db.prepare("SELECT COUNT(*) AS n FROM push_tasks WHERE kind='rest'").first()).n, 1);
  assert.equal((await h.call('/api/push/rest-timer/cancel', {})).status, 200);
  assert.equal((await h.db.prepare("SELECT COUNT(*) AS n FROM push_tasks WHERE kind='rest'").first()).n, 0);
  await h.db.prepare("UPDATE users SET disabled=1 WHERE id='pushuser'").run();
  assert.ok([401, 403].includes((await h.call('/api/push/test', {})).status));
});

test('workerd performs interoperable encrypted push using fetch and prunes expired subscriptions', async t => {
  const h = await setup(t);
  assert.equal((await h.subscribe()).status, 200);
  let captured;
  h.fetchMock.get('https://fcm.googleapis.com').intercept({ method: 'POST', path: '/fcm/send/test-only' })
    .reply(options => { captured = options; return { statusCode: 201, data: '' }; });
  const response = await h.call('/api/push/test', {});
  assert.equal(response.status, 200, await response.clone().text());
  assert.equal((await response.json()).sent, 1);
  assert.ok(captured);
  assert.deepEqual(decrypt(Buffer.from(captured.body)), { title: 'openGym', body: 'Test notification ✅ — this is what alerts look like.', tag: 'test' });
  h.fetchMock.get('https://fcm.googleapis.com').intercept({ method: 'POST', path: '/fcm/send/test-only' }).reply(410, 'gone');
  assert.equal((await h.call('/api/push/test', {})).status, 502);
  const status = await h.call('/api/push/status?endpoint=' + encodeURIComponent(subscription.endpoint));
  assert.equal((await status.json()).subscribed, false);
  h.fetchMock.assertNoPendingInterceptors();
});

test('workerd rejects push-service redirects instead of fetching arbitrary destinations', async t => {
  const h = await setup(t);
  assert.equal((await h.subscribe()).status, 200);
  h.fetchMock.get('https://fcm.googleapis.com').intercept({ method: 'POST', path: '/fcm/send/test-only' })
    .reply(307, '', { headers: { Location: 'https://127.0.0.1/private' } });
  assert.equal((await h.call('/api/push/test', {})).status, 502);
  h.fetchMock.assertNoPendingInterceptors();
});

test('real durable alarm survives workerd reload and sends a rest timer only once', async t => {
  const h = await setup(t);
  assert.equal((await h.subscribe()).status, 200);
  let sent = 0;
  h.fetchMock.get('https://fcm.googleapis.com').intercept({ method: 'POST', path: '/fcm/send/test-only' })
    .reply(options => {
      assert.equal(decrypt(Buffer.from(options.body)).tag, 'rest-timer');
      sent++;
      return { statusCode: 201, data: '' };
    });
  assert.equal((await h.call('/api/push/rest-timer', { seconds: 2, deviceId: 'device_123' })).status, 200);
  assert.equal((await h.db.prepare("SELECT COUNT(*) AS n FROM push_tasks WHERE kind='rest'").first()).n, 1);
  await h.reload();
  await eventually(() => sent === 1);
  assert.equal((await h.db.prepare("SELECT COUNT(*) AS n FROM push_tasks WHERE kind='rest'").first()).n, 0);
  await new Promise(resolve => setTimeout(resolve, 400));
  assert.equal(sent, 1);
  h.fetchMock.assertNoPendingInterceptors();
});

test('daily reminder uses canonical workout plan and deduplicates across state updates/reload', async t => {
  const h = await setup(t);
  assert.equal((await h.subscribe()).status, 200);
  let sent = 0;
  h.fetchMock.get('https://fcm.googleapis.com').intercept({ method: 'POST', path: '/fcm/send/test-only' })
    .reply(options => {
      const payload = decrypt(Buffer.from(options.body));
      assert.equal(payload.tag, 'day-reminder');
      assert.match(payload.title, /Strength/);
      sent++;
      return { statusCode: 201, data: '' };
    });
  const time = new Date().toISOString().slice(11, 16);
  const date = new Date().toISOString().slice(0, 10);
  const state = { lang: 'en', reminder: { on: true, time, tz: 'UTC' }, routines: [{ id: 'strength', name: 'Strength' }],
    week: Object.fromEntries(Array.from({ length: 7 }, (_, day) => [day, ['strength']])), workouts: [], dayPlan: {} };
  let response = await h.call('/api/data', { state, baseRev: 0 }, { method: 'PUT' });
  assert.equal(response.status, 200, await response.clone().text());
  await eventually(() => sent === 1);
  const record = await h.db.prepare("SELECT * FROM push_reminders WHERE user_id='pushuser'").first();
  assert.equal(record.last_sent_date, date);
  const next = await h.db.prepare("SELECT * FROM push_tasks WHERE kind='reminder'").first();
  assert.ok(next.due_at > Date.now());
  response = await h.call('/api/data', { state, baseRev: 1 }, { method: 'PUT' });
  assert.equal(response.status, 200);
  await h.reload();
  await new Promise(resolve => setTimeout(resolve, 400));
  assert.equal(sent, 1);
  h.fetchMock.assertNoPendingInterceptors();
  response = await h.call('/api/data', { state: { ...state, reminder: { ...state.reminder, on: false } }, baseRev: 2 }, { method: 'PUT' });
  assert.equal(response.status, 200);
  assert.equal((await h.db.prepare("SELECT COUNT(*) AS n FROM push_tasks WHERE kind='reminder'").first()).n, 0);
});

test('completed workouts and rest-day overrides skip reminder delivery without a tight alarm loop', async t => {
  const h = await setup(t);
  assert.equal((await h.subscribe()).status, 200);
  const date = new Date().toISOString().slice(0, 10);
  const state = { reminder: { on: true, time: new Date().toISOString().slice(11, 16), tz: 'UTC' },
    routines: [{ id: 'routine', name: 'Planned' }],
    week: Object.fromEntries(Array.from({ length: 7 }, (_, day) => [day, 'routine'])),
    workouts: [{ d: date }], dayPlan: {} };
  assert.equal((await h.call('/api/data', { state, baseRev: 0 }, { method: 'PUT' })).status, 200);
  await eventually(async () => (await h.db.prepare("SELECT due_at FROM push_tasks WHERE kind='reminder'").first())?.due_at > Date.now());
  assert.equal(h.fetchMock.calls.length, 0);
  assert.equal((await h.db.prepare("SELECT last_sent_date FROM push_reminders WHERE user_id='pushuser'").first()).last_sent_date, null);
  assert.equal((await h.call('/api/data', { state: { ...state, workouts: [], dayPlan: { [date]: 'rest' } }, baseRev: 1 }, { method: 'PUT' })).status, 200);
  await eventually(async () => (await h.db.prepare("SELECT due_at FROM push_tasks WHERE kind='reminder'").first())?.due_at > Date.now());
  assert.equal(h.fetchMock.calls.length, 0);
});

test('rest delivery targets its registered device and disabled users lose pending alerts', async t => {
  const h = await setup(t);
  assert.equal((await h.subscribe('device_123')).status, 200);
  assert.equal((await h.subscribe('device_456', 'https://fcm.googleapis.com/fcm/send/other-device')).status, 200);
  let sent = 0;
  h.fetchMock.get('https://fcm.googleapis.com').intercept({ method: 'POST', path: '/fcm/send/test-only' })
    .reply(() => { sent++; return { statusCode: 201, data: '' }; });
  assert.equal((await h.call('/api/push/rest-timer', { seconds: 1, deviceId: 'device_123' })).status, 200);
  await eventually(() => sent === 1);
  assert.equal(h.fetchMock.calls.length, 1);
  assert.equal((await h.call('/api/push/rest-timer', { seconds: 1, deviceId: 'device_456' })).status, 200);
  await h.db.prepare("UPDATE users SET disabled=1 WHERE id='pushuser'").run();
  await eventually(async () => (await h.db.prepare("SELECT COUNT(*) AS n FROM push_tasks WHERE user_id='pushuser'").first()).n === 0);
  assert.equal(h.fetchMock.calls.length, 1);
  h.fetchMock.assertNoPendingInterceptors();
});

import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

test('pending rest alarm persists across complete runtime disposal and a new instance', async t => {
  const persistPath = await mkdtemp(join(tmpdir(), 'opengym-push-persist-'));
  const fetchMock = createFetchMock();
  const options = { bindings: { ...SESSION, ...env }, persistPath, outboundService: request => fetchMock.fetch(request) };
  let h = await createHarness(options);
  t.after(async () => { await h.close(); await rm(persistPath, { recursive: true, force: true }); });
  await h.db.prepare(`INSERT INTO users(id,name,name_key,created,sv,admin,disabled)
    VALUES('pushuser','Push Test','push test',?,0,0,0)`).bind(new Date().toISOString()).run();
  const headers = { Cookie: '__Host-gymsid=' + makeSession({ id: 'pushuser', sv: 0 }, SESSION) };
  const call = (path, body) => h.request(path, { method: 'POST', body, headers });
  assert.equal((await call('/api/push/subscribe', { subscription, deviceId: 'device_123' })).status, 200);
  let sent = 0;
  fetchMock.get('https://fcm.googleapis.com').intercept({ method: 'POST', path: '/fcm/send/test-only' })
    .reply(options => {
      assert.equal(decrypt(Buffer.from(options.body)).tag, 'rest-timer');
      sent++;
      return { statusCode: 201, data: '' };
    });
  assert.equal((await call('/api/push/rest-timer', { seconds: 3, deviceId: 'device_123' })).status, 200);
  await h.close();
  h = await createHarness(options);
  assert.equal((await h.db.prepare("SELECT COUNT(*) AS n FROM push_tasks WHERE kind='rest'").first()).n, 1);
  await eventually(() => sent === 1);
  assert.equal((await h.db.prepare("SELECT COUNT(*) AS n FROM push_tasks WHERE kind='rest'").first()).n, 0);
  fetchMock.assertNoPendingInterceptors();
});
