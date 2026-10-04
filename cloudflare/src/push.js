import { Buffer } from 'node:buffer';
import { createECDH } from 'node:crypto';
import webpush from 'web-push';
import { dayReminderPush, restTimerPush, testPush } from '../../api/push-messages.js';
import { readState } from './state.js';

// Do not use web-push's Node HTTPS transport: Workers fetch owns outbound I/O.
// Only provider-owned push hosts are accepted. A caller-selected arbitrary HTTPS host
// cannot be made safe by a DNS preflight (rebinding), so upstream's Node DNS guard is
// replaced with this intentionally small allowlist, enforced again before every send.
const PUSH_HOSTS = [
  'fcm.googleapis.com', 'updates.push.services.mozilla.com',
  'web.push.apple.com',
  'wns.windows.com', 'notify.windows.com',
];
const MAX_SUBS = 20;
const PUSH_TIMEOUT_MS = 10000;
const REMINDER_WINDOW_MS = 15 * 60 * 1000;
const json = (body, status = 200) => Response.json(body, { status, headers: { 'Cache-Control': 'no-store' } });
const deviceIdOf = v => typeof v === 'string' && /^[A-Za-z0-9_-]{8,64}$/.test(v) ? v : '';
const restKey = (uid, device) => JSON.stringify(['rest', uid, device]);
const reminderKey = uid => JSON.stringify(['reminder', uid]);

export function pushEndpointError(raw) {
  if (typeof raw !== 'string' || raw.length > 4096) return 'endpoint is not a valid URL';
  let u;
  try { u = new URL(raw); } catch { return 'endpoint is not a valid URL'; }
  if (u.protocol !== 'https:') return 'endpoint must be an https:// URL';
  if (u.username || u.password) return 'endpoint must not carry credentials';
  if (u.port && u.port !== '443') return 'endpoint must use HTTPS port 443';
  if (u.hash) return 'endpoint must not carry a fragment';
  const host = u.hostname.toLowerCase();
  const allowed = PUSH_HOSTS.some(base => host === base ||
    (base !== 'fcm.googleapis.com' && host.endsWith('.' + base)));
  return allowed ? null : 'endpoint is not a supported push service';
}

function decodeKey(value, length) {
  if (typeof value !== 'string' || value.length > Math.ceil(length * 4 / 3) + 2 || !/^[A-Za-z0-9_-]+={0,2}$/.test(value)) return null;
  const bytes = Buffer.from(value, 'base64url');
  return bytes.length === length ? bytes : null;
}

// No auto-generated keys or defaults: operators explicitly configure all three values.
function vapidDetails(env) {
  const publicBytes = decodeKey(env.VAPID_PUBLIC_KEY, 65);
  const privateBytes = decodeKey(env.VAPID_PRIVATE_KEY, 32);
  if (!publicBytes || publicBytes[0] !== 4 || !privateBytes) return null;
  let subject;
  try { subject = new URL(env.VAPID_SUBJECT); } catch { return null; }
  if (!['https:', 'mailto:'].includes(subject.protocol) || subject.username || subject.password) return null;
  if (subject.protocol === 'mailto:' && !/^[^@\s]+@[^@\s]+$/.test(subject.pathname)) return null;
  try {
    const key = createECDH('prime256v1');
    key.setPrivateKey(privateBytes);
    if (!key.getPublicKey().equals(publicBytes)) return null;
  } catch { return null; }
  return { subject: env.VAPID_SUBJECT, publicKey: env.VAPID_PUBLIC_KEY, privateKey: env.VAPID_PRIVATE_KEY };
}

function disabled() {
  return json({ enabled: false, key: null, code: 'push_disabled',
    error: 'Push notifications are disabled. Configure valid VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY and VAPID_SUBJECT.' }, 503);
}

// Exported for an actual workerd crypto interoperability test, not a custom transport hook.
export function buildPushRequest(env, subscription, payload) {
  const bad = pushEndpointError(subscription.endpoint);
  if (bad) throw new Error(bad);
  const vapid = vapidDetails(env);
  if (!vapid) throw new Error('Push notifications are disabled');
  return webpush.generateRequestDetails(subscription, JSON.stringify(payload), {
    vapidDetails: vapid, contentEncoding: 'aes128gcm', urgency: 'high',
    TTL: payload.tag === 'rest-timer' ? 60 : 900,
    topic: payload.tag === 'rest-timer' ? 'rest-timer' : payload.tag === 'day-reminder' ? 'day-reminder' : 'test',
  });
}

async function sendPush(env, userId, payload, deviceId = '') {
  const user = await env.DB.prepare('SELECT id, disabled FROM users WHERE id = ?').bind(userId).first();
  if (!user || user.disabled || !vapidDetails(env)) return { sent: 0, failed: 0, skipped: true };
  let { results: subs } = await env.DB.prepare('SELECT * FROM push_subscriptions WHERE user_id = ?').bind(userId).all();
  // Preserve older-client fallback when the sending device has never registered its own ID.
  if (deviceId && subs.some(s => s.device_id === deviceId)) subs = subs.filter(s => s.device_id === deviceId);
  let sent = 0, failed = 0, next = 0;
  const worker = async () => {
    while (next < subs.length) {
      const sub = subs[next++];
      if (pushEndpointError(sub.endpoint)) {
        await env.DB.prepare('DELETE FROM push_subscriptions WHERE endpoint = ?').bind(sub.endpoint).run();
        failed++;
        continue;
      }
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), PUSH_TIMEOUT_MS);
      try {
        const details = buildPushRequest(env, { endpoint: sub.endpoint, keys: { p256dh: sub.p256dh, auth: sub.auth } }, payload);
        const response = await fetch(details.endpoint, { method: details.method, headers: details.headers,
          body: details.body, signal: controller.signal, redirect: 'manual' });
        if (response.ok) sent++;
        else {
          failed++;
          if ([403, 404, 410].includes(response.status)) {
            await env.DB.prepare('DELETE FROM push_subscriptions WHERE endpoint = ?').bind(sub.endpoint).run();
          }
        }
        // Never log endpoints, auth keys, payloads, or push service response bodies.
        if (response.body) await response.body.cancel().catch(() => {});
      } catch { failed++; }
      finally { clearTimeout(timeout); }
    }
  };
  await Promise.all(Array.from({ length: Math.min(6, subs.length) }, worker));
  return { sent, failed };
}

function zoneParts(timeZone, timestamp) {
  try {
    const parts = new Intl.DateTimeFormat('en-CA', { timeZone, hourCycle: 'h23',
      year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' }).formatToParts(timestamp);
    const get = k => parts.find(p => p.type === k)?.value;
    return { date: `${get('year')}-${get('month')}-${get('day')}`, time: `${get('hour')}:${get('minute')}` };
  } catch { return null; }
}

function timeValid(value) { return typeof value === 'string' && /^(?:[01]\d|2[0-3]):[0-5]\d$/.test(value); }
function nextDate(date, days) { return new Date(Date.parse(date + 'T12:00:00Z') + days * 86400000).toISOString().slice(0, 10); }

// Find all actual instants for one wall-clock minute. Sampling both sides of the date
// handles DST folds, half-hour offsets and skipped hours without guessing a fixed offset.
export function localInstants(date, time, tz) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date) || !timeValid(time)) return [];
  const wall = Date.parse(date + 'T' + time + ':00Z');
  if (!Number.isFinite(wall)) return [];
  const offsets = new Set();
  for (const delta of [-36, -12, 0, 12, 36]) {
    const at = wall + delta * 3600000;
    const p = zoneParts(tz, at);
    if (!p) return [];
    offsets.add(Date.parse(p.date + 'T' + p.time + ':00Z') - at);
  }
  return [...offsets].map(offset => wall - offset).filter(at => {
    const p = zoneParts(tz, at);
    return p?.date === date && p.time === time;
  }).sort((a, b) => a - b);
}

// A daily alarm is sufficient; no 10-second polling or full workout-document reads.
// A nonexistent DST minute is skipped; a repeated minute is deduplicated by local date.
export function nextReminder(reminder, lastSentDate, now = Date.now()) {
  if (!reminder?.on || !timeValid(reminder.time)) return null;
  const tz = reminder.tz || 'UTC';
  const today = zoneParts(tz, now);
  if (!today) return null;
  for (let n = 0; n < 4; n++) {
    const date = nextDate(today.date, n);
    if (date === lastSentDate) continue;
    for (const at of localInstants(date, reminder.time, tz)) {
      // Catch-up never crosses the user's local midnight.
      if (at >= now || (date === today.date && now - at <= REMINDER_WINDOW_MS)) {
        return { dueAt: at, localDate: date };
      }
    }
  }
  return null;
}

function projection(data) {
  const reminder = data?.reminder;
  return {
    lang: typeof data?.lang === 'string' ? data.lang.slice(0, 16) : 'en',
    reminder: { on: Boolean(reminder?.on), time: typeof reminder?.time === 'string' ? reminder.time.slice(0, 6) : '',
      tz: typeof reminder?.tz === 'string' ? reminder.tz.slice(0, 128) : 'UTC' },
  };
}

function routineFor(state, date) {
  if ((Array.isArray(state.workouts) ? state.workouts : []).some(w => w?.d === date)) return null;
  const routines = Array.isArray(state.routines) ? state.routines : [];
  const ov = state.dayPlan?.[date];
  if (ov === 'rest') return null;
  if (ov) {
    const routine = routines.find(r => r?.id === ov);
    if (routine) return routine;
  }
  const weekday = new Date(date + 'T12:00:00Z').getUTCDay();
  for (const id of [].concat(state.week?.[weekday] || [])) {
    const routine = routines.find(r => r?.id === id);
    if (routine) return routine;
  }
  return null;
}

export async function rearmPushAlarm(env, storage) {
  const first = await env.DB.prepare('SELECT MIN(due_at) AS due FROM push_tasks').first();
  if (first?.due != null) await storage.setAlarm(Math.max(Date.now() + 100, first.due));
  else await storage.deleteAlarm();
}

async function scheduleReminder(env, userId, now = Date.now()) {
  const remove = () => env.DB.prepare('DELETE FROM push_tasks WHERE task_key = ?').bind(reminderKey(userId)).run();
  if (!vapidDetails(env)) return remove();
  const user = await env.DB.prepare('SELECT disabled FROM users WHERE id = ?').bind(userId).first();
  if (!user || user.disabled) return remove();
  const sub = await env.DB.prepare('SELECT 1 AS present FROM push_subscriptions WHERE user_id = ? LIMIT 1').bind(userId).first();
  if (!sub) return remove();
  const record = await env.DB.prepare('SELECT * FROM push_reminders WHERE user_id = ?').bind(userId).first();
  if (!record) return remove();
  const state = JSON.parse(record.state_json);
  const next = nextReminder(state.reminder, record.last_sent_date, now);
  if (!next) return remove();
  // Replace atomically; a failed read/write never loses the previous wake-up.
  await env.DB.prepare(`INSERT INTO push_tasks (task_key, user_id, kind, due_at, local_date) VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(task_key) DO UPDATE SET due_at = excluded.due_at, local_date = excluded.local_date`)
    .bind(reminderKey(userId), userId, 'reminder', next.dueAt, next.localDate).run();
}

export async function syncReminders(env, userId, data, storage) {
  const state = projection(data);
  await env.DB.prepare(`INSERT INTO push_reminders (user_id, state_json) VALUES (?, ?)
    ON CONFLICT(user_id) DO UPDATE SET state_json = excluded.state_json`).bind(userId, JSON.stringify(state)).run();
  await scheduleReminder(env, userId);
  await rearmPushAlarm(env, storage);
}

// AppDO must serialize this with pushRoute and state PUTs. Process one task per alarm:
// at most 20 provider fetches, below Workers Free's outbound-subrequest limit.
export async function alarm(env, storage) {
  try {
    const task = await env.DB.prepare('SELECT * FROM push_tasks WHERE due_at <= ? ORDER BY due_at, task_key LIMIT 1').bind(Date.now()).first();
    if (!task) return;
    const user = await env.DB.prepare('SELECT id, disabled FROM users WHERE id = ?').bind(task.user_id).first();
    if (!user || user.disabled || !vapidDetails(env)) {
      await env.DB.prepare('DELETE FROM push_tasks WHERE user_id = ?').bind(task.user_id).run();
      return;
    }
    // Persist the claim before contacting a provider. Alarm retries cannot duplicate it.
    // Delivery is intentionally at-most-once: a crash after this write can lose a push;
    // neither Web Push nor an external HTTP request supports an exactly-once transaction.
    if (task.kind === 'rest') {
      await env.DB.prepare('DELETE FROM push_tasks WHERE task_key = ?').bind(task.task_key).run();
      if (Date.now() - task.due_at <= REMINDER_WINDOW_MS) {
        await sendPush(env, task.user_id, JSON.parse(task.payload_json), task.device_id);
      }
      return;
    }
    const record = await env.DB.prepare('SELECT * FROM push_reminders WHERE user_id = ?').bind(task.user_id).first();
    if (!record) {
      await env.DB.prepare('DELETE FROM push_tasks WHERE task_key = ?').bind(task.task_key).run();
      return;
    }
    // Read the canonical state once at delivery, so completed workouts and plans use
    // the latest committed data without a second large copy in push_reminders.
    const state = await readState(env, task.user_id) || JSON.parse(record.state_json);
    const current = zoneParts(state.reminder?.tz || 'UTC', Date.now());
    const routine = routineFor(state, task.local_date);
    if (state.reminder?.on && current?.date === task.local_date && record.last_sent_date !== task.local_date &&
        Date.now() - task.due_at <= REMINDER_WINDOW_MS && routine) {
      await env.DB.prepare('UPDATE push_reminders SET last_sent_date = ? WHERE user_id = ?').bind(task.local_date, task.user_id).run();
      // Schedule tomorrow before network I/O, so transient provider failure cannot stop it.
      await scheduleReminder(env, task.user_id, Date.now());
      await sendPush(env, task.user_id, dayReminderPush(state.lang, { ...routine,
        name: String(routine.name || '').slice(0, 160), emoji: String(routine.emoji || '').slice(0, 16) }));
    } else {
      // Past the local reminder minute, completed workout, or rest day: move forward,
      // rather than re-arming the same 15-minute catch-up window in a tight loop.
      await scheduleReminder(env, task.user_id, Math.max(Date.now(), task.due_at) + REMINDER_WINDOW_MS + 1);
    }
  } finally { await rearmPushAlarm(env, storage); }
}

async function bodyOf(request) {
  try {
    const body = await request.json();
    return body && typeof body === 'object' && !Array.isArray(body) ? body : null;
  } catch { return null; }
}

export async function pushRoute(request, env, user, storage) {
  const url = new URL(request.url);
  const path = url.pathname;
  if (!path.startsWith('/api/push/')) return null;
  if (request.method === 'GET' && path === '/api/push/public-key') {
    return vapidDetails(env) ? json({ key: env.VAPID_PUBLIC_KEY, enabled: true }) : disabled();
  }
  if (!user?.id) return json({ error: 'not signed in' }, 401);
  const currentUser = await env.DB.prepare('SELECT disabled FROM users WHERE id = ?').bind(user.id).first();
  if (!currentUser || user.disabled || currentUser.disabled) return json({ error: 'account disabled' }, 403);
  if (request.method === 'GET' && path === '/api/push/status') {
    const sub = await env.DB.prepare('SELECT 1 AS present FROM push_subscriptions WHERE user_id = ? AND endpoint = ?')
      .bind(user.id, url.searchParams.get('endpoint') || '').first();
    return json({ subscribed: Boolean(vapidDetails(env) && sub), enabled: Boolean(vapidDetails(env)) });
  }
  const routes = new Set(['/api/push/subscribe', '/api/push/unsubscribe', '/api/push/test', '/api/push/rest-timer', '/api/push/rest-timer/cancel']);
  if (request.method !== 'POST' || !routes.has(path)) return json({ error: 'not found' }, 404);
  const body = await bodyOf(request);
  if (!body) return json({ error: 'invalid JSON body' }, 400);
  // Cleanup remains possible after VAPID is removed; it does not claim delivery works.
  if (path === '/api/push/unsubscribe') {
    if (typeof body.endpoint !== 'string') return json({ error: 'endpoint required' }, 400);
    await env.DB.prepare('DELETE FROM push_subscriptions WHERE user_id = ? AND endpoint = ?').bind(user.id, body.endpoint).run();
    const remaining = await env.DB.prepare('SELECT 1 AS present FROM push_subscriptions WHERE user_id = ? LIMIT 1').bind(user.id).first();
    if (!remaining) await env.DB.prepare('DELETE FROM push_tasks WHERE user_id = ?').bind(user.id).run();
    await rearmPushAlarm(env, storage);
    return json({ ok: true });
  }
  const deviceId = deviceIdOf(body.deviceId);
  if (path === '/api/push/rest-timer/cancel') {
    await env.DB.prepare(deviceId ? 'DELETE FROM push_tasks WHERE user_id = ? AND kind = ? AND device_id = ?' :
      'DELETE FROM push_tasks WHERE user_id = ? AND kind = ?').bind(...(deviceId ? [user.id, 'rest', deviceId] : [user.id, 'rest'])).run();
    await rearmPushAlarm(env, storage);
    return json({ ok: true });
  }
  if (!vapidDetails(env)) return disabled();
  if (path === '/api/push/subscribe') {
    const sub = body.subscription;
    const publicKey = decodeKey(sub?.keys?.p256dh, 65);
    if (!sub?.endpoint || !publicKey || publicKey[0] !== 4 || !decodeKey(sub?.keys?.auth, 16)) return json({ error: 'invalid subscription' }, 400);
    const bad = pushEndpointError(sub.endpoint);
    if (bad) return json({ error: bad }, 400);
    try {
      // Reject invalid curve points now rather than storing a permanently undeliverable row.
      await crypto.subtle.importKey('raw', publicKey, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
    } catch { return json({ error: 'invalid subscription key' }, 400); }
    await env.DB.prepare(`INSERT INTO push_subscriptions (endpoint, user_id, device_id, p256dh, auth, created_at)
      VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(endpoint) DO UPDATE SET
      user_id = excluded.user_id, device_id = excluded.device_id, p256dh = excluded.p256dh, auth = excluded.auth`)
      .bind(sub.endpoint, user.id, deviceId, sub.keys.p256dh, sub.keys.auth, Date.now()).run();
    await env.DB.prepare(`DELETE FROM push_subscriptions WHERE user_id = ? AND endpoint NOT IN
      (SELECT endpoint FROM push_subscriptions WHERE user_id = ? ORDER BY created_at DESC, endpoint DESC LIMIT ?)`)
      .bind(user.id, user.id, MAX_SUBS).run();
    await syncReminders(env, user.id, await readState(env, user.id), storage);
    return json({ ok: true });
  }
  const sub = await env.DB.prepare('SELECT 1 AS present FROM push_subscriptions WHERE user_id = ? LIMIT 1').bind(user.id).first();
  if (!sub) return json({ error: 'No push subscriptions registered', code: 'push_not_subscribed' }, 409);
  const state = await readState(env, user.id);
  if (path === '/api/push/test') {
    const result = await sendPush(env, user.id, testPush(state?.lang));
    return result.sent ? json({ ok: true, ...result }) : json({ error: 'Push service did not accept the notification', ...result }, 502);
  }
  const raw = body.seconds;
  const seconds = typeof raw === 'number' || typeof raw === 'string' ? Number(raw) : NaN;
  if (!Number.isFinite(seconds) || seconds < 1) return json({ error: 'seconds required' }, 400);
  const key = restKey(user.id, deviceId);
  const count = await env.DB.prepare('SELECT COUNT(*) AS n FROM push_tasks WHERE user_id = ? AND kind = ? AND task_key != ?')
    .bind(user.id, 'rest', key).first();
  if (count.n >= MAX_SUBS) return json({ error: 'too many active rest timers' }, 429);
  await env.DB.prepare(`INSERT INTO push_tasks (task_key, user_id, kind, device_id, due_at, payload_json)
    VALUES (?, ?, 'rest', ?, ?, ?) ON CONFLICT(task_key) DO UPDATE SET due_at = excluded.due_at, payload_json = excluded.payload_json`)
    .bind(key, user.id, deviceId, Date.now() + Math.min(3600, Math.round(seconds)) * 1000, JSON.stringify(restTimerPush(state?.lang))).run();
  await rearmPushAlarm(env, storage);
  return json({ ok: true });
}
