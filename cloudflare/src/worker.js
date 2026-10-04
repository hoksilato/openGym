/* openGym Cloudflare adapter. AGPL-3.0-or-later; upstream Node/Docker is unchanged. */
import { DurableObject } from 'cloudflare:workers';
import { authRoute, getUser, csrfOk, inviteOnly, json, readJSON, pruneAuth } from './auth.js';
import { readState, readHead, writeState, notePull, MAX_BODY } from './state.js';
import { pushRoute, syncReminders, alarm as pushAlarm } from './push.js';
import { adminRoute } from './admin.js';

const enabled = value => /^(1|true|yes|on)$/i.test(String(value || ''));
const error = (message, status) => json({ error: message }, status);
const security = {
  'Cache-Control': 'no-store, private', 'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY', 'Referrer-Policy': 'same-origin',
  'Content-Security-Policy': "frame-ancestors 'none'"
};
function secure(response, request) {
  const out = new Response(response.body, response);
  for (const [k, v] of Object.entries(security)) out.headers.set(k, v);
  // Paired native clients use Bearer tokens, never browser cookies. No credentials CORS.
  const origin = request?.headers.get('Origin');
  if (origin) { out.headers.set('Access-Control-Allow-Origin', origin); out.headers.set('Vary', 'Origin'); }
  return out;
}
export default {
  async fetch(request, env) {
    const path = new URL(request.url).pathname;
    if (path === '/api' || path.startsWith('/api/')) {
      // Free Workers allow 10 ms CPU: body parsing/crypto run in the SQLite DO.
      return env.APP.get(env.APP.idFromName('opengym')).fetch(request);
    }
    return env.ASSETS ? env.ASSETS.fetch(request) : new Response('Not found', { status: 404 });
  }
};
async function buffered(request) {
  if (!request.body) return request;
  if (Number(request.headers.get('Content-Length')) > MAX_BODY) throw Object.assign(new Error('body too large'), { status: 413 });
  const reader = request.body.getReader();
  const parts = []; let length = 0; let timer;
  const timeout = new Promise((_, reject) => { timer = setTimeout(() => {
    reader.cancel().catch(() => {});
    reject(Object.assign(new Error('request body timed out'), { status: 408 }));
  }, 30000); });
  try {
    while (true) {
      const { done, value } = await Promise.race([reader.read(), timeout]);
      if (done) break;
      length += value.byteLength;
      if (length > MAX_BODY) { await reader.cancel(); throw Object.assign(new Error('body too large'), { status: 413 }); }
      parts.push(value);
    }
    const body = new Uint8Array(length); let offset = 0;
    for (const part of parts) { body.set(part, offset); offset += part.length; }
    return new Request(request, { body });
  } finally { clearTimeout(timer); }
}
export class OpenGym extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.ctx = ctx; this.env = env; this.tail = Promise.resolve(); this.pending = 0; this.lastPrune = 0; this.inflight = 0;
  }
  async serial(run) {
    // Input gates alone do not serialize arbitrary D1 network awaits.
    if (this.pending >= 32) throw Object.assign(new Error('server busy'), { status: 503 });
    this.pending++;
    const task = this.tail.then(run); this.tail = task.catch(() => {});
    try { return await task; } finally { this.pending--; }
  }
  async fetch(original) {
    // Four 5 MiB bodies plus parsed documents fit the 128 MiB isolate budget;
    // admission happens BEFORE buffering, including clients trickling an upload.
    if (this.inflight >= 4) return secure(error('server busy — retry shortly', 503), original);
    this.inflight++;
    let response;
    try {
      // A slow upload must not hold the mutation queue.
      const request = await buffered(original);
      response = await this.serial(async () => {
        if (Date.now() - this.lastPrune > 3600000) {
          await pruneAuth(this.env); this.lastPrune = Date.now();
          await this.env.DB.prepare('DELETE FROM presence WHERE expires_at<?').bind(Date.now()).run();
        }
        return handle(request, this.env, this.ctx.storage);
      });
    } catch (e) {
      const status = Number(e.status) || 500;
      if (status >= 500) console.error('openGym API operation failed', e.name || 'Error');
      response = error(status < 500 ? e.message : 'server error', status);
    }
    this.inflight--;
    return secure(response, original);
  }
  async alarm() { await this.serial(() => pushAlarm(this.env, this.ctx.storage)); }
}
async function handle(request, env, storage) {
  const url = new URL(request.url), route = request.method + ' ' + url.pathname;
  if (!env.SESSION_SECRET || env.SESSION_SECRET.length < 32 || !env.ORIGIN || !env.RP_ID) return error('server configuration incomplete', 503);
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: {
    'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Access-Control-Max-Age': '86400'
  } });
  if (!csrfOk(request, env)) return error('cross-origin request refused', 403);
  const auth = await authRoute(request, env);
  if (auth) {
    if (route === 'POST /api/admin/user/disable' && auth.ok) {
      // Rehydrate reminders for a re-enabled account without consuming the request twice.
      const result = await auth.clone().json();
      if (result.id && result.disabled) await env.DB.prepare('DELETE FROM presence WHERE user_id=?').bind(result.id).run();
      if (result.id && !result.disabled) {
        try { await syncReminders(env, result.id, await readState(env, result.id) || {}, storage); }
        catch { console.error('openGym reminder re-enable update failed'); }
      }
    }
    return auth;
  }
  if (!enabled(env.PASSWORD_LOGIN) && /\/(?:password(?:-reset)?|email)$/.test(url.pathname)) return error('not found', 404);
  if (route === 'GET /api/health') {
    const row = await env.DB.prepare('SELECT COUNT(*) AS n FROM users').first();
    return json({ ok: true, users: row.n });
  }
  const user = await getUser(request, env);
  if (route === 'GET /api/config') return json({
    invite_only: inviteOnly(env), allow_guest: enabled(env.ALLOW_GUEST),
    ...(enabled(env.PASSWORD_LOGIN) ? { password_login: true } : {}),
    ...(env.DEFAULT_LANG ? { default_lang: env.DEFAULT_LANG } : {}), ...(user ? { coach: null } : {})
  });
  // Omitted capability flags hide upload/AI UI; disabled API routes never return SPA HTML.
  if (url.pathname.startsWith('/api/media') || url.pathname.startsWith('/api/coach')) return error('not found', 404);
  const push = await pushRoute(request, env, user, storage);
  if (push) return push;
  if (!user) return error('not signed in', 401);
  if (route === 'GET /api/data') {
    const state = await readState(env, user.id); await notePull(env, user.id);
    return json({ state, rev: state?._rev || 0, uid: user.id });
  }
  if (route === 'GET /api/data/rev') {
    const head = await readHead(env, user.id);
    return json({ rev: head?.revision || 0, uid: user.id });
  }
  if (route === 'PUT /api/data') {
    const body = await readJSON(request, MAX_BODY);
    if (body.uid != null && body.uid !== user.id) return json({ error: 'account changed', code: 'account-changed' }, 403);
    const result = await writeState(env, user.id, body);
    if (result.error) { const { status, ...payload } = result; return json({ ...payload, uid: user.id }, status); }
    // Accepted state must never be reported rejected if reminder projection fails.
    try { await syncReminders(env, user.id, result.state, storage); }
    catch { console.error('openGym reminder projection update failed'); }
    return json({ ok: true, ts: result.state._ts || null, rev: result.rev, uid: user.id });
  }
  if (route === 'POST /api/activity') {
    const body = await readJSON(request);
    if (body.active) {
      const payload = { name: String(body.name || '').slice(0, 60), exIdx: +body.exIdx || 0,
        exTotal: +body.exTotal || 0, setsDone: +body.setsDone || 0, setsTotal: +body.setsTotal || 0,
        startedAt: +body.startedAt || Date.now(), updatedAt: Date.now() };
      await env.DB.prepare(`INSERT INTO presence(user_id,payload,expires_at) VALUES(?,?,?)
        ON CONFLICT(user_id) DO UPDATE SET payload=excluded.payload,expires_at=excluded.expires_at`)
        .bind(user.id, JSON.stringify(payload), Date.now() + 120000).run();
    } else await env.DB.prepare('DELETE FROM presence WHERE user_id=?').bind(user.id).run();
    return json({ ok: true });
  }
  if (url.pathname.startsWith('/api/admin/')) return adminRoute(request, env, user);
  return error('not found', 404);
}
