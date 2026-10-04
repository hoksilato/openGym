/* Admin projections, AGPL-3.0-or-later. Authentication mutations live in auth.js. */
import { isAdmin, inviteOnly, json, readJSON, audit } from './auth.js';
import { readState, readHead, records } from './state.js';
const error = (message, status) => json({ error: message }, status);
export async function adminRoute(request, env, admin) {
  if (!isAdmin(admin, env)) return error('admin only', 403);
  const url = new URL(request.url), route = request.method + ' ' + url.pathname;
  const password = /^(1|true|yes|on)$/i.test(env.PASSWORD_LOGIN || '');
  if (route === 'GET /api/admin/users') {
    // A roster reads only compact head metadata, never each 5 MiB workout document.
    // Indexed correlated existence lookup avoids a D1 invocation per user.
    const { results: all } = await env.DB.prepare(`SELECT u.id,u.name,u.created,u.admin,u.disabled,
      u.invited_by,u.email,(u.pw_hash IS NOT NULL) AS has_password,
      h.workout_count,h.last_workout,h.state_ts,h.last_pull,p.payload AS live_payload,
      EXISTS(SELECT 1 FROM push_subscriptions s WHERE s.user_id=u.id) AS has_push
      FROM users u LEFT JOIN state_heads h ON h.user_id=u.id
      LEFT JOIN presence p ON p.user_id=u.id AND p.expires_at>?
      ORDER BY u.created`).bind(Date.now()).all();
    const users = all.map(u => ({ id: u.id, name: u.name, created: u.created,
      disabled: !!u.disabled, admin: isAdmin(u, env), invitedBy: u.invited_by || null,
      workouts: u.workout_count || 0, lastWorkout: u.last_workout || null,
      lastSync: Math.max(u.state_ts || 0, u.last_pull || 0) || null,
      hasPush: !!u.has_push, live: u.live_payload ? JSON.parse(u.live_payload) : null,
      ...(password ? { password: !!u.has_password, email: u.email || null } : {}) }));
    return json({ users, invite_only: inviteOnly(env), ...(password ? { password_login: true } : {}), now: Date.now() });
  }
  if (route === 'GET /api/admin/user') {
    const u = await env.DB.prepare('SELECT * FROM users WHERE id=?').bind(url.searchParams.get('id')).first();
    if (!u) return error('no such user', 404);
    const state = await readState(env, u.id) || {}, head = await readHead(env, u.id);
    const reset = password ? await env.DB.prepare("SELECT expires FROM auth_codes WHERE user_id=? AND kind='reset' ORDER BY expires DESC LIMIT 1").bind(u.id).first() : null;
    return json({ user: { id: u.id, name: u.name, created: u.created, disabled: !!u.disabled,
      admin: isAdmin(u, env), invitedBy: u.invited_by || null,
      ...(password ? { password: !!u.pw_hash, email: u.email || null, resetUntil: reset?.expires > Date.now() ? reset.expires : null } : {}) },
      unit: state.unit || 'kg', lastSync: Math.max(Number(state._ts) || 0, head?.last_pull || 0) || null,
      routines: records(state.routines).map(r => ({ id: r.id, name: r.name, emoji: r.emoji, count: records(r.ex).length })),
      bodyweight: records(state.bodyweight), workouts: records(state.workouts).reverse().map(({ media, ...w }) => w) });
  }
  if (route === 'POST /api/admin/user/delete') {
    const { id } = await readJSON(request);
    const u = await env.DB.prepare('SELECT * FROM users WHERE id=?').bind(id).first();
    if (!u) return error('no such user', 404);
    if (u.id === admin.id) return error('you cannot delete your own account', 400);
    if (isAdmin(u, env)) {
      const { results } = await env.DB.prepare('SELECT id,admin FROM users').all();
      if (results.filter(x => isAdmin(x, env)).length <= 1) return error('cannot delete the last admin', 400);
    }
    await env.DB.prepare('DELETE FROM users WHERE id=?').bind(id).run();
    await audit(env, 'admin.user.delete', admin, null, u.name);
    return json({ ok: true, id });
  }
  if (route === 'GET /api/admin/audit') {
    const days = Math.max(1, Number(env.AUDIT_DAYS) || 90), max = 5000;
    await env.DB.batch([
      env.DB.prepare('DELETE FROM audit_events WHERE ts<?').bind(Date.now() - days * 86400000),
      env.DB.prepare('DELETE FROM audit_events WHERE id NOT IN (SELECT id FROM audit_events ORDER BY id DESC LIMIT ?)').bind(max)
    ]);
    const limit = Math.max(1, Math.min(200, Number(url.searchParams.get('limit')) || 100));
    const before = Number(url.searchParams.get('before')) || Number.MAX_SAFE_INTEGER;
    const cat = url.searchParams.get('cat') || '';
    const where = cat === 'fail' ? 'ok=0' : cat ? 'event LIKE ?' : '1=1';
    const params = cat && cat !== 'fail' ? [cat.replace(/[%_]/g, '') + '.%'] : [];
    const { results } = await env.DB.prepare(`SELECT * FROM audit_events WHERE ${where} AND id<? ORDER BY id DESC LIMIT ?`).bind(...params, before, limit).all();
    const total = await env.DB.prepare(`SELECT COUNT(*) AS n FROM audit_events WHERE ${where}`).bind(...params).first();
    const events = results.map(r => ({ id: r.id, ts: r.ts, ev: r.event, ok: !!r.ok,
      ...(r.actor_id ? { uid: r.actor_id, name: r.actor_name } : {}),
      ...(r.target_id ? { tgt: r.target_id, tname: r.target_name } : {}), ...(r.message ? { msg: r.message } : {}) }));
    return json({ events, total: total.n, nextBefore: events.length === limit ? events.at(-1).id : null,
      enabled: true, ip_mode: 'off', retention: { max, days }, now: Date.now() });
  }
  if (route === 'POST /api/admin/audit/clear') {
    await env.DB.prepare('DELETE FROM audit_events').run(); await audit(env, 'admin.audit.clear', admin);
    return json({ ok: true });
  }
  return error('not found', 404);
}
