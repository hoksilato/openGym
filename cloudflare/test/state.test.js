import { test } from 'node:test';
import assert from 'node:assert/strict';
import { chunkText, prepareState, writeState, readState } from '../src/state.js';
import { createHarness } from './helpers.js';

test('chunks preserve Unicode and remain safely below D1 row maximum', () => {
  const value = 'a'.repeat(131071) + '🏋️'.repeat(100000);
  const chunks = chunkText(value);
  assert.equal(chunks.join(''), value);
  for (const chunk of chunks) {
    assert.ok(Buffer.byteLength(chunk) < 900000);
    assert.equal(Buffer.from(chunk).toString('utf8'), chunk);
  }
});
test('state validation preserves reset metadata and device-local active workouts', () => {
  assert.equal(prepareState({ state: {} }, null).status, 400);
  assert.equal(prepareState({ state: [] }, null).status, 400);
  assert.equal(prepareState({ state: { workouts: {} } }, null).status, 400);
  const old = { _rev: 5, resetAt: 200, resetIds: { workouts: ['gone'] } };
  assert.equal(prepareState({ state: { workouts: [] }, baseRev: 4 }, old).status, 409);
  const value = prepareState({ state: { workouts: [null, 1, { id: 'ok' }], active: { id: 'local' }, resetAt: 100 }, baseRev: 5 }, old).state;
  assert.deepEqual(value.workouts, [{ id: 'ok' }]);
  assert.equal(value.active, undefined);
  assert.equal(value.resetAt, 200);
  assert.equal(value._rev, 6);
  assert.deepEqual(value.resetIds, old.resetIds);
});
test('workerd D1 sync: multiuser isolation, UID binding, atomic conflicts, large import and cleanup', async t => {
  const h = await createHarness(); t.after(() => h.close());
  const alice = await h.seedUser('alice'), bob = await h.seedUser('bob');
  const get = (p, cookie = alice) => h.request(p, { headers: { Cookie: cookie } });
  const put = (body, cookie = alice) => h.request('/api/data', { method: 'PUT', body, headers: { Cookie: cookie } });
  assert.equal((await h.request('/api/data')).status, 401);
  assert.equal((await put({ uid: 'bob', state: { workouts: [] } })).status, 403);
  assert.equal((await h.request('/api/data', { method: 'PUT', body: { state: { workouts: [] } }, headers: { Cookie: alice, Origin: 'https://evil.example' } })).status, 403);
  const first = await put({ uid: 'alice', baseRev: 0, state: { workouts: [{ id: 'a' }], routines: [], active: { id: 'local' }, resetAt: 123, resetIds: { workouts: ['old'] } } });
  assert.equal(first.status, 200, await first.clone().text());
  assert.equal((await first.json()).rev, 1);
  assert.deepEqual(await (await get('/api/data/rev')).json(), { rev: 1, uid: 'alice' });
  assert.equal((await (await get('/api/data', bob)).json()).state, null);
  const simultaneous = await Promise.all(['x','y'].map(id => put({ baseRev: 1, uid: 'alice', state: { workouts: [{ id }], routines: [] } })));
  assert.deepEqual(simultaneous.map(r => r.status).sort(), [200, 409]);
  const conflict = await simultaneous.find(r => r.status === 409).json();
  assert.equal(conflict.rev, 2); assert.equal(conflict.uid, 'alice');
  assert.equal(conflict.state.resetAt, 123); assert.equal(conflict.state.active, undefined);
  const large = { workouts: [{ id: 'big', note: 'x'.repeat(4 * 1024 * 1024) }], routines: [] };
  const saved = await put({ uid: 'alice', baseRev: 2, state: large });
  assert.equal(saved.status, 200, await saved.clone().text());
  const back = await (await get('/api/data')).json();
  assert.equal(back.state.workouts[0].note.length, 4 * 1024 * 1024);
  assert.equal(back.state._rev, 3);
  const parts = await h.db.prepare('SELECT COUNT(*) AS n, MAX(length(CAST(data AS BLOB))) AS max FROM state_parts WHERE user_id=?').bind('alice').first();
  assert.ok(parts.n > 10 && parts.max < 900000);
  assert.equal((await put({ state: { workouts: [], routines: [] }, baseRev: 3 })).status, 200);
  assert.equal((await h.db.prepare('SELECT COUNT(*) AS n FROM state_parts WHERE user_id=?').bind('alice').first()).n, 1);
  assert.equal((await put({ state: { workouts: [{ note: 'x'.repeat(5 * 1024 * 1024) }] } })).status, 413);
  for (const path of ['/api/data', '/api/data/rev', '/api/no-such-route']) {
    const r = await get(path); assert.match(r.headers.get('cache-control'), /no-store/);
    assert.match(r.headers.get('content-type'), /application\/json/);
  }
});
test('admin projections, disable, deletion cascade and JSON API routing', async t => {
  const h = await createHarness(); t.after(() => h.close());
  const admin = await h.seedUser('owner', { admin: true }), bob = await h.seedUser('bob');
  const request = (p, body, cookie = admin) => h.request(p, { body, headers: { Cookie: cookie } });
  assert.equal((await request('/api/admin/users', undefined, bob)).status, 403);
  let r = await request('/api/admin/users'); assert.equal(r.status, 200, await r.clone().text());
  assert.equal((await r.json()).users.length, 2);
  r = await request('/api/admin/user?id=bob'); assert.equal(r.status, 200, await r.clone().text());
  assert.equal((await request('/api/admin/user/disable', { id: 'bob', disabled: true })).status, 200);
  assert.equal((await request('/api/data', undefined, bob)).status, 401);
  assert.equal((await request('/api/admin/user/disable', { id: 'owner', disabled: true })).status, 400);
  assert.equal((await request('/api/admin/user/delete', { id: 'owner' })).status, 400);
  assert.equal((await request('/api/admin/user/delete', { id: 'bob' })).status, 200);
  assert.equal((await h.db.prepare('SELECT COUNT(*) AS n FROM users').first()).n, 1);
  r = await request('/api/admin/audit'); assert.equal(r.status, 200, await r.clone().text()); assert.ok((await r.json()).events.length);
  r = await h.request('/api/media/missing', { body: { hashes: [] } }); assert.equal(r.status, 404);
  r = await h.request('/api/login/password', { body: { name: 'owner', password: 'irrelevant' } }); assert.equal(r.status, 404);
  r = await h.request('/api/config'); const config = await r.json();
  assert.equal(config.invite_only, true); assert.equal(config.allow_guest, false);
  assert.equal(config.media, undefined); assert.equal(config.coach, undefined);
});

test('D1 CAS remains atomic without the DO mutex and a failed batch rolls back all chunks', async t => {
  const h = await createHarness(); t.after(() => h.close());
  await h.seedUser('cas');
  const env = { DB: h.db };
  await writeState(env, 'cas', { state: { workouts: [{ id: 'original' }] }, baseRev: 0 });
  let waiting = 0, release;
  const barrier = new Promise(resolve => { release = resolve; });
  const racing = { DB: {
    prepare: (...args) => h.db.prepare(...args),
    async batch(statements) { if (++waiting === 2) release(); await barrier; return h.db.batch(statements); }
  } };
  const results = await Promise.all(['a', 'b'].map(id => writeState(racing, 'cas', { state: { workouts: [{ id }] }, baseRev: 1 })));
  assert.equal(results.filter(r => r.status === 409).length, 1);
  assert.equal((await readState(env, 'cas'))._rev, 2);
  const broken = { DB: {
    prepare: (...args) => h.db.prepare(...args),
    batch: statements => h.db.batch([...statements, h.db.prepare('INSERT INTO users(id) VALUES(?)').bind('invalid')])
  } };
  await assert.rejects(() => writeState(broken, 'cas', { state: { workouts: [{ note: 'rollback'.repeat(400000) }] }, baseRev: 2 }));
  assert.equal((await readState(env, 'cas'))._rev, 2);
  const parts = await h.db.prepare('SELECT COUNT(DISTINCT write_id) AS n FROM state_parts WHERE user_id=?').bind('cas').first();
  assert.equal(parts.n, 1);
});

test('admin roster reads compact summaries in a fixed query count', async t => {
  const h = await createHarness(); t.after(() => h.close());
  const owner = await h.seedUser('owner', { admin: true });
  await h.seedUser('athlete');
  const env = { DB: h.db };
  await writeState(env, 'athlete', { state: { workouts: [{ id: 'one', d: '2026-10-04', note: 'x'.repeat(3 * 1024 * 1024) }], _ts: 123456 }, baseRev: 0 });
  for (let n = 0; n < 14; n++) await h.seedUser('member' + n);
  const response = await h.request('/api/admin/users', { headers: { Cookie: owner } });
  assert.equal(response.status, 200);
  const { users } = await response.json();
  assert.equal(users.length, 16);
  const athlete = users.find(u => u.id === 'athlete');
  assert.equal(athlete.workouts, 1); assert.equal(athlete.lastWorkout, '2026-10-04');
  assert.equal(athlete.lastSync, 123456);
  assert.ok(JSON.stringify(users).length < 10000);
});
