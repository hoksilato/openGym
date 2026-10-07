import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import crypto from 'node:crypto';
import { authRoute, getUser, makeSession, csrfOk, readJSON, hashPassword } from '../src/auth.js';

const ORIGIN = 'https://gym.example.test';
const PASSWORD = 'correct horse battery staple';

// D1's parameter and transaction semantics, backed by real SQLite, not a SQL
// parser mock. The separate Miniflare suite exercises the deployed runtime.
function database() {
  const db = new DatabaseSync(':memory:');
  db.exec(readFileSync(new URL('../migrations/0001_auth.sql', import.meta.url), 'utf8'));
  return {
    raw: db,
    prepare(sql) {
      const statement = db.prepare(sql); let args = [];
      return {
        bind(...values) { args = values; return this; },
        async first() { return statement.get(...args) || null; },
        async all() { return { results: statement.all(...args) }; },
        async run() { const r = statement.run(...args); return { meta: { changes: Number(r.changes) } }; }
      };
    },
    async batch(statements) {
      db.exec('BEGIN');
      try { const results = []; for (const s of statements) results.push(await s.run()); db.exec('COMMIT'); return results; }
      catch (e) { db.exec('ROLLBACK'); throw e; }
    }
  };
}
function harness(t, overrides = {}) {
  const DB = database(); t.after(() => DB.raw.close());
  const env = { DB, SESSION_SECRET: 'test-only-not-a-real-secret-00000000000000', ORIGIN, RP_ID: 'gym.example.test', INVITE_ONLY: '1', PASSWORD_LOGIN: '1', ...overrides };
  let address = 1;
  function request(path, { method = 'POST', body = {}, cookie, headers = {} } = {}) {
    return new Request(ORIGIN + path, { method, headers: { Origin: ORIGIN, 'Content-Type': 'application/json',
      'CF-Connecting-IP': `192.0.2.${address++}`, ...(cookie ? { Cookie: cookie } : {}), ...headers },
    ...(!['GET', 'HEAD'].includes(method) ? { body: JSON.stringify(body) } : {}) });
  }
  async function call(path, options) {
    const res = await authRoute(request(path, options), env);
    return res ? { status: res.status, body: await res.json(), cookie: res.headers.get('set-cookie')?.split(';')[0], headers: res.headers } : null;
  }
  function invite(code = 'INVITE', admin = 0) {
    DB.raw.prepare('INSERT INTO invites(code,created,admin) VALUES(?,?,?)').run(code, new Date().toISOString(), admin);
  }
  function seed(uid = 'owner', { admin = 0, disabled = 0 } = {}) {
    DB.raw.prepare('INSERT INTO users(id,name,name_key,created,admin,disabled) VALUES(?,?,?,?,?,?)').run(uid, uid, uid.toLowerCase(), new Date().toISOString(), admin, disabled);
    return { id: uid, sv: 0, cookie: `__Host-gymsid=${makeSession({ id: uid, sv: 0 }, env)}` };
  }
  async function proof(key) {
    const login = await call('/api/login/options');
    return { cid: login.body.cid, credential: key.assertion(login.body.options.challenge) };
  }
  async function register(key = softPasskey(), { code = 'INVITE', name = 'Ana' } = {}) {
    const options = await call('/api/register/options', { body: { name, code } });
    assert.equal(options.status, 200, JSON.stringify(options.body));
    const registered = await call('/api/register/verify', { body: { cid: options.body.cid, credential: key.attestation(options.body.options.challenge) } });
    assert.equal(registered.status, 200, JSON.stringify(registered.body));
    return { ...registered, key };
  }
  return { env, DB, request, call, seed, invite, register, proof };
}
const sha = b => crypto.createHash('sha256').update(b).digest();
const b64 = b => Buffer.from(b).toString('base64url');
const cborHead = (major, n) => n < 24 ? Buffer.from([(major << 5) | n]) : n < 256 ? Buffer.from([(major << 5) | 24, n]) : Buffer.from([(major << 5) | 25, n >> 8, n & 255]);
const cborText = s => Buffer.concat([cborHead(3, Buffer.byteLength(s)), Buffer.from(s)]);
const cborBytes = b => Buffer.concat([cborHead(2, b.length), b]);
function softPasskey() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = publicKey.export({ format: 'jwk' });
  const cose = Buffer.concat([Buffer.from([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]),
    Buffer.from(jwk.x, 'base64url'), Buffer.from([0x22, 0x58, 0x20]), Buffer.from(jwk.y, 'base64url')]);
  const raw = crypto.randomBytes(16), id = b64(raw); let counter = 0;
  return {
    id,
    attestation(challenge, origin = ORIGIN, rp = 'gym.example.test') {
      const client = Buffer.from(JSON.stringify({ type: 'webauthn.create', challenge, origin, crossOrigin: false }));
      const auth = Buffer.concat([sha(rp), Buffer.from([0x45]), Buffer.alloc(4), Buffer.alloc(16), Buffer.from([0, raw.length]), raw, cose]);
      const attestation = Buffer.concat([Buffer.from([0xa3]), cborText('fmt'), cborText('none'), cborText('attStmt'), Buffer.from([0xa0]), cborText('authData'), cborBytes(auth)]);
      return { id, rawId: id, type: 'public-key', clientExtensionResults: {}, response: { clientDataJSON: b64(client), attestationObject: b64(attestation), transports: ['internal'] } };
    },
    assertion(challenge, origin = ORIGIN, userHandle = null) {
      const client = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin, crossOrigin: false }));
      const count = Buffer.alloc(4); count.writeUInt32BE(++counter);
      const auth = Buffer.concat([sha('gym.example.test'), Buffer.from([0x05]), count]);
      const signature = crypto.sign('sha256', Buffer.concat([auth, sha(client)]), privateKey);
      return { id, rawId: id, type: 'public-key', clientExtensionResults: {}, response: { clientDataJSON: b64(client), authenticatorData: b64(auth), signature: b64(signature), userHandle } };
    }
  };
}

test('sessions use secure host cookies, reject ambiguity/tampering/expiry, and hide hashes', async t => {
  const h = harness(t), owner = h.seed();
  const good = h.request('/api/me', { method: 'GET', cookie: owner.cookie });
  const user = await getUser(good, h.env);
  assert.equal(user.id, owner.id); assert.equal(user.sv, 0); assert.equal('pw_hash' in user, false);
  assert.equal(await getUser(h.request('/api/me', { method: 'GET', cookie: owner.cookie + 'x' }), h.env), null);
  assert.equal(await getUser(h.request('/api/me', { method: 'GET', cookie: owner.cookie + '; __Host-gymsid=attacker' }), h.env), null);
  assert.equal(await getUser(h.request('/api/me', { method: 'GET', cookie: owner.cookie.replace('__Host-', '') }), h.env), null);
  h.DB.raw.prepare('UPDATE users SET sv=1 WHERE id=?').run(owner.id);
  assert.equal(await getUser(good, h.env), null);
});

test('cross-origin cookie writes cannot bypass CSRF with a fake bearer header', t => {
  const h = harness(t), u = h.seed();
  assert.equal(csrfOk(h.request('/api/logout/all', { cookie: u.cookie, headers: { Origin: 'https://evil.example.test', Authorization: 'Bearer fake' } }), h.env), false);
  assert.equal(csrfOk(h.request('/api/account/email', { headers: { Origin: 'https://evil.example.test' } }), h.env), false);
  for (const path of ['/api/login/options', '/api/login/verify', '/api/register/verify', '/api/login/password', '/api/register/password', '/api/login/password-reset', '/api/device-link/verify']) {
    assert.equal(csrfOk(h.request(path, { headers: { Origin: 'https://evil.example.test', Authorization: 'Bearer fake' } }), h.env), false, path);
    const native = new Request(ORIGIN + path, { method: 'POST' });
    assert.equal(csrfOk(native, h.env), true, 'no-Origin native ' + path);
  }
  assert.equal(csrfOk(h.request('/api/pair/redeem', { headers: { Origin: 'capacitor://localhost' } }), h.env), true);
});

test('signup defaults closed, and only an explicitly privileged invite grants admin', async t => {
  const h = harness(t, { INVITE_ONLY: undefined });
  assert.equal((await h.call('/api/register/options', { body: { name: 'Ana' } })).status, 403);
  h.invite('ADMIN', 1); h.invite('REGULAR');
  const admin = await h.register(undefined, { code: 'ADMIN' }); assert.equal(admin.body.user.admin, true);
  const regular = await h.register(undefined, { code: 'REGULAR', name: 'Ben' }); assert.equal(regular.body.user.admin, false);
  const denied = await h.call('/api/register/options', { body: { name: 'Other', code: 'ADMIN' } }); assert.equal(denied.status, 403);
  assert.equal(h.DB.raw.prepare('SELECT used_by FROM invites WHERE code=?').get('ADMIN').used_by, admin.body.user.id);
});

test('an open instance never makes its first profile an administrator', async t => {
  const h = harness(t, { INVITE_ONLY: '0' });
  const first = await h.register(undefined, { code: '' }); assert.equal(first.body.user.admin, false);
});

test('valid WebAuthn ceremonies persist across requests and reject challenge replay', async t => {
  const h = harness(t); h.invite(); const registered = await h.register();
  assert.match(registered.cookie, /^__Host-gymsid=/);
  const options = await h.call('/api/login/options'), credential = registered.key.assertion(options.body.options.challenge);
  const body = { cid: options.body.cid, credential };
  const login = await h.call('/api/login/verify', { body }); assert.equal(login.status, 200);
  assert.equal(login.body.user.id, registered.body.user.id);
  assert.equal((await h.call('/api/login/verify', { body })).status, 400);
  assert.equal(h.DB.raw.prepare('SELECT counter,revision FROM credentials').get().revision, 1);
  assert.equal((await h.call('/api/me', { method: 'GET', cookie: login.cookie })).status, 200);
});

test('WebAuthn rejects wrong origin/RP ID and burns each failed challenge', async t => {
  const h = harness(t); h.invite(); const key = softPasskey();
  for (const [origin, rp] of [['https://evil.example.test', 'gym.example.test'], [ORIGIN, 'evil.example.test']]) {
    const opts = await h.call('/api/register/options', { body: { name: 'Ana', code: 'INVITE' } });
    const body = { cid: opts.body.cid, credential: key.attestation(opts.body.options.challenge, origin, rp) };
    assert.equal((await h.call('/api/register/verify', { body })).status, 400);
    assert.equal(h.DB.raw.prepare('SELECT * FROM challenges WHERE id=?').get(opts.body.cid), undefined);
  }
  assert.equal(h.DB.raw.prepare('SELECT count(*) AS n FROM users').get().n, 0);
});

test('challenge kind is bound to its endpoint and expiry is checked', async t => {
  const h = harness(t); h.invite(); const key = softPasskey();
  const options = await h.call('/api/register/options', { body: { name: 'Ana', code: 'INVITE' } });
  const cross = await h.call('/api/login/verify', { body: { cid: options.body.cid, credential: key.assertion(options.body.options.challenge) } });
  assert.equal(cross.status, 400);
  const login = await h.call('/api/login/options');
  h.DB.raw.prepare('UPDATE challenges SET expires=0 WHERE id=?').run(login.body.cid);
  assert.equal((await h.call('/api/login/verify', { body: { cid: login.body.cid } })).status, 400);
});

test('passkey additions require owner proof and sign-out invalidates unfinished additions', async t => {
  const h = harness(t); h.invite(); const owner = await h.register();
  assert.equal((await h.call('/api/account/passkeys/options', { cookie: owner.cookie })).status, 403);
  const opts = await h.call('/api/account/passkeys/options', { cookie: owner.cookie, body: await h.proof(owner.key) });
  assert.equal(opts.status, 200);
  await h.call('/api/logout/all', { cookie: owner.cookie });
  const add = await h.call('/api/account/passkeys/verify', { cookie: owner.cookie, body: { cid: opts.body.cid, credential: softPasskey().attestation(opts.body.options.challenge) } });
  assert.equal(add.status, 401);
  assert.equal(h.DB.raw.prepare('SELECT count(*) AS n FROM credentials').get().n, 1);
});

test('passkey management preserves a last way in and scopes IDs to the owner', async t => {
  const h = harness(t); h.invite(); const owner = await h.register(), other = h.seed('other');
  const removal = await h.call('/api/account/passkeys?id=' + owner.key.id, { method: 'DELETE', cookie: owner.cookie });
  assert.equal(removal.status, 409); assert.equal(removal.body.code, 'last-way-in');
  assert.equal((await h.call('/api/account/passkeys/rename', { cookie: other.cookie, body: { id: owner.key.id, name: 'stolen' } })).status, 404);
  const opts = await h.call('/api/account/passkeys/options', { cookie: owner.cookie, body: await h.proof(owner.key) });
  const second = softPasskey();
  assert.equal((await h.call('/api/account/passkeys/verify', { cookie: owner.cookie, body: { cid: opts.body.cid, credential: second.attestation(opts.body.options.challenge), name: 'Phone\u202E' } })).status, 200);
  const list = await h.call('/api/account/passkeys', { method: 'GET', cookie: owner.cookie });
  assert.equal(list.body.passkeys.length, 2); assert.equal(list.body.passkeys[1].name, 'Phone');
  assert.equal(JSON.stringify(list.body).includes('public_key'), false);
  assert.equal((await h.call('/api/account/passkeys?id=' + second.id, { method: 'DELETE', cookie: owner.cookie, body: await h.proof(owner.key) })).status, 200);
});

test('device-link codes are hashed, single-use, and cannot complete a signup ceremony', async t => {
  const h = harness(t); h.invite(); const owner = await h.register();
  const link = await h.call('/api/account/device-link', { cookie: owner.cookie, body: await h.proof(owner.key) });
  assert.equal(link.status, 200);
  assert.equal(JSON.stringify(h.DB.raw.prepare('SELECT * FROM auth_codes').all()).includes(link.body.code), false);
  const options = await h.call('/api/device-link/options', { body: { code: link.body.code } });
  const key = softPasskey(), body = { cid: options.body.cid, code: link.body.code, credential: key.attestation(options.body.options.challenge) };
  assert.equal((await h.call('/api/register/verify', { body })).status, 400);
  const again = await h.call('/api/device-link/options', { body: { code: link.body.code } });
  const redeemed = await h.call('/api/device-link/verify', { body: { cid: again.body.cid, code: link.body.code, credential: key.attestation(again.body.options.challenge) } });
  assert.equal(redeemed.status, 200); assert.equal(redeemed.body.user.id, owner.body.user.id);
  assert.equal((await h.call('/api/device-link/options', { body: { code: link.body.code } })).status, 400);
});

test('pairing creates bearer sessions once; logout-all also burns unredeemed codes', async t => {
  const h = harness(t), owner = h.seed();
  const pair = await h.call('/api/pair/create', { cookie: owner.cookie });
  const redeemed = await h.call('/api/pair/redeem', { body: pair.body }); assert.equal(redeemed.status, 200);
  assert.equal((await h.call('/api/me', { method: 'GET', headers: { Authorization: 'Bearer ' + redeemed.body.token } })).status, 200);
  assert.equal((await h.call('/api/pair/redeem', { body: pair.body })).status, 400);
  const pending = await h.call('/api/pair/create', { cookie: owner.cookie });
  await h.call('/api/logout/all', { cookie: owner.cookie });
  assert.equal((await h.call('/api/pair/redeem', { body: pending.body })).status, 400);
  assert.equal((await h.call('/api/me', { method: 'GET', headers: { Authorization: 'Bearer ' + redeemed.body.token } })).status, 401);
});

test('full password signup/login/email/change and last-way-in contracts', async t => {
  const h = harness(t); h.invite();
  const created = await h.call('/api/register/password', { body: { name: 'Ana', password: PASSWORD, code: 'INVITE' } });
  assert.equal(created.status, 200, JSON.stringify(created.body));
  const props = await h.call('/api/account/password', { method: 'GET', cookie: created.cookie }); assert.equal(props.body.set, true);
  const login = await h.call('/api/login/password', { body: { identifier: ' ＡＮＡ ', password: PASSWORD } }); assert.equal(login.status, 200);
  assert.equal((await h.call('/api/login/password', { body: { identifier: 'Ana', password: 'incorrect' } })).status, 401);
  assert.equal((await h.call('/api/account/password', { method: 'DELETE', cookie: login.cookie })).status, 409);
  assert.equal((await h.call('/api/account/email', { cookie: login.cookie, body: { email: 'ANA@example.test', current: PASSWORD } })).status, 200);
  assert.equal((await h.call('/api/login/password', { body: { email: 'ana@example.test', password: PASSWORD } })).status, 200);
  // Clear the deliberate account-wide attempt budget between independent assertions.
  h.DB.raw.exec('DELETE FROM rate_limits');
  const change = await h.call('/api/account/password', { cookie: login.cookie, body: { current: PASSWORD, next: 'another strong horse phrase' } });
  assert.equal(change.status, 200); assert.equal((await h.call('/api/me', { method: 'GET', cookie: login.cookie })).status, 401);
  assert.equal((await h.call('/api/me', { method: 'GET', cookie: change.cookie })).status, 200);
});

test('admin reset is one-use, revokes sessions, and cannot target admins', async t => {
  const h = harness(t), admin = h.seed('admin', { admin: 1 }); h.invite();
  const created = await h.call('/api/register/password', { body: { name: 'Ana', password: PASSWORD, code: 'INVITE' } });
  const reset = await h.call('/api/admin/user/password-reset', { cookie: admin.cookie, body: { id: created.body.user.id } });
  assert.equal(reset.status, 200); assert.equal((await h.call('/api/me', { method: 'GET', cookie: created.cookie })).status, 401);
  const body = { identifier: 'Ana', code: reset.body.code, next: 'a completely different password' };
  assert.equal((await h.call('/api/login/password-reset', { body })).status, 200);
  assert.equal((await h.call('/api/login/password-reset', { body })).status, 400);
  assert.equal((await h.call('/api/admin/user/password-reset', { cookie: admin.cookie, body: { id: admin.id } })).status, 400);
});

test('disable/enable never resurrects old sessions or permits disabling admins', async t => {
  const h = harness(t), admin = h.seed('admin', { admin: 1 }), user = h.seed();
  assert.equal((await h.call('/api/admin/user/disable', { cookie: user.cookie, body: { id: admin.id, disabled: true } })).status, 403);
  assert.equal((await h.call('/api/admin/user/disable', { cookie: admin.cookie, body: { id: user.id, disabled: true } })).status, 200);
  assert.equal((await h.call('/api/me', { method: 'GET', cookie: user.cookie })).status, 401);
  await h.call('/api/admin/user/disable', { cookie: admin.cookie, body: { id: user.id, disabled: false } });
  assert.equal((await h.call('/api/me', { method: 'GET', cookie: user.cookie })).status, 401);
});

test('password routes are absent when disabled; orphaned passwords cannot prove ownership', async t => {
  const h = harness(t, { PASSWORD_LOGIN: '0' }), user = h.seed();
  h.DB.raw.prepare('UPDATE users SET pw_hash=? WHERE id=?').run(await hashPassword(PASSWORD), user.id);
  assert.equal(await h.call('/api/login/password'), null);
  assert.equal((await h.call('/api/account/device-link', { cookie: user.cookie, body: { current: PASSWORD } })).body.code, 'passkey-required');
});

test('durable account throttle applies across IP changes and masks unknown identifiers', async t => {
  const h = harness(t), user = h.seed('Ana');
  h.DB.raw.prepare('UPDATE users SET login_name=name_key,pw_hash=? WHERE id=?').run(await hashPassword(PASSWORD), user.id);
  for (let i = 0; i < 5; i++) assert.equal((await h.call('/api/login/password', { body: { name: 'ana', password: 'wrong' } })).status, 401);
  const limited = await h.call('/api/login/password', { body: { name: 'ana', password: PASSWORD } });
  assert.equal(limited.status, 429); assert.ok(Number(limited.headers.get('retry-after')) > 0);
  const unknown = await h.call('/api/login/password', { body: { name: 'nobody', password: 'wrong' } });
  assert.equal(unknown.status, 401); assert.equal(unknown.body.code, 'bad-credentials');
});

test('JSON parser bounds streamed bytes and refuses arrays and malformed bodies', async () => {
  for (const body of ['[]', 'null', '{']) await assert.rejects(readJSON(new Request(ORIGIN, { method: 'POST', body })), e => e.status === 400);
  await assert.rejects(readJSON(new Request(ORIGIN, { method: 'POST', body: JSON.stringify({ x: 'a'.repeat(100) }) }), 32), e => e.status === 413);
});

test('admin invites cannot grant privileges and revoked codes disappear from active list', async t => {
  const h = harness(t), admin = h.seed('admin', { admin: 1 });
  const result = await h.call('/api/admin/invites/new', { cookie: admin.cookie, body: { note: 'Guest', admin: true } });
  assert.equal(result.status, 200);
  assert.equal(h.DB.raw.prepare('SELECT admin FROM invites WHERE code=?').get(result.body.invite.code).admin, 0);
  assert.equal((await h.call('/api/admin/invites/revoke', { cookie: admin.cookie, body: { code: result.body.invite.code } })).status, 200);
  const list = await h.call('/api/admin/invites', { method: 'GET', cookie: admin.cookie });
  assert.deepEqual(list.body.invites, []);
});

test('failed authentication is audited without submitted credentials or identifier', async t => {
  const h = harness(t);
  const response = await h.call('/api/login/password', { body: { name: 'private@example.test', password: 'do-not-save-this-password' } });
  assert.equal(response.status, 401);
  const log = h.DB.raw.prepare('SELECT * FROM audit_events').all();
  assert.equal(log.length, 1); assert.equal(log[0].event, 'auth.password.fail'); assert.equal(log[0].ok, 0);
  assert.equal(JSON.stringify(log).includes('private@example.test'), false);
  assert.equal(JSON.stringify(log).includes('do-not-save-this-password'), false);
});
