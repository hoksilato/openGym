import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHarness, cookieFor } from './helpers.js';

const ORIGIN = 'https://gym.example';
const sha = b => crypto.createHash('sha256').update(b).digest();
const b64 = b => Buffer.from(b).toString('base64url');
const head = (major, n) => n < 24 ? Buffer.from([(major << 5) | n]) : n < 256 ? Buffer.from([(major << 5) | 24, n]) : Buffer.from([(major << 5) | 25, n >> 8, n & 255]);
const str = s => Buffer.concat([head(3, Buffer.byteLength(s)), Buffer.from(s)]);
function authenticator() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = publicKey.export({ format: 'jwk' });
  const cose = Buffer.concat([Buffer.from([0xa5, 1, 2, 3, 0x26, 0x20, 1, 0x21, 0x58, 0x20]), Buffer.from(jwk.x, 'base64url'),
    Buffer.from([0x22, 0x58, 0x20]), Buffer.from(jwk.y, 'base64url')]);
  const raw = crypto.randomBytes(16), id = b64(raw); let counter = 0;
  return {
    id,
    create(challenge, origin = ORIGIN, rp = 'gym.example') {
      const client = Buffer.from(JSON.stringify({ type: 'webauthn.create', challenge, origin, crossOrigin: false }));
      const auth = Buffer.concat([sha(rp), Buffer.from([0x45]), Buffer.alloc(4), Buffer.alloc(16), Buffer.from([0, raw.length]), raw, cose]);
      const attestation = Buffer.concat([Buffer.from([0xa3]), str('fmt'), str('none'), str('attStmt'), Buffer.from([0xa0]), str('authData'), head(2, auth.length), auth]);
      return { id, rawId: id, type: 'public-key', clientExtensionResults: {}, response: { clientDataJSON: b64(client), attestationObject: b64(attestation), transports: ['internal'] } };
    },
    get(challenge, origin = ORIGIN) {
      const client = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin, crossOrigin: false }));
      const c = Buffer.alloc(4); c.writeUInt32BE(++counter);
      const auth = Buffer.concat([sha('gym.example'), Buffer.from([0x05]), c]);
      const signature = crypto.sign('sha256', Buffer.concat([auth, sha(client)]), privateKey);
      return { id, rawId: id, type: 'public-key', clientExtensionResults: {}, response: { clientDataJSON: b64(client), authenticatorData: b64(auth), signature: b64(signature), userHandle: null } };
    }
  };
}
async function call(h, path, body, cookie, method = body === undefined ? 'GET' : 'POST') {
  const response = await h.request(path, { body, method, headers: cookie ? { Cookie: cookie } : {} });
  return { status: response.status, data: await response.json(), cookie: response.headers.get('set-cookie')?.split(';')[0] };
}
const invite = (h, code = 'FIRST', admin = 0) => h.db.prepare('INSERT INTO invites(code,created,admin) VALUES(?,?,?)').bind(code, new Date().toISOString(), admin).run();
async function register(h, key, code = 'FIRST', name = 'Ana') {
  const start = await call(h, '/api/register/options', { code, name }); assert.equal(start.status, 200, JSON.stringify(start.data));
  const result = await call(h, '/api/register/verify', { cid: start.data.cid, credential: key.create(start.data.options.challenge) });
  assert.equal(result.status, 200, JSON.stringify(result.data)); return result;
}
async function proof(h, key) {
  const result = await call(h, '/api/login/options', {});
  return { cid: result.data.cid, credential: key.get(result.data.options.challenge) };
}

test('workerd verifies real passkeys, device-link additions, owner proof and logout revocation', async t => {
  const h = await createHarness(); t.after(() => h.close()); await invite(h, 'FIRST', 1);
  const key = authenticator(), created = await register(h, key);
  assert.equal(created.data.user.admin, true);
  const login = await call(h, '/api/login/verify', await proof(h, key)); assert.equal(login.status, 200, JSON.stringify(login.data));
  const add = await call(h, '/api/account/passkeys/options', await proof(h, key), login.cookie);
  assert.equal(add.status, 200, JSON.stringify(add.data));
  const second = authenticator();
  const added = await call(h, '/api/account/passkeys/verify', { cid: add.data.cid, credential: second.create(add.data.options.challenge), name: 'Phone' }, login.cookie);
  assert.equal(added.status, 200, JSON.stringify(added.data)); assert.equal(added.data.passkeys.length, 2);
  const link = await call(h, '/api/account/device-link', await proof(h, second), login.cookie);
  assert.equal(link.status, 200, JSON.stringify(link.data));
  const options = await call(h, '/api/device-link/options', { code: link.data.code });
  const third = authenticator();
  const linked = await call(h, '/api/device-link/verify', { cid: options.data.cid, code: link.data.code, credential: third.create(options.data.options.challenge) });
  assert.equal(linked.status, 200, JSON.stringify(linked.data)); assert.equal(linked.data.user.id, created.data.user.id);
  assert.equal((await call(h, '/api/device-link/options', { code: link.data.code })).status, 400);
  const pair = await call(h, '/api/pair/create', {}, linked.cookie);
  assert.equal((await call(h, '/api/logout/all', {}, login.cookie)).status, 200);
  assert.equal((await call(h, '/api/me', undefined, linked.cookie)).status, 401);
  assert.equal((await call(h, '/api/pair/redeem', pair.data)).status, 400);
});

test('workerd scrypt supports password signup, email login, changing password and admin resets', async t => {
  const h = await createHarness({ bindings: { PASSWORD_LOGIN: '1' } }); t.after(() => h.close());
  await invite(h); const admin = await h.seedUser('admin', { admin: true });
  const pw = 'correct horse battery staple';
  const created = await call(h, '/api/register/password', { code: 'FIRST', name: 'Ana', password: pw, email: 'ana@example.test' });
  assert.equal(created.status, 200, JSON.stringify(created.data));
  const login = await call(h, '/api/login/password', { identifier: 'ana@example.test', password: pw });
  assert.equal(login.status, 200, JSON.stringify(login.data));
  const change = await call(h, '/api/account/password', { current: pw, next: 'another long strong phrase' }, login.cookie);
  assert.equal(change.status, 200, JSON.stringify(change.data));
  assert.equal((await call(h, '/api/me', undefined, login.cookie)).status, 401);
  const reset = await call(h, '/api/admin/user/password-reset', { id: created.data.user.id }, admin);
  assert.equal(reset.status, 200, JSON.stringify(reset.data));
  const body = { identifier: 'Ana', code: reset.data.code, next: 'a third very long password' };
  assert.equal((await call(h, '/api/login/password-reset', body)).status, 200);
  assert.equal((await call(h, '/api/login/password-reset', body)).status, 400);
  assert.equal((await call(h, '/api/admin/user', undefined, admin, 'GET')).status, 404);
});

test('workerd atomically consumes concurrent challenge replays and rejects wrong origins', async t => {
  const h = await createHarness(); t.after(() => h.close()); await invite(h); const key = authenticator();
  const created = await register(h, key);
  const assertion = await proof(h, key);
  const results = await Promise.all([call(h, '/api/login/verify', assertion), call(h, '/api/login/verify', assertion)]);
  assert.deepEqual(results.map(r => r.status).sort(), [200, 400]);
  const options = await call(h, '/api/login/options', {});
  const failed = await call(h, '/api/login/verify', { cid: options.data.cid, credential: key.get(options.data.options.challenge, 'https://evil.example') });
  assert.equal(failed.status, 403);
  const forged = await h.request('/api/logout/all', { body: {}, headers: { Cookie: created.cookie, Origin: 'https://evil.example', Authorization: 'Bearer fake' } });
  assert.equal(forged.status, 403);
  const still = await call(h, '/api/me', undefined, created.cookie); assert.equal(still.status, 200);
});

test('workerd persists pending challenges and pair codes across a full isolate restart', async t => {
  const persistPath = await mkdtemp(join(tmpdir(), 'opengym-auth-'));
  let h = await createHarness({ persistPath });
  t.after(async () => { await h.close(); await rm(persistPath, { recursive: true, force: true }); });
  await invite(h); const key = authenticator(), created = await register(h, key);
  const options = await call(h, '/api/login/options', {}), pair = await call(h, '/api/pair/create', {}, created.cookie);
  const before = await h.db.prepare('SELECT id,kind,expires FROM challenges WHERE id=?').bind(options.data.cid).first();
  assert.ok(before, JSON.stringify(options));
  await h.close(); h = await createHarness({ persistPath });
  const after = await h.db.prepare('SELECT id,kind,expires FROM challenges WHERE id=?').bind(options.data.cid).first();
  assert.deepEqual(after, before, 'D1 pending challenge survives process restart: users=' + JSON.stringify(await h.db.prepare('SELECT id FROM users').all()));
  const login = await call(h, '/api/login/verify', { cid: options.data.cid, credential: key.get(options.data.options.challenge) });
  assert.equal(login.status, 200, JSON.stringify(login.data));
  const paired = await call(h, '/api/pair/redeem', pair.data); assert.equal(paired.status, 200, JSON.stringify(paired.data));
  assert.equal(paired.data.user.id, created.data.user.id);
});

test('workerd rejects login CSRF using a valid attacker assertion in a cross-site form', async t => {
  const h = await createHarness(); t.after(() => h.close()); await invite(h);
  const key = authenticator(); await register(h, key);
  const assertion = await proof(h, key);
  for (const headers of [
    { Origin: 'https://evil.example', 'Sec-Fetch-Site': 'cross-site', 'Content-Type': 'text/plain' },
    { Origin: 'https://evil.example', Authorization: 'Bearer fake', 'Content-Type': 'application/json' },
    { Origin: ORIGIN, 'Sec-Fetch-Site': 'same-site', 'Content-Type': 'text/plain' }
  ]) {
    const response = await h.request('/api/login/verify', { body: assertion, headers });
    assert.equal(response.status, 403);
    assert.equal(response.headers.has('set-cookie'), false);
  }
  // Reject at the HTTP-origin guard before spending the credential's challenge.
  const valid = await call(h, '/api/login/verify', assertion);
  assert.equal(valid.status, 200, JSON.stringify(valid.data));
});

test('workerd checks incoming Origin for registration and device-link cookie creation', async t => {
  const h = await createHarness(); t.after(() => h.close()); await invite(h);
  const key = authenticator(), options = await call(h, '/api/register/options', { code: 'FIRST', name: 'Ana' });
  const body = { cid: options.data.cid, credential: key.create(options.data.options.challenge) };
  const rejected = await h.request('/api/register/verify', { body, headers: { Origin: 'https://evil.example', 'Content-Type': 'text/plain' } });
  assert.equal(rejected.status, 403); assert.equal(rejected.headers.has('set-cookie'), false);
  const created = await call(h, '/api/register/verify', body); assert.equal(created.status, 200);
  const link = await call(h, '/api/account/device-link', await proof(h, key), created.cookie);
  const linkOptions = await call(h, '/api/device-link/options', { code: link.data.code });
  const next = authenticator(), linkedBody = { cid: linkOptions.data.cid, code: link.data.code, credential: next.create(linkOptions.data.options.challenge) };
  const linkRejected = await h.request('/api/device-link/verify', { body: linkedBody, headers: { Origin: 'https://evil.example', Authorization: 'Bearer fake' } });
  assert.equal(linkRejected.status, 403); assert.equal(linkRejected.headers.has('set-cookie'), false);
  assert.equal((await call(h, '/api/device-link/verify', linkedBody)).status, 200);
});

test('workerd retains no-Origin native authentication and cross-origin token-only pairing', async t => {
  const h = await createHarness(); t.after(() => h.close()); await invite(h);
  const key = authenticator(), created = await register(h, key);
  const assertion = await proof(h, key);
  const native = await h.mf.dispatchFetch(ORIGIN + '/api/login/verify', { method: 'POST',
    headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(assertion) });
  assert.equal(native.status, 200, await native.text());
  const pair = await call(h, '/api/pair/create', {}, created.cookie);
  const redeemed = await h.request('/api/pair/redeem', { body: pair.data, headers: { Origin: 'capacitor://localhost', 'Sec-Fetch-Site': 'cross-site' } });
  assert.equal(redeemed.status, 200); assert.equal(redeemed.headers.has('set-cookie'), false);
  assert.ok((await redeemed.json()).token);
});
