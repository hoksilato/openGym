/* Cloudflare adapter. All API calls must pass through the single FIFO Durable
 * Object before entering this module. No challenge, code, or session is kept in
 * process memory. WebAuthn verification is exclusively SimpleWebAuthn's. */
import { Buffer } from 'node:buffer';
import { createHmac, randomBytes, scrypt, timingSafeEqual } from 'node:crypto';
import {
  generateRegistrationOptions, verifyRegistrationResponse,
  generateAuthenticationOptions, verifyAuthenticationResponse
} from '@simplewebauthn/server';
import { nameKey, normalizeEmail, passwordProblem, passwordLength } from '../../api/password.js';
import { passkeyName } from '../../api/passkeys-store.js';

const COOKIE = '__Host-gymsid';
const MAX_PASSKEYS = 20;
const CHALLENGE_TTL = 5 * 60000;
const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const SAFE_USER = 'id,name,name_key,login_name,created,sv,admin,disabled,invited_by,email,pw_set,pw_hash IS NOT NULL AS password';
const enabled = value => /^(1|true|yes|on)$/i.test(String(value || ''));
export const inviteOnly = env => env.INVITE_ONLY == null ? true : enabled(env.INVITE_ONLY);
export const passwordEnabled = env => enabled(env.PASSWORD_LOGIN);
export const isAdmin = (user, env = {}) => !!user && (!!user.admin || String(env.ADMIN_UIDS || '').split(',').map(s => s.trim()).includes(user.id));
export const publicUser = user => ({ id: user.id, name: user.name, admin: !!user.admin });
const text = value => typeof value === 'string' ? value : '';
const id = () => randomBytes(18).toString('base64url');
const nowISO = () => new Date().toISOString();
const stmt = (env, sql, ...values) => env.DB.prepare(sql).bind(...values);
const one = (env, sql, ...values) => stmt(env, sql, ...values).first();
const run = (env, sql, ...values) => stmt(env, sql, ...values).run();
const rows = async (env, sql, ...values) => (await stmt(env, sql, ...values).all()).results;
const modified = result => Number(result.meta?.changes || 0);

export function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), { status, headers: {
    'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers
  } });
}
class AuthError extends Error {
  constructor(status, message, code, headers) {
    super(message); this.status = status; this.code = code; this.headers = headers;
  }
}
const fail = (status, message, code) => { throw new AuthError(status, message, code); };
const notSignedIn = () => fail(401, 'not signed in');
const invalidChallenge = () => fail(400, 'challenge expired — try again');
const invalidCode = kind => fail(400, kind === 'reset' ? 'that reset code is wrong or has expired' : 'invalid or expired code', kind === 'reset' ? 'reset-invalid' : kind === 'link' ? 'link-invalid' : undefined);
const passkeyLimit = () => fail(409, `a profile can have at most ${MAX_PASSKEYS} passkeys`, 'passkey-limit');
const wrongPassword = () => fail(401, 'wrong name or password', 'bad-credentials');

export async function readJSON(request, maxBytes = 65536) {
  if (Number(request.headers.get('content-length') || 0) > maxBytes) fail(413, 'request body too large');
  if (!request.body) return {};
  const reader = request.body.getReader(), parts = []; let length = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > maxBytes) { await reader.cancel(); fail(413, 'request body too large'); }
      parts.push(value);
    }
  } finally { reader.releaseLock(); }
  if (!length) return {};
  const data = new Uint8Array(length); let offset = 0;
  for (const part of parts) { data.set(part, offset); offset += part.byteLength; }
  try {
    const body = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(data));
    if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error();
    return body;
  } catch { fail(400, 'invalid JSON body'); }
}

function validateConfig(env) {
  let origin;
  try { origin = new URL(env.ORIGIN); } catch { fail(503, 'authentication is not configured'); }
  if (origin.protocol !== 'https:' || origin.origin !== env.ORIGIN || origin.hostname !== env.RP_ID ||
      typeof env.SESSION_SECRET !== 'string' || env.SESSION_SECRET.length < 32) {
    fail(503, 'authentication is not configured');
  }
}
const sessionDays = env => Math.max(1, Math.min(365, Number(env.SESSION_DAYS) || 90));
const signature = (value, env) => createHmac('sha256', env.SESSION_SECRET).update(value).digest('base64url');
export function makeSession(user, env) {
  validateConfig(env);
  const payload = `${user.id}:${Date.now() + sessionDays(env) * 86400000}:${user.sv}`;
  return `${payload}.${signature(payload, env)}`;
}
function cookieToken(request) {
  const values = (request.headers.get('cookie') || '').split(';').map(s => s.trim())
    .filter(s => s.startsWith(COOKIE + '=')).map(s => s.slice(COOKIE.length + 1));
  if (values.length && values.some(v => v !== values[0])) return { invalid: true };
  return { token: values[0] || null };
}
async function sessionOf(request, env) {
  const cookie = cookieToken(request);
  if (cookie.invalid || typeof env.SESSION_SECRET !== 'string' || env.SESSION_SECRET.length < 32) return null;
  const auth = request.headers.get('authorization') || '';
  const token = cookie.token || (auth.startsWith('Bearer ') ? auth.slice(7).trim() : null);
  if (!token || token.length > 512) return null;
  const match = /^([A-Za-z0-9_-]+):(\d{1,16}):(\d{1,16})\.([A-Za-z0-9_-]{43})$/.exec(token);
  if (!match) return null;
  const expected = signature(token.slice(0, token.lastIndexOf('.')), env);
  if (!timingSafeEqual(Buffer.from(match[4]), Buffer.from(expected))) return null;
  const expires = Number(match[2]), sv = Number(match[3]);
  if (!Number.isSafeInteger(expires) || !Number.isSafeInteger(sv) || expires <= Date.now()) return null;
  const user = await userByID(env, match[1]);
  if (!user || user.disabled || user.sv !== sv) return null;
  return { user, expires, bearer: !cookie.token };
}
async function userByID(env, uid) {
  const user = await one(env, `SELECT ${SAFE_USER} FROM users WHERE id=?`, uid);
  if (!user) return null;
  user.admin = isAdmin(user, env); user.disabled = !!user.disabled; user.password = !!user.password;
  user.invitedBy = user.invited_by;
  return user;
}
export async function getUser(request, env) { return (await sessionOf(request, env))?.user || null; }
const expiredCookie = `${COOKIE}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax`;
const sessionCookie = (user, env) => `${COOKIE}=${makeSession(user, env)}; Path=/; Max-Age=${sessionDays(env) * 86400}; Secure; HttpOnly; SameSite=Lax`;
const signedIn = (user, env) => json({ user: publicUser(user) }, 200, { 'Set-Cookie': sessionCookie(user, env) });

export function csrfOk(request, env) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(request.method)) return true;
  const path = new URL(request.url).pathname;
  // Pair redemption returns a token to a native WebView and never sets a cookie.
  if (request.method === 'POST' && path === '/api/pair/redeem') return true;
  const cookie = cookieToken(request);
  // A signed WebAuthn response authenticates the RP's clientData origin, not the
  // browser submitting this HTTP request. An attacker can carry their own valid
  // assertion to another browser: cookie-setting sign-ins must check its Origin
  // even when it has no cookie yet. A fake Bearer header cannot waive that check.
  const browserAuth = /^\/api\/(login|register|device-link)\//.test(path);
  if (!browserAuth && !cookie.token && !cookie.invalid && (request.headers.get('authorization') || '').startsWith('Bearer ')) return true;
  const origin = request.headers.get('origin'), site = request.headers.get('sec-fetch-site');
  if (origin && origin !== env.ORIGIN) return false;
  if (site && site !== 'same-origin' && site !== 'none') return false;
  return true;
}

// Persisted fixed windows, scoped to an HMAC of Cloudflare's trusted client-IP
// header (never X-Forwarded-For). Account keys are separate from address keys.
async function limitKey(env, key, limit, windowMs) {
  const now = Date.now();
  const digest = signature(`rate:${key}`, env);
  const value = await one(env, `INSERT INTO rate_limits(key,count,expires) VALUES(?,1,?)
    ON CONFLICT(key) DO UPDATE SET count=CASE WHEN rate_limits.expires<=? THEN 1 ELSE rate_limits.count+1 END,
    expires=CASE WHEN rate_limits.expires<=? THEN excluded.expires ELSE rate_limits.expires END RETURNING count,expires`,
  digest, now + windowMs, now, now);
  if (value.count > limit) {
    const seconds = Math.max(1, Math.ceil((value.expires - now) / 1000));
    throw new AuthError(429, 'too many attempts — try again later', 'rate-limit', { 'Retry-After': String(seconds) });
  }
}
export async function rateLimit(request, env, scope = 'api', limit = 120, windowMs = 60000) {
  try {
    await limitKey(env, `${scope}:ip:${request.headers.get('cf-connecting-ip') || 'unknown'}`, limit, windowMs);
    return null;
  } catch (e) { if (e instanceof AuthError) return errorResponse(e); throw e; }
}
async function requireLimit(request, env, scope, limit = 20, window = 60000) {
  await limitKey(env, `${scope}:ip:${request.headers.get('cf-connecting-ip') || 'unknown'}`, limit, window);
}
export async function audit(env, event, actor, target = null, message = null, ok = true) {
  await env.DB.batch([
    stmt(env, `INSERT INTO audit_events(ts,event,actor_id,actor_name,target_id,target_name,message,ok) VALUES(?,?,?,?,?,?,?,?)`,
      Date.now(), event, actor?.id || null, actor?.name || null, target?.id || null, target?.name || null,
      typeof message === 'string' ? message.slice(0, 160) : null, ok ? 1 : 0),
    stmt(env, `DELETE FROM audit_events WHERE id IN (SELECT id FROM audit_events ORDER BY id DESC LIMIT -1 OFFSET 10000)`)
  ]);
}
export async function pruneAuth(env) {
  const now = Date.now();
  await env.DB.batch([
    stmt(env, 'DELETE FROM challenges WHERE expires<=?', now),
    stmt(env, 'DELETE FROM auth_codes WHERE expires<=?', now),
    stmt(env, `UPDATE users SET login_name=NULL WHERE pw_hash IS NULL AND login_name IS NOT NULL
      AND NOT EXISTS(SELECT 1 FROM auth_codes WHERE user_id=users.id AND kind='reset' AND expires>?)`, now),
    stmt(env, 'DELETE FROM rate_limits WHERE expires<=?', now),
    stmt(env, 'DELETE FROM audit_events WHERE ts<?', now - 90 * 86400000)
  ]);
}
async function putChallenge(env, kind, challenge, uid = null, data = {}) {
  const cid = id();
  await run(env, 'INSERT INTO challenges(id,kind,challenge,user_id,data,expires) VALUES(?,?,?,?,?,?)',
    cid, kind, challenge, uid, JSON.stringify(data), Date.now() + CHALLENGE_TTL);
  return cid;
}
async function takeChallenge(env, cid, kind) {
  // Delete-returning is atomic; even an invalid proof spends the challenge.
  const c = await one(env, 'DELETE FROM challenges WHERE id=? RETURNING *', text(cid).slice(0, 128));
  if (!c || c.kind !== kind || c.expires <= Date.now()) invalidChallenge();
  return { ...c, ...JSON.parse(c.data) };
}
const countPasskeys = async (env, uid) => (await one(env, 'SELECT count(*) AS n FROM credentials WHERE user_id=?', uid)).n;
const transports = raw => (Array.isArray(raw) ? raw.filter(t => typeof t === 'string' && t.length <= 16).slice(0, 8) : []);
async function passkeyState(env, user) {
  const list = await rows(env, 'SELECT id,name,created,last_used,transports FROM credentials WHERE user_id=? ORDER BY created,id', user.id);
  const password = passwordEnabled(env) && user.password;
  return { passkeys: list.map(c => ({ id: c.id, name: c.name || null, created: c.created,
    lastUsed: c.last_used || null, transports: JSON.parse(c.transports) })), password,
  lastWayIn: list.length + (password ? 1 : 0) <= 1 };
}
async function registrationOptions(env, user) {
  const creds = await rows(env, 'SELECT id,transports FROM credentials WHERE user_id=?', user.id);
  return generateRegistrationOptions({ rpName: env.RP_NAME || 'openGym', rpID: env.RP_ID,
    userID: new TextEncoder().encode(user.id), userName: user.name, userDisplayName: user.name,
    attestationType: 'none', authenticatorSelection: { residentKey: 'required', userVerification: 'preferred' },
    supportedAlgorithmIDs: [-7, -257],
    excludeCredentials: creds.map(c => ({ id: c.id, transports: JSON.parse(c.transports) })) });
}
async function verifyRegistration(env, c, body) {
  let v;
  try {
    v = await verifyRegistrationResponse({ response: body.credential, expectedChallenge: c.challenge,
      expectedOrigin: env.ORIGIN, expectedRPID: env.RP_ID, requireUserVerification: false });
  } catch { fail(400, 'passkey could not be verified — check the site address and try again'); }
  if (!v.verified || !v.registrationInfo?.credential) fail(400, 'not verified');
  const key = v.registrationInfo.credential;
  if (await one(env, 'SELECT id FROM credentials WHERE id=?', key.id)) fail(409, 'credential already registered', 'credential-exists');
  return { id: key.id, publicKey: Buffer.from(key.publicKey).toString('base64url'), counter: key.counter || 0,
    transports: transports(body.credential?.response?.transports), name: passkeyName(body.name) || null };
}
function insertCredential(env, uid, cred, used = false) {
  const created = nowISO();
  return stmt(env, `INSERT INTO credentials(id,user_id,public_key,counter,transports,name,created,last_used)
    SELECT ?,id,?,?,?,?,?,? FROM users WHERE id=? AND disabled=0`,
  cred.id, cred.publicKey, cred.counter, JSON.stringify(cred.transports), cred.name, created, used ? created : null, uid);
}
async function assertPasskey(env, c, body, owner = null) {
  const credential = await one(env, 'SELECT * FROM credentials WHERE id=?', text(body.credential?.id).slice(0, 2048));
  if (!credential || (owner && credential.user_id !== owner.id)) fail(403, 'the passkey could not be verified', 'passkey');
  const user = await userByID(env, credential.user_id);
  if (!user || user.disabled) fail(403, 'this account has been disabled', 'disabled');
  let v;
  try {
    // A discoverable credential's optional userHandle must refer to its owner.
    const handle = body.credential?.response?.userHandle;
    if (handle && Buffer.from(handle, 'base64url').toString() !== user.id) throw new Error();
    v = await verifyAuthenticationResponse({ response: body.credential, expectedChallenge: c.challenge,
      expectedOrigin: env.ORIGIN, expectedRPID: env.RP_ID, requireUserVerification: false,
      credential: { id: credential.id, publicKey: new Uint8Array(Buffer.from(credential.public_key, 'base64url')),
        counter: credential.counter, transports: JSON.parse(credential.transports) } });
  } catch { fail(403, 'the passkey could not be verified', 'passkey'); }
  if (!v.verified) fail(403, 'the passkey could not be verified', 'passkey');
  const result = await run(env, `UPDATE credentials SET counter=?,last_used=?,revision=revision+1
    WHERE id=? AND revision=? AND counter=? AND EXISTS(SELECT 1 FROM users WHERE id=? AND sv=? AND disabled=0)`,
  v.authenticationInfo.newCounter, nowISO(), credential.id, credential.revision, credential.counter, user.id, user.sv);
  if (modified(result) !== 1) fail(409, 'passkey changed — try again');
  return user;
}

// Preserve upstream scrypt PHC hashes and policy. Unlike upstream's startup dummy
// promise, an unknown account performs one derivation in this request, with no
// cross-request promise or process-memory auth state.
const derive = (pw, salt, N, r, p, length) => new Promise((resolve, reject) => scrypt(pw.normalize('NFKC'), salt, length,
  { N, r, p, maxmem: 128 * N * r * p + 16 * 1024 * 1024 }, (error, key) => error ? reject(error) : resolve(key)));
export async function hashPassword(pw) {
  const salt = randomBytes(16), key = await derive(pw, salt, 32768, 8, 1, 32);
  return `$scrypt$v=1$ln=15,r=8,p=1$${salt.toString('base64')}$${key.toString('base64')}`;
}
async function verifyPassword(pw, stored) {
  if (typeof pw !== 'string' || passwordLength(pw) > 256) return false;
  const match = /^\$scrypt\$v=1\$ln=(\d{1,2}),r=(\d{1,2}),p=(\d{1,2})\$([A-Za-z0-9+/]+=*)\$([A-Za-z0-9+/]+=*)$/.exec(stored || '');
  let valid = !!match, N = 32768, r = 8, p = 1, salt = Buffer.alloc(16), expected = Buffer.alloc(32);
  if (match) {
    N = 2 ** Number(match[1]); r = Number(match[2]); p = Number(match[3]);
    salt = Buffer.from(match[4], 'base64'); expected = Buffer.from(match[5], 'base64');
    valid = N >= 1024 && N <= 65536 && r >= 1 && r <= 16 && p >= 1 && p <= 4 &&
      128 * N * r * p <= 64 * 1024 * 1024 && salt.length >= 8 && salt.length <= 64 && expected.length >= 16 && expected.length <= 64;
    if (!valid) { N = 32768; r = 8; p = 1; salt = Buffer.alloc(16); expected = Buffer.alloc(32); }
  }
  const actual = await derive(pw, salt, N, r, p, expected.length);
  return timingSafeEqual(actual, expected) && valid;
}
function policy(pw, name) {
  const problem = passwordProblem(pw, name);
  if (problem) fail(400, problem === 'too-short' ? 'the password needs at least 10 characters' :
    problem === 'too-long' ? 'the password can have at most 256 characters' : 'this password is too easy to guess', problem);
}
async function nameTaken(env, name, except = '') {
  return !!await one(env, 'SELECT id FROM users WHERE id<>? AND (login_name=? OR email=?)', except, nameKey(name), nameKey(name));
}
async function emailTaken(env, email, except = '') {
  return !!await one(env, 'SELECT id FROM users WHERE id<>? AND (email=? OR login_name=?)', except, email, email);
}
const takenName = () => fail(409, 'another profile already signs in with this name', 'name-taken');
const takenEmail = () => fail(409, 'another profile already uses this e-mail address', 'email-taken');
function validEmail(raw) {
  const email = normalizeEmail(raw);
  if (!email) fail(400, 'that is not an e-mail address', 'email-invalid');
  return email;
}
async function proveOwner(request, env, user, body) {
  if (body.credential) {
    let c;
    try { c = await takeChallenge(env, body.cid, 'login'); } catch { fail(403, 'the passkey could not be verified', 'passkey'); }
    await assertPasskey(env, c, body, user); return 'passkey';
  }
  if (!passwordEnabled(env) || !user.password) fail(403, 'confirm with your passkey first', 'passkey-required');
  const current = text(body.current);
  if (!current) fail(403, 'enter your current password', 'current-required');
  await requireLimit(request, env, 'password');
  await limitKey(env, `password:account:${user.id}`, 5, 60000);
  const record = await one(env, 'SELECT pw_hash FROM users WHERE id=? AND sv=? AND disabled=0', user.id, user.sv);
  if (!record || !await verifyPassword(current, record.pw_hash)) fail(403, 'your current password is not right', 'current-wrong');
  await run(env, 'DELETE FROM rate_limits WHERE key=?', signature(`rate:password:account:${user.id}`, env));
  return 'password';
}
async function ensureSession(request, env, old) {
  const user = await getUser(request, env);
  if (!user || user.id !== old.id || user.sv !== old.sv) notSignedIn();
  return user;
}
function invalidateStatements(env, uid) {
  return [stmt(env, 'DELETE FROM auth_codes WHERE user_id=?', uid), stmt(env, 'DELETE FROM challenges WHERE user_id=?', uid)];
}
async function setPassword(env, user, hash, resetHash = null) {
  const query = `UPDATE users SET pw_hash=?,pw_set=?,login_name=name_key,sv=sv+1 WHERE id=? AND sv=? AND disabled=0` +
    (resetHash ? ` AND EXISTS(SELECT 1 FROM auth_codes WHERE hash=? AND kind='reset' AND user_id=users.id AND sv=users.sv AND expires>?)` : '');
  const args = [hash, nowISO(), user.id, user.sv, ...(resetHash ? [resetHash, Date.now()] : [])];
  const results = await env.DB.batch([stmt(env, query, ...args), ...invalidateStatements(env, user.id)]);
  if (modified(results[0]) !== 1) notSignedIn();
  return userByID(env, user.id);
}
function newCode(length = 12) {
  // Rejection sampling keeps this unbiased if the human-friendly alphabet changes.
  let raw = '';
  while (raw.length < length) {
    for (const n of randomBytes(length)) if (n < Math.floor(256 / ALPHABET.length) * ALPHABET.length && raw.length < length) raw += ALPHABET[n % ALPHABET.length];
  }
  return length === 12 ? `${raw.slice(0, 4)}-${raw.slice(4, 8)}-${raw.slice(8)}` : raw;
}
const cleanCode = code => text(code).toUpperCase().replace(/[^A-Z0-9]/g, '');
const codeHash = (kind, code, env) => signature(`opengym:${kind}:${cleanCode(code)}`, env);
async function storeCode(env, kind, user, ttl) {
  const code = newCode(kind === 'pair' ? 8 : 12), now = Date.now(), expires = now + ttl;
  await run(env, `INSERT INTO auth_codes(hash,kind,user_id,sv,expires,created) VALUES(?,?,?,?,?,?)
    ON CONFLICT(kind,user_id) DO UPDATE SET hash=excluded.hash,sv=excluded.sv,expires=excluded.expires,created=excluded.created`,
  codeHash(kind, code, env), kind, user.id, user.sv, expires, now);
  return { code, expires };
}
async function findCode(env, kind, code) {
  if (cleanCode(code).length !== (kind === 'pair' ? 8 : 12)) return null;
  return one(env, `SELECT c.* FROM auth_codes c JOIN users u ON u.id=c.user_id
    WHERE c.hash=? AND c.kind=? AND c.expires>? AND c.sv=u.sv AND u.disabled=0`, codeHash(kind, code, env), kind, Date.now());
}
async function validInvite(env, code) {
  return one(env, 'SELECT * FROM invites WHERE code=? AND used_by IS NULL AND revoked=0', text(code).trim().toUpperCase());
}
async function requireInvite(env, code) {
  const inv = await validInvite(env, code);
  if (inviteOnly(env) && !inv) fail(403, 'a valid invite code is required', 'invite');
  return inv;
}
async function createUser(env, user, invite, credential = null, pwHash = null, email = null) {
  const created = nowISO();
  const params = [user.id, user.name, nameKey(user.name), pwHash ? nameKey(user.name) : null, created,
    invite?.admin ? 1 : 0, invite?.code || null, email, pwHash, pwHash ? created : null];
  const insert = `INSERT INTO users(id,name,name_key,login_name,created,admin,invited_by,email,pw_hash,pw_set)
    SELECT ?,?,?,?,?,?,?,?,?,?` + (invite ? ' WHERE EXISTS(SELECT 1 FROM invites WHERE code=? AND used_by IS NULL AND revoked=0)' : '');
  if (invite) params.push(invite.code);
  const statements = [stmt(env, insert, ...params)];
  if (credential) statements.push(insertCredential(env, user.id, credential, true));
  if (invite) statements.push(stmt(env, `UPDATE invites SET used_by=?,used_at=? WHERE code=? AND used_by IS NULL AND revoked=0
    AND EXISTS(SELECT 1 FROM users WHERE id=?)`, user.id, created, invite.code, user.id));
  const result = await env.DB.batch(statements);
  if (modified(result[0]) !== 1) fail(403, 'invite code is no longer valid — ask for a new one', 'invite');
  return userByID(env, user.id);
}

const ROUTES = new Set([
  'GET /api/me', 'POST /api/register/options', 'POST /api/register/verify', 'POST /api/login/options', 'POST /api/login/verify',
  'POST /api/logout', 'POST /api/logout/all', 'POST /api/pair/create', 'POST /api/pair/redeem',
  'GET /api/account/passkeys', 'POST /api/account/passkeys/options', 'POST /api/account/passkeys/verify',
  'POST /api/account/passkeys/rename', 'DELETE /api/account/passkeys', 'POST /api/account/device-link',
  'POST /api/device-link/options', 'POST /api/device-link/verify',
  'POST /api/login/password', 'POST /api/register/password', 'GET /api/account/password',
  'POST /api/account/password', 'DELETE /api/account/password', 'POST /api/account/email', 'DELETE /api/account/email',
  'POST /api/admin/user/password-reset', 'POST /api/login/password-reset',
  'POST /api/admin/user/disable', 'GET /api/admin/invites', 'POST /api/admin/invites/new', 'POST /api/admin/invites/revoke'
]);
const PASSWORD_ROUTES = /\/(password(?:-reset)?|email)$/;
function errorResponse(e) { return json({ error: e.message, ...(e.code ? { code: e.code } : {}) }, e.status, e.headers); }

export async function authRoute(request, env) {
  const url = new URL(request.url), path = url.pathname, route = `${request.method} ${path}`;
  if (!ROUTES.has(route) || (PASSWORD_ROUTES.test(path) && !passwordEnabled(env))) return null;
  try {
    validateConfig(env);
    if (!csrfOk(request, env)) fail(403, 'request origin is not allowed');
    const mutates = !['GET', 'HEAD'].includes(request.method);
    if (mutates) await requireLimit(request, env, 'auth', 60);
    const body = mutates ? await readJSON(request) : {};
    let user = null, session = null;
    if (path.startsWith('/api/account/') || path.startsWith('/api/admin/') ||
        ['/api/me', '/api/logout/all', '/api/pair/create'].includes(path)) {
      session = await sessionOf(request, env); user = session?.user;
      if (!user) notSignedIn();
    }
    if (path.startsWith('/api/admin/') && !user.admin) fail(403, 'forbidden');

    switch (route) {
      case 'GET /api/me': {
        const renew = session.bearer && session.expires - Date.now() < sessionDays(env) * 86400000 / 2;
        return json({ user: publicUser(user), ...(renew ? { token: makeSession(user, env) } : {}) });
      }
      case 'POST /api/register/options': {
        await requireLimit(request, env, 'signup', 10);
        const name = text(body.name).trim().slice(0, 40);
        if (!name) fail(400, 'name required');
        const inv = await requireInvite(env, body.code), uid = id();
        const options = await registrationOptions(env, { id: uid, name });
        const cid = await putChallenge(env, 'register', options.challenge, uid, { name, invite: inv?.code || null });
        return json({ cid, options });
      }
      case 'POST /api/register/verify': {
        const c = await takeChallenge(env, body.cid, 'register');
        const cred = await verifyRegistration(env, c, body);
        const inv = await requireInvite(env, c.invite);
        user = await createUser(env, { id: c.user_id, name: c.name }, inv, cred);
        await audit(env, 'auth.register.ok', user); return signedIn(user, env);
      }
      case 'POST /api/login/options': {
        const options = await generateAuthenticationOptions({ rpID: env.RP_ID, userVerification: 'preferred', allowCredentials: [] });
        return json({ cid: await putChallenge(env, 'login', options.challenge), options });
      }
      case 'POST /api/login/verify': {
        const c = await takeChallenge(env, body.cid, 'login');
        user = await assertPasskey(env, c, body);
        await audit(env, 'auth.login.ok', user); return signedIn(user, env);
      }
      case 'POST /api/logout': return json({ ok: true }, 200, { 'Set-Cookie': expiredCookie });
      case 'POST /api/logout/all': {
        await env.DB.batch([stmt(env, 'UPDATE users SET sv=sv+1 WHERE id=?', user.id), ...invalidateStatements(env, user.id)]);
        await audit(env, 'auth.logout.all', user);
        return json({ ok: true }, 200, { 'Set-Cookie': expiredCookie });
      }
      case 'POST /api/pair/create': {
        const code = await storeCode(env, 'pair', user, CHALLENGE_TTL);
        await audit(env, 'auth.pair.create', user); return json({ code: code.code });
      }
      case 'POST /api/pair/redeem': {
        await requireLimit(request, env, 'pair', 10);
        const c = await one(env, `DELETE FROM auth_codes WHERE hash=? AND kind='pair' RETURNING *`, codeHash('pair', body.code, env));
        if (!c || c.expires <= Date.now()) invalidCode('pair');
        user = await userByID(env, c.user_id);
        if (!user || user.disabled || user.sv !== c.sv) invalidCode('pair');
        await audit(env, 'auth.pair.ok', user); return json({ token: makeSession(user, env), user: publicUser(user) });
      }
      case 'GET /api/account/passkeys': return json(await passkeyState(env, user));
      case 'POST /api/account/passkeys/options': {
        if (await countPasskeys(env, user.id) >= MAX_PASSKEYS) passkeyLimit();
        const proof = await proveOwner(request, env, user, body);
        await ensureSession(request, env, user);
        const options = await registrationOptions(env, user);
        const cid = await putChallenge(env, 'add', options.challenge, user.id, { sv: user.sv, proof });
        return json({ cid, options });
      }
      case 'POST /api/account/passkeys/verify': {
        const c = await takeChallenge(env, body.cid, 'add');
        if (c.user_id !== user.id || c.sv !== user.sv) invalidChallenge();
        const cred = await verifyRegistration(env, c, body);
        await ensureSession(request, env, user);
        if (await countPasskeys(env, user.id) >= MAX_PASSKEYS) passkeyLimit();
        await insertCredential(env, user.id, cred).run();
        await audit(env, 'auth.passkey.add', user, null, c.proof);
        return json({ ok: true, ...await passkeyState(env, user) });
      }
      case 'POST /api/account/passkeys/rename': {
        const changed = await run(env, 'UPDATE credentials SET name=? WHERE id=? AND user_id=?', passkeyName(body.name) || null, text(body.id), user.id);
        if (!modified(changed)) fail(404, 'passkey not found', 'not-found');
        return json({ ok: true, ...await passkeyState(env, user) });
      }
      case 'DELETE /api/account/passkeys': {
        const credID = url.searchParams.get('id') || '';
        if (!await one(env, 'SELECT id FROM credentials WHERE id=? AND user_id=?', credID, user.id)) fail(404, 'passkey not found', 'not-found');
        if (await countPasskeys(env, user.id) <= 1 && !(passwordEnabled(env) && user.password)) fail(409, 'this passkey is the only way into this profile', 'last-way-in');
        await proveOwner(request, env, user, body); await ensureSession(request, env, user);
        await env.DB.batch([stmt(env, 'DELETE FROM credentials WHERE id=? AND user_id=?', credID, user.id),
          stmt(env, "DELETE FROM auth_codes WHERE user_id=? AND kind='link'", user.id)]);
        await audit(env, 'auth.passkey.remove', user);
        return json({ ok: true, ...await passkeyState(env, user) });
      }
      case 'POST /api/account/device-link': {
        if (await countPasskeys(env, user.id) >= MAX_PASSKEYS) passkeyLimit();
        const proof = await proveOwner(request, env, user, body); await ensureSession(request, env, user);
        const code = await storeCode(env, 'link', user, 10 * 60000);
        await audit(env, 'auth.link.create', user, null, proof); return json(code);
      }
      case 'POST /api/device-link/options': {
        await requireLimit(request, env, 'link', 10);
        const link = await findCode(env, 'link', body.code); if (!link) invalidCode('link');
        user = await userByID(env, link.user_id);
        if (await countPasskeys(env, user.id) >= MAX_PASSKEYS) passkeyLimit();
        const options = await registrationOptions(env, user);
        const cid = await putChallenge(env, 'link', options.challenge, user.id, { hash: link.hash, sv: user.sv });
        return json({ cid, options, id: user.id, name: user.name });
      }
      case 'POST /api/device-link/verify': {
        await requireLimit(request, env, 'link', 10);
        const c = await takeChallenge(env, body.cid, 'link'), link = await findCode(env, 'link', body.code);
        if (!link || c.hash !== link.hash || c.user_id !== link.user_id || c.sv !== link.sv) invalidCode('link');
        const cred = await verifyRegistration(env, c, body);
        user = await userByID(env, link.user_id);
        if (await countPasskeys(env, user.id) >= MAX_PASSKEYS) passkeyLimit();
        // A transaction inserts the key and consumes the code together. The DO's
        // FIFO prevents another ceremony interleaving between validation and batch.
        await env.DB.batch([insertCredential(env, user.id, cred, true), stmt(env, 'DELETE FROM auth_codes WHERE hash=?', link.hash)]);
        await audit(env, 'auth.link.ok', user); return signedIn(user, env);
      }
      case 'POST /api/login/password': {
        const identifier = nameKey(text(body.identifier ?? body.name ?? body.email).slice(0, 300));
        if (!identifier || !text(body.password)) fail(400, 'name and password required', 'missing');
        await requireLimit(request, env, 'password');
        const onlyEmail = body.identifier === undefined && body.name === undefined;
        let record = identifier.includes('@') ? await one(env, 'SELECT * FROM users WHERE email=? AND pw_hash IS NOT NULL', identifier) : null;
        if (!record && !onlyEmail) record = await one(env, 'SELECT * FROM users WHERE login_name=? AND pw_hash IS NOT NULL', identifier);
        await limitKey(env, `password:${record ? 'account:' + record.id : 'identifier:' + identifier}`, 5, 60000);
        if (!await verifyPassword(body.password, record?.pw_hash)) wrongPassword();
        user = await userByID(env, record.id);
        if (!user || user.sv !== record.sv) wrongPassword();
        if (user.disabled) fail(403, 'this account has been disabled', 'disabled');
        if (!record.pw_hash.startsWith('$scrypt$v=1$ln=15,r=8,p=1$')) {
          const hash = await hashPassword(body.password);
          const updated = await run(env, 'UPDATE users SET pw_hash=? WHERE id=? AND sv=? AND pw_hash=?', hash, user.id, user.sv, record.pw_hash);
          if (modified(updated) !== 1) wrongPassword();
        }
        await run(env, 'DELETE FROM rate_limits WHERE key=?', signature(`rate:password:account:${user.id}`, env));
        await audit(env, 'auth.password.ok', user); return signedIn(user, env);
      }
      case 'POST /api/register/password': {
        await requireLimit(request, env, 'signup', 10);
        const name = text(body.name).trim().slice(0, 40);
        if (!name) fail(400, 'name required', 'missing');
        await requireInvite(env, body.code); policy(body.password, name);
        if (await nameTaken(env, name)) takenName();
        const email = text(body.email).trim() ? validEmail(body.email) : null;
        const hash = await hashPassword(body.password), inv = await requireInvite(env, body.code);
        if (email && await emailTaken(env, email)) takenEmail();
        user = await createUser(env, { id: id(), name }, inv, null, hash, email);
        await audit(env, 'auth.register.ok', user, null, 'password'); return signedIn(user, env);
      }
      case 'GET /api/account/password': return json({ set: user.password, setAt: user.pw_set || null,
        passkeys: await countPasskeys(env, user.id), name: user.name, nameTaken: await nameTaken(env, user.name, user.id), email: user.email || null });
      case 'POST /api/account/password': {
        policy(body.next, user.name);
        if (await nameTaken(env, user.name, user.id)) takenName();
        await proveOwner(request, env, user, body);
        const hash = await hashPassword(body.next); await ensureSession(request, env, user);
        user = await setPassword(env, user, hash); await audit(env, 'auth.password.set', user);
        return session.bearer ? json({ ok: true, token: makeSession(user, env) }) : json({ ok: true }, 200, { 'Set-Cookie': sessionCookie(user, env) });
      }
      case 'DELETE /api/account/password': {
        if (!user.password) return json({ ok: true });
        if (!await countPasskeys(env, user.id)) fail(409, 'the password is the only way into this profile', 'last-way-in');
        await proveOwner(request, env, user, body); await ensureSession(request, env, user);
        await run(env, 'UPDATE users SET pw_hash=NULL,pw_set=NULL,login_name=NULL WHERE id=?', user.id);
        await audit(env, 'auth.password.remove', user); return json({ ok: true });
      }
      case 'POST /api/account/email':
      case 'DELETE /api/account/email': {
        const email = request.method === 'DELETE' || body.email == null || (typeof body.email === 'string' && body.email.trim() === '') ? null : validEmail(body.email);
        if (email === user.email || (!email && !user.email)) return json({ ok: true, email });
        await proveOwner(request, env, user, body); await ensureSession(request, env, user);
        if (email && await emailTaken(env, email, user.id)) takenEmail();
        await run(env, 'UPDATE users SET email=? WHERE id=?', email, user.id);
        await audit(env, email ? 'auth.email.set' : 'auth.email.remove', user); return json({ ok: true, email });
      }
      case 'POST /api/admin/user/password-reset': {
        const target = await userByID(env, text(body.id));
        if (!target) fail(404, 'no such user');
        if (target.admin) fail(400, 'an admin sets their own password in Settings');
        if (await nameTaken(env, target.name, target.id)) takenName();
        const code = newCode(), expires = Date.now() + 86400000;
        await env.DB.batch([stmt(env, 'UPDATE users SET pw_hash=NULL,pw_set=NULL,login_name=name_key,sv=sv+1 WHERE id=?', target.id),
          ...invalidateStatements(env, target.id),
          stmt(env, 'INSERT INTO auth_codes(hash,kind,user_id,sv,expires,created) VALUES(?,?,?,?,?,?)',
            codeHash('reset', code, env), 'reset', target.id, target.sv + 1, expires, Date.now())]);
        await audit(env, 'admin.password.reset', user, target); return json({ ok: true, name: target.name, code, expires });
      }
      case 'POST /api/login/password-reset': {
        await requireLimit(request, env, 'reset', 10);
        const identifier = nameKey(text(body.identifier ?? body.name ?? body.email).slice(0, 300));
        if (!identifier || !text(body.code)) fail(400, 'name and code required', 'missing');
        const reset = await findCode(env, 'reset', body.code); if (!reset) invalidCode('reset');
        user = await userByID(env, reset.user_id);
        if (!user || (user.name_key !== identifier && user.email !== identifier)) invalidCode('reset');
        policy(body.next, user.name); if (await nameTaken(env, user.name, user.id)) takenName();
        user = await setPassword(env, user, await hashPassword(body.next), reset.hash);
        await audit(env, 'auth.password.reset', user); return signedIn(user, env);
      }
      case 'POST /api/admin/user/disable': {
        const target = await userByID(env, text(body.id)); if (!target) fail(404, 'no such user');
        if (target.admin) fail(400, 'cannot disable an admin');
        const disabled = !!body.disabled;
        await env.DB.batch([stmt(env, 'UPDATE users SET disabled=?,sv=sv+? WHERE id=?', disabled ? 1 : 0, disabled ? 1 : 0, target.id),
          ...(disabled ? invalidateStatements(env, target.id) : [])]);
        await audit(env, disabled ? 'admin.user.disable' : 'admin.user.enable', user, target);
        return json({ ok: true, id: target.id, disabled });
      }
      case 'GET /api/admin/invites': {
        const invites = await rows(env, `SELECT i.*,u.name AS used_by_name FROM invites i LEFT JOIN users u ON i.used_by=u.id WHERE i.revoked=0 ORDER BY i.created`);
        return json({ invites: invites.map(i => ({ code: i.code, note: i.note, createdBy: i.created_by, created: i.created,
          usedBy: i.used_by, usedAt: i.used_at, usedByName: i.used_by_name, revoked: !!i.revoked })), invite_only: inviteOnly(env) });
      }
      case 'POST /api/admin/invites/new': {
        const invite = { code: randomBytes(12).toString('hex').toUpperCase(), note: text(body.note).slice(0, 60), createdBy: user.id, created: nowISO() };
        // Public administration cannot create an admin invite. Only the operator
        // can seed one using authenticated D1 tooling during bootstrap.
        await run(env, 'INSERT INTO invites(code,note,created_by,created) VALUES(?,?,?,?)', invite.code, invite.note, user.id, invite.created);
        await audit(env, 'admin.invite.create', user); return json({ invite });
      }
      case 'POST /api/admin/invites/revoke': {
        const code = text(body.code).trim().toUpperCase(), inv = await one(env, 'SELECT * FROM invites WHERE code=?', code);
        if (!inv) fail(404, 'no such code'); if (inv.used_by) fail(400, 'already used — cannot revoke');
        await run(env, 'UPDATE invites SET revoked=1 WHERE code=?', code);
        await audit(env, 'admin.invite.revoke', user); return json({ ok: true });
      }
      default: return null;
    }
  } catch (e) {
    if (e instanceof AuthError) {
      if ([400, 401, 403, 409].includes(e.status)) {
        // Throttled separately: invalid proofs must not flood the audit. Never
        // retain the submitted identifier, code, credential or exception text.
        const event = path.startsWith('/api/admin/') ? 'admin.denied' :
          path.startsWith('/api/register/') ? 'auth.register.fail' :
          path.includes('password') ? 'auth.password.fail' :
          path.startsWith('/api/login/') ? 'auth.login.fail' :
          path.includes('device-link') ? 'auth.link.fail' :
          path.startsWith('/api/pair/') ? 'auth.pair.fail' :
          path.startsWith('/api/account/') ? 'auth.proof.fail' : null;
        if (event) {
          try {
            await requireLimit(request, env, 'audit-failure', 10);
            await audit(env, event, await getUser(request, env), null, e.code || 'request-rejected', false);
          } catch { /* Audit availability must not change the authentication result. */ }
        }
      }
      return errorResponse(e);
    }
    // Never echo verifier/SQLite errors: they may contain untrusted credential
    // contents or password/email data. Only a stable, non-sensitive server code.
    console.error('auth request failed');
    return json({ error: 'authentication service unavailable — try again', code: 'auth-unavailable' }, 503);
  }
}
