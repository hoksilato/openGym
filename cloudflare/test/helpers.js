import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { readFile, readdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { createHmac } from 'node:crypto';
export const TEST_SECRET = 'test-only-session-secret-not-for-deployment-0123456789';
export const sessionToken = (uid, sv = 0, secret = TEST_SECRET) => {
  const body = `${uid}:${Date.now() + 86400000}:${sv}`;
  return `${body}.${createHmac('sha256', secret).update(body).digest('base64url')}`;
};
export const cookieFor = (uid, sv = 0, secret = TEST_SECRET) => `__Host-gymsid=${sessionToken(uid, sv, secret)}`;
export async function createHarness({ bindings = {}, fetchMock, persistPath, ...options } = {}) {
  const miniflareOptions = convertV4MiniflareOptions({
    modules: true,
    scriptPath: fileURLToPath(new URL('../.test-bundle/worker.js', import.meta.url)),
    compatibilityDate: '2026-10-01', compatibilityFlags: ['nodejs_compat'],
    bindings: { SESSION_SECRET: TEST_SECRET, ORIGIN: 'https://gym.example', RP_ID: 'gym.example',
      RP_NAME: 'openGym', INVITE_ONLY: '1', ALLOW_GUEST: '0', PASSWORD_LOGIN: '0', ...bindings },
    d1Databases: { DB: 'opengym-test' },
    durableObjects: { APP: { className: 'OpenGym', useSQLite: true } },
    ...(persistPath ? { d1Persist: persistPath + '/d1', durableObjectsPersist: persistPath + '/do' } : {}),
    ...(fetchMock ? { fetchMock } : {}), ...options
  });
  if (persistPath) miniflareOptions.resourcePersistencePath = persistPath;
  const mf = new Miniflare(miniflareOptions);
  let db = await mf.getD1Database('DB');
  if (!persistPath || !(await db.prepare("SELECT name FROM sqlite_master WHERE name='users'").first())) {
    const directory = new URL('../migrations/', import.meta.url);
    for (const file of (await readdir(directory)).filter(x => x.endsWith('.sql')).sort()) {
      const sql = await readFile(new URL(file, directory), 'utf8');
      // Statements contain no semicolons inside string literals; D1 exec needs one line/statement.
      await db.exec(sql.replace(/--[^\n]*/g, '').split(';').map(s => s.trim().replace(/\s+/g, ' ')).filter(Boolean).join(';\n'));
    }
  }
  return { mf, get db() { return db; },
    async seedUser(id = 'alice', { admin = false, disabled = false } = {}) {
      await db.prepare('INSERT INTO users(id,name,name_key,created,admin,disabled) VALUES(?,?,?,?,?,?)')
        .bind(id, id, id.toLowerCase(), new Date().toISOString(), Number(admin), Number(disabled)).run();
      return cookieFor(id);
    },
    request(path, { body, headers, method, ...init } = {}) {
      return mf.dispatchFetch('https://gym.example' + path, { ...init, method: method || (body === undefined ? 'GET' : 'POST'),
        headers: { Origin: 'https://gym.example', ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), ...headers },
        ...(body === undefined ? {} : { body: typeof body === 'string' ? body : JSON.stringify(body) }) });
    },
    async reload() {
      await mf.setOptions(miniflareOptions);
      db = await mf.getD1Database('DB');
    },
    close: () => mf.dispose()
  };
}
