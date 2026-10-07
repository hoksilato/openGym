import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('deployment profile stays on explicitly bound Free-compatible resources', async () => {
  const config = JSON.parse(await readFile(new URL('../wrangler.jsonc', import.meta.url), 'utf8'));
  assert.deepEqual(config.assets.run_worker_first, ['/api', '/api/*']);
  assert.equal(config.assets.not_found_handling, 'none');
  assert.equal(config.preview_urls, false);
  assert.deepEqual(config.migrations[0].new_sqlite_classes, ['OpenGym']);
  assert.equal(config.vars.INVITE_ONLY, '1'); assert.equal(config.vars.ALLOW_GUEST, '0');
  assert.equal(config.vars.PASSWORD_LOGIN, '0');
  assert.equal(config.vars.SESSION_SECRET, undefined);
  for (const binding of ['r2_buckets', 'containers', 'queues', 'ai']) assert.equal(config[binding], undefined);
  assert.equal(config.d1_databases.length, 1);
});
test('Cloudflare static policy retains security headers and service-worker revalidation', async () => {
  const headers = await readFile(new URL('../assets/_headers', import.meta.url), 'utf8');
  for (const value of ['X-Content-Type-Options: nosniff', 'X-Frame-Options: DENY', "frame-ancestors 'none'", '/sw.js\n  Cache-Control: no-cache']) assert.ok(headers.includes(value));
  const build = await readFile(new URL('../scripts/build-frontend.mjs', import.meta.url), 'utf8');
  assert.match(build, /VITE_EXERCISE_MEDIA/); assert.match(build, /VITE_SOURCE_URL/);
  assert.match(build, /manifest\.id = '\/'/);
});
