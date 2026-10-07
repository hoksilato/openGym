import { spawnSync } from 'node:child_process';
import { copyFileSync, readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
const frontend = fileURLToPath(new URL('../../frontend', import.meta.url));
const result = spawnSync('npm', ['run', 'build'], { cwd: frontend, stdio: 'inherit', env: {
  ...process.env,
  VITE_EXERCISE_MEDIA: process.env.VITE_EXERCISE_MEDIA || 'false',
  VITE_SOURCE_URL: process.env.VITE_SOURCE_URL || 'https://github.com/hoksilato/openGym/tree/feat/cloudflare-free-pwa',
  APP_BUILD: process.env.APP_BUILD || 'cloudflare-free'
} });
if (result.status !== 0) process.exit(result.status || 1);
copyFileSync(new URL('../assets/_headers', import.meta.url), new URL('../../frontend/dist/_headers', import.meta.url));

const manifestFile = new URL('../../frontend/dist/manifest.json', import.meta.url);
const manifest = JSON.parse(readFileSync(manifestFile, 'utf8'));
manifest.id = '/';
writeFileSync(manifestFile, JSON.stringify(manifest, null, 2) + '\n');
