import { readFileSync } from 'node:fs';
const config = JSON.parse(readFileSync(new URL('../wrangler.jsonc', import.meta.url), 'utf8'));
const origin = new URL(config.vars.ORIGIN);
const problems = [];
if (origin.protocol !== 'https:' || origin.origin !== config.vars.ORIGIN || origin.hostname !== config.vars.RP_ID) problems.push('ORIGIN must be canonical HTTPS, and RP_ID its exact hostname');
if (/YOUR-SUBDOMAIN/i.test(origin.hostname)) problems.push('choose a permanent hostname');
if (config.d1_databases[0].database_id === '00000000-0000-0000-0000-000000000000') problems.push('replace the D1 database UUID');
if (problems.length) { console.error(problems.join('\n')); process.exit(1); }
console.log('Public config valid. This does not verify secrets, migrations, Free quotas, or actual deployment.');
