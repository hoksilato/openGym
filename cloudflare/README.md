# Cloudflare Free adapter (draft)

Upstream Node/Docker remains available. This optional deployment uses static assets, a thin
Worker, one SQLite Durable Object, and D1. It targets an invite-only 2–3-person iPhone PWA.
Passkeys and offline revision sync remain first-class; optional password login defaults off.
AI Coach, private media uploads, and exercise-media downloads are disabled in this profile.

See the complete [Vietnamese setup, limits and acceptance guide](../docs/CLOUDFLARE_FREE.vi.md).
No deployment, Cloudflare credential provisioning, billing change, or real-iPhone test has
been performed. Local workerd tests do not prove hosted Free CPU compliance.

```sh
npm ci --prefix frontend
npm ci --prefix cloudflare
npm test --prefix cloudflare
npm run build --prefix cloudflare   # frontend + Wrangler dry-run only
```

Configuration contains explicit placeholders. Run `npm run check:config --prefix cloudflare`
after replacing the permanent origin/RP ID and D1 UUID. Never commit `.dev.vars` or production
secrets. Bootstrap requires an operator-created admin invite, never first-public-user promotion.

This is AGPL-3.0-or-later; preserve LICENSE/NOTICE and point `VITE_SOURCE_URL` at the exact
corresponding source of the deployed fork.
