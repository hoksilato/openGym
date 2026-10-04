# Local verification: 4 October 2026

Base: upstream openGym `1350409a7b15ff8ce5690c18b530cfba62d80f46` (v1.3.9).
Runtime: Linux, Node 24.19.0, npm 11.9.0. Tests run with `TZ=UTC` to match GitHub runners.
No Cloudflare deployment or production-secret provisioning was performed.

## Passed

| Check | Result |
| --- | --- |
| Cloudflare adapter `npm test --prefix cloudflare` | 47/47 |
| Frontend `npm test --prefix frontend` | 3,183/3,183 across 258 files |
| Upstream Node API `npm test --prefix api` | 473/473 |
| MCP `npm test --prefix mcp` | 63/63 |
| MCP Node-loadable check | Passed |
| Coach generated-asset consistency and core Node-loadability | Passed |
| Locale check | 16 packs, 1,703 keys each, synchronized |
| Source-string check | 1,342 strings present in packs |
| Fatigue monotonicity | 108,000 comparisons, no increase |
| History-edit probe | 14,076 comparisons, non-increasing |
| Frontend production build + Wrangler dry-run | Passed; 75 static assets |
| Worker bundle | 985.82 KiB raw, 186.35 KiB gzip |
| Manifest / service worker | standalone, root id `/`, build stamp resolved |
| Production Cloudflare dependency audit | 0 reported advisories at time of check |
| `git diff --check` | Passed |

Wrangler and Miniflare use Cloudflare's actual workerd runtime locally. The adapter tests
include real WebAuthn ES256 registration/assertion validation, scrypt flows, durable D1 state,
encrypted RFC8291 Web Push with VAPID signature verification, and actual Durable Object alarms.
Outbound push traffic is replaced with a test-only capture service; no live device was contacted.

## Critical regressions covered

- Multi-user isolation; stale-tab/account-switch responses cannot merge or push another account's data
- Request UID binding on state writes; response UID check in current clients
- Single-use, kind-bound, expiring challenges and hashed pairing/device-link/reset codes
- Pending challenges/pair codes survive complete runtime disposal and recreation
- Explicit wrong request Origin rejected even when a submitted WebAuthn assertion is valid
- Last-login-method protection, owner proof, disabled-user/session-version revocation and admin invite bootstrap
- D1 concurrent compare-and-swap remains safe even when called without the DO FIFO
- A failed publication batch rolls back every chunk; a 4 MiB state imports/reads correctly
- Compact admin roster handles 16 users without loading full workout documents per person
- Push endpoint validation, redirect refusal, subscription/device ownership and expired endpoint cleanup
- Rest alarm survives reload and complete process recreation, with one provider attempt
- Reminder timezone/DST behavior, completion/rest-day skip and durable local-day deduplication
- No paid resource bindings; missing VAPID and disabled AI/media return explicit API behavior

An existing Hevy test assumed UTC timestamps always shared a local calendar date. It was
confirmed to fail unchanged in UTC+7 and pass in UTC, then made timezone-independent without
changing import logic. The upstream MCP fixture also assumes UTC; its unchanged suite passes
under UTC. No Docker binary was available, so Docker image build/boot jobs were not run locally.

## Still requires a real environment

- GitHub CI against the published commit (not inferred from local tests)
- Hosted Cloudflare Free CPU, memory, quota and latency measurements
- Actual HTTPS hostname/RP ID, D1 creation/migrations and operator bootstrap
- Real iPhone Safari/standalone passkey and offline/reconnect acceptance tests
- User-granted Home Screen notification permission and real Apple push delivery
- Backup/export/restore rehearsal using operator-owned deployment data

Push is best effort with at-most-once provider attempts, not a guaranteed iOS alarm. The UI
countdown is not restored after process kill. Private media uploads, AI, and unverified
exercise media redistribution are deliberately excluded from this initial Free profile.
