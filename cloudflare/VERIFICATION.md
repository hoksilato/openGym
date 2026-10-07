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

## Re-review: 6 October 2026

Reviewed the actual cloud checkout of `feat/cloudflare-free-pwa` at `f102d18` and
re-ran the adapter, upstream API, MCP and frontend checks. The review found and fixed:

- A stale tab joining the account already installed by another tab could erase that
  account's unsynced saved copy. It now loads that copy with its own dirty/revision
  markers, while keeping the previous account's owed changes separate.
- A sign-out waiting for sync, a stash or a logout response could resume after an
  account switch and wipe the next account's copy. Both sign-out variants now check
  the initiating session across asynchronous boundaries.
- A stale signed-in tab could save its previous account's state after another tab
  removed the owner during logout. That ownerless copy could then be mistaken for
  guest data at a new registration. Signed-in writes and sync now require an exact
  match with the stored owner, including when the stored owner has been removed.
- An unchanged upstream Coach demo test used a fixed microtask count to wait for a
  lazy module import. The failure reproduced in a clean archive of upstream
  `1350409`; the test now waits for that real module, without changing Coach behavior.

Final checks after the fixes:

| Check | Result |
| --- | --- |
| Cloudflare adapter | 47/47 passed |
| Frontend | 3,196/3,196 passed across 258 files, including 13 new regression cases |
| Upstream Node API | 473/473 passed |
| MCP | 63/63 passed; Node-loadable check passed |
| Coach generated assets / core loadability | Passed |
| Locale / source-string consistency | Passed |
| Fatigue / history-edit probes | 108,000 / 14,076 comparisons passed |
| Frontend build + Wrangler dry-run | Passed, 75 static assets |
| PWA manifest / service-worker stamp / static headers | Passed |
| git diff --check | Passed |

The client-side sign-out fence cannot undo a `Set-Cookie` deletion from a logout
response already in flight when another tab signs in. In that ordering the new
account may need to sign in again; its local copy must remain intact.

Cloudflare's current official documentation still lists SQLite Durable Objects on
Workers Free, with separate Durable Object CPU limits from the thin Worker. This
confirms resource eligibility, not measured hosted quota or latency compliance:

- <https://developers.cloudflare.com/durable-objects/platform/pricing/>
- <https://developers.cloudflare.com/durable-objects/platform/limits/>
- <https://developers.cloudflare.com/workers/platform/limits/>

`check:config` intentionally fails against the committed hostname and D1 placeholders.
No live deployment, GitHub CI, production credential provisioning, Docker boot, or
real-iPhone acceptance test was performed during this re-review. This is a code review
and local regression pass, not an independent security certification.

Before publication, the fork's `main` was verified at `31c6795b40fb54130192b5016d7dc29e9f457d30`.
It differs from the original `1350409` base only by the upstream author's two-line README
coffee-button addition. That addition is retained in the publication tree; application code,
dependencies and test inputs are unchanged from the final passing checks above. The connector
publication is based on that current fork-main commit, and may have a different commit SHA
from the local review commits; the complete Git tree must match.
