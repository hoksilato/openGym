-- Auth is durable. The application must route every API request through its FIFO
-- Durable Object; D1 batches provide transactional writes within each ceremony.
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  name_key TEXT NOT NULL,
  login_name TEXT UNIQUE,
  created TEXT NOT NULL,
  sv INTEGER NOT NULL DEFAULT 0 CHECK (sv >= 0),
  admin INTEGER NOT NULL DEFAULT 0 CHECK (admin IN (0,1)),
  disabled INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0,1)),
  invited_by TEXT,
  email TEXT UNIQUE,
  pw_hash TEXT,
  pw_set TEXT
);
CREATE INDEX IF NOT EXISTS users_name ON users(name_key);

CREATE TABLE IF NOT EXISTS credentials (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  public_key TEXT NOT NULL,
  counter INTEGER NOT NULL DEFAULT 0,
  revision INTEGER NOT NULL DEFAULT 0,
  transports TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(transports)),
  name TEXT,
  created TEXT NOT NULL,
  last_used TEXT
);
CREATE INDEX IF NOT EXISTS credentials_user ON credentials(user_id);

CREATE TABLE IF NOT EXISTS invites (
  code TEXT PRIMARY KEY,
  note TEXT NOT NULL DEFAULT '',
  created_by TEXT,
  created TEXT NOT NULL,
  used_by TEXT,
  used_at TEXT,
  revoked INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0,1)),
  admin INTEGER NOT NULL DEFAULT 0 CHECK (admin IN (0,1))
);

CREATE TABLE IF NOT EXISTS challenges (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind IN ('register','login','add','link')),
  challenge TEXT NOT NULL,
  user_id TEXT,
  data TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(data)),
  expires INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS challenges_expiry ON challenges(expires);
CREATE INDEX IF NOT EXISTS challenges_user ON challenges(user_id);

CREATE TABLE IF NOT EXISTS auth_codes (
  hash TEXT PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind IN ('pair','link','reset')),
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  sv INTEGER NOT NULL,
  expires INTEGER NOT NULL,
  created INTEGER NOT NULL,
  UNIQUE (kind,user_id)
);
CREATE INDEX IF NOT EXISTS auth_codes_expiry ON auth_codes(expires);

CREATE TABLE IF NOT EXISTS rate_limits (
  key TEXT PRIMARY KEY,
  count INTEGER NOT NULL,
  expires INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS rate_limits_expiry ON rate_limits(expires);

CREATE TABLE IF NOT EXISTS audit_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  event TEXT NOT NULL,
  actor_id TEXT,
  actor_name TEXT,
  target_id TEXT,
  target_name TEXT,
  message TEXT,
  ok INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS audit_events_ts ON audit_events(ts);
