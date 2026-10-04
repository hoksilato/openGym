-- AGPL-3.0-or-later. A small head plus immutable chunks preserves the 5 MiB HTTP contract
-- without exceeding D1's 2,000,000-byte row limit. Only the head publishes a version.
CREATE TABLE state_heads (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  revision INTEGER NOT NULL DEFAULT 0,
  write_id TEXT,
  updated_at INTEGER NOT NULL DEFAULT 0,
  last_pull INTEGER NOT NULL DEFAULT 0,
  workout_count INTEGER NOT NULL DEFAULT 0,
  last_workout TEXT,
  state_ts INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE state_parts (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  write_id TEXT NOT NULL,
  part_no INTEGER NOT NULL,
  data TEXT NOT NULL,
  PRIMARY KEY(user_id, write_id, part_no)
);
CREATE TABLE presence (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  payload TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX presence_expiry ON presence(expires_at);
