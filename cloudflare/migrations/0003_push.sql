-- Durable Web Push state. The single AppDO serializes all mutations and owns the alarm.
CREATE TABLE IF NOT EXISTS push_subscriptions (
  endpoint TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_id TEXT NOT NULL DEFAULT '',
  p256dh TEXT NOT NULL,
  auth TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS push_subscriptions_user ON push_subscriptions(user_id, created_at);

-- A small projection of the workout state; excludes workout/set/body-weight details.
CREATE TABLE IF NOT EXISTS push_reminders (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  state_json TEXT NOT NULL,
  last_sent_date TEXT
);

CREATE TABLE IF NOT EXISTS push_tasks (
  task_key TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK (kind IN ('rest', 'reminder')),
  device_id TEXT NOT NULL DEFAULT '',
  due_at INTEGER NOT NULL,
  local_date TEXT,
  payload_json TEXT
);
CREATE INDEX IF NOT EXISTS push_tasks_due ON push_tasks(due_at);
CREATE INDEX IF NOT EXISTS push_tasks_user ON push_tasks(user_id, kind);
