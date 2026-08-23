CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  owner_hash TEXT NOT NULL,
  partner_hash TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  iv TEXT NOT NULL,
  payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);

