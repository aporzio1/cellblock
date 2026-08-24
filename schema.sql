CREATE TABLE IF NOT EXISTS installations (
  installation_id TEXT PRIMARY KEY,
  auth_token_hash TEXT NOT NULL UNIQUE,
  verified_opaque_vehicle_id TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  revoked_at TEXT
);
CREATE TABLE IF NOT EXISTS enrollments (
  enrollment_id TEXT PRIMARY KEY,
  installation_id TEXT NOT NULL REFERENCES installations(installation_id) ON DELETE CASCADE,
  opaque_vehicle_id TEXT NOT NULL,
  vehicle_ciphertext TEXT,
  apns_environment TEXT NOT NULL CHECK(apns_environment IN ('sandbox','production')),
  charging_mode TEXT NOT NULL DEFAULT 'both' CHECK(charging_mode IN ('fast','allAC','both')),
  status TEXT NOT NULL DEFAULT 'enrolled',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  revoked_at TEXT,
  UNIQUE(installation_id, opaque_vehicle_id)
);
CREATE TABLE IF NOT EXISTS activity_tokens (
  token_id TEXT PRIMARY KEY,
  enrollment_id TEXT NOT NULL REFERENCES enrollments(enrollment_id) ON DELETE CASCADE,
  token_kind TEXT NOT NULL CHECK(token_kind IN ('pushToStart','activity')),
  token_ciphertext TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  apns_environment TEXT NOT NULL CHECK(apns_environment IN ('sandbox','production')),
  activity_id TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  invalidated_at TEXT,
  UNIQUE(enrollment_id, token_kind, activity_id)
);
CREATE TABLE IF NOT EXISTS ford_accounts (
  ford_account_id TEXT PRIMARY KEY,
  installation_id TEXT NOT NULL REFERENCES installations(installation_id) ON DELETE CASCADE,
  refresh_token_ciphertext TEXT,
  token_expires_at TEXT,
  status TEXT NOT NULL DEFAULT 'reauthorizationRequired',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS vehicle_poll_state (
  enrollment_id TEXT PRIMARY KEY REFERENCES enrollments(enrollment_id) ON DELETE CASCADE,
  next_poll_at TEXT,
  last_source_updated_at TEXT,
  charge_phase TEXT NOT NULL DEFAULT 'unknown',
  last_soc REAL,
  last_power_kw REAL,
  last_session_id TEXT,
  session_started_at TEXT,
  consecutive_qualifying INTEGER NOT NULL DEFAULT 0,
  consecutive_nonqualifying INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS service_state (
  key TEXT PRIMARY KEY,
  value TEXT,
  updated_at TEXT NOT NULL
);
INSERT OR IGNORE INTO service_state(key,value,updated_at) VALUES ('last_cron_tick',NULL,datetime('now'));
CREATE INDEX IF NOT EXISTS idx_enrollments_active ON enrollments(status, revoked_at);
CREATE INDEX IF NOT EXISTS idx_poll_due ON vehicle_poll_state(next_poll_at);
CREATE INDEX IF NOT EXISTS idx_tokens_enrollment ON activity_tokens(enrollment_id, invalidated_at);
