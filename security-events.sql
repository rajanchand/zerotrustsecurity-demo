-- security_events table for SIEM-like monitoring
CREATE TABLE IF NOT EXISTS security_events (
  id BIGSERIAL PRIMARY KEY,
  timestamp TIMESTAMPTZ DEFAULT NOW(),
  event_type TEXT NOT NULL,
  severity TEXT NOT NULL DEFAULT 'INFO',
  user_id INTEGER,
  username TEXT,
  ip TEXT,
  location TEXT,
  device_id INTEGER,
  risk_score INTEGER DEFAULT 0,
  details JSONB DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_security_events_ts ON security_events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_type ON security_events(event_type);
CREATE INDEX IF NOT EXISTS idx_security_events_user ON security_events(user_id);
