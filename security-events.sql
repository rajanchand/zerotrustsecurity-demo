-- security_events table for SIEM-like monitoring (Updated)
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
  details JSONB DEFAULT '{}',
  resolved BOOLEAN DEFAULT FALSE,
  resolved_by INTEGER REFERENCES users(id),
  resolved_at TIMESTAMPTZ
);

-- Performance indexes
CREATE INDEX IF NOT EXISTS idx_security_events_ts ON security_events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_type ON security_events(event_type);
CREATE INDEX IF NOT EXISTS idx_security_events_user ON security_events(user_id);
CREATE INDEX IF NOT EXISTS idx_security_events_severity ON security_events(severity);
CREATE INDEX IF NOT EXISTS idx_security_events_ip ON security_events(ip);
CREATE INDEX IF NOT EXISTS idx_security_events_risk ON security_events(risk_score DESC);

-- RLS
ALTER TABLE security_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Allow all on security_events" ON security_events FOR ALL USING (true) WITH CHECK (true);

-- Grants
GRANT ALL ON security_events TO anon;
GRANT ALL ON security_events TO authenticated;
GRANT USAGE, SELECT ON SEQUENCE security_events_id_seq TO anon;
GRANT USAGE, SELECT ON SEQUENCE security_events_id_seq TO authenticated;
