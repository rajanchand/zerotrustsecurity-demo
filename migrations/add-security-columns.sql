-- migrations/add-security-columns.sql
-- Adds columns and tables needed for enhanced ZTS security

-- Password expiry tracking
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMPTZ DEFAULT NOW();

-- Concurrent session control
ALTER TABLE users ADD COLUMN IF NOT EXISTS active_session_token TEXT;

-- Password history table (prevent reuse of last 3 passwords)
CREATE TABLE IF NOT EXISTS password_history (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Remote Work: Geo-fencing support
ALTER TABLE departments ADD COLUMN IF NOT EXISTS allowed_countries TEXT;

-- Remote Work: Device Trust Levels
ALTER TABLE devices ADD COLUMN IF NOT EXISTS trust_level TEXT DEFAULT 'Unknown';
UPDATE devices SET trust_level = 'Managed' WHERE approved = true AND trust_level = 'Unknown';
