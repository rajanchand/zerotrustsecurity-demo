-- ZTS Zero Trust Security
-- Users table
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'HR',
    email TEXT,
    department TEXT DEFAULT 'General',
    status TEXT DEFAULT 'active',
    failed_attempts INTEGER DEFAULT 0,
    last_failed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW ()
);

-- Departments table
CREATE TABLE IF NOT EXISTS departments (
    id SERIAL PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW ()
);

-- Devices table
CREATE TABLE IF NOT EXISTS devices (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users (id),
    fingerprint TEXT NOT NULL,
    browser TEXT,
    os TEXT,
    ip TEXT,
    country TEXT,
    approved BOOLEAN DEFAULT FALSE,
    approved_by INTEGER REFERENCES users (id),
    first_seen TIMESTAMPTZ DEFAULT NOW (),
    last_seen TIMESTAMPTZ DEFAULT NOW (),
    label TEXT DEFAULT 'Unknown Device'
);

-- Sessions log
CREATE TABLE IF NOT EXISTS sessions_log (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users (id),
    ip TEXT,
    user_agent TEXT,
    browser TEXT,
    os TEXT,
    device_fingerprint TEXT,
    country TEXT,
    risk_score INTEGER DEFAULT 0,
    login_at TIMESTAMPTZ DEFAULT NOW ()
);

-- OTP store
CREATE TABLE IF NOT EXISTS otp_store (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    code TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW ()
);

-- Risk logs
CREATE TABLE IF NOT EXISTS risk_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users (id),
    score INTEGER NOT NULL,
    level TEXT NOT NULL,
    factors_json TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW ()
);

-- Audit log
CREATE TABLE IF NOT EXISTS audit_log (
    id SERIAL PRIMARY KEY,
    user_id INTEGER,
    action TEXT NOT NULL,
    detail TEXT,
    ip TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW ()
);

-- IP rules
CREATE TABLE IF NOT EXISTS ip_rules (
    id SERIAL PRIMARY KEY,
    ip_address TEXT NOT NULL,
    action TEXT NOT NULL DEFAULT 'block',
    reason TEXT,
    created_by INTEGER REFERENCES users (id),
    created_at TIMESTAMPTZ DEFAULT NOW ()
);

-- Default departments
INSERT INTO
    departments (name)
VALUES
    ('General'),
    ('Human Resources'),
    ('Finance'),
    ('Information Technology'),
    ('Customer Support') ON CONFLICT (name) DO NOTHING;

-- Deployments log (tracks every VPS deployment)
CREATE TABLE IF NOT EXISTS deployments (
    id          SERIAL PRIMARY KEY,
    deployed_by TEXT DEFAULT 'root',
    git_commit  TEXT,
    git_branch  TEXT DEFAULT 'main',
    status      TEXT DEFAULT 'success',
    vps_ip      TEXT,
    notes       TEXT,
    deployed_at TIMESTAMPTZ DEFAULT NOW()
);