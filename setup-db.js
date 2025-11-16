// setup-db.js
// Creates all the required tables in Supabase
// Run once: node setup-db.js

require('dotenv').config();
var { createClient } = require('@supabase/supabase-js');

var supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

async function setup() {
    console.log('Setting up Supabase tables...');
    console.log('NOTE: You should create these tables through the Supabase SQL Editor.');
    console.log('Copy and paste the SQL below into your Supabase Dashboard > SQL Editor:\n');

    var sql = `
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
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Departments table
CREATE TABLE IF NOT EXISTS departments (
  id SERIAL PRIMARY KEY,
  name TEXT UNIQUE NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Devices table
CREATE TABLE IF NOT EXISTS devices (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id),
  fingerprint TEXT NOT NULL,
  browser TEXT,
  os TEXT,
  ip TEXT,
  country TEXT,
  approved BOOLEAN DEFAULT FALSE,
  approved_by INTEGER REFERENCES users(id),
  first_seen TIMESTAMPTZ DEFAULT NOW(),
  last_seen TIMESTAMPTZ DEFAULT NOW(),
  label TEXT DEFAULT 'Unknown Device'
);

-- Sessions log
CREATE TABLE IF NOT EXISTS sessions_log (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id),
  ip TEXT,
  user_agent TEXT,
  browser TEXT,
  os TEXT,
  device_fingerprint TEXT,
  country TEXT,
  risk_score INTEGER DEFAULT 0,
  login_at TIMESTAMPTZ DEFAULT NOW()
);

-- OTP store
CREATE TABLE IF NOT EXISTS otp_store (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL,
  code TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  used BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Risk logs
CREATE TABLE IF NOT EXISTS risk_logs (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id),
  score INTEGER NOT NULL,
  level TEXT NOT NULL,
  factors_json TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Audit log
CREATE TABLE IF NOT EXISTS audit_log (
  id SERIAL PRIMARY KEY,
  user_id INTEGER,
  action TEXT NOT NULL,
  detail TEXT,
  ip TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- IP rules
CREATE TABLE IF NOT EXISTS ip_rules (
  id SERIAL PRIMARY KEY,
  ip_address TEXT NOT NULL,
  action TEXT NOT NULL DEFAULT 'block',
  reason TEXT,
  created_by INTEGER REFERENCES users(id),
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Default departments
INSERT INTO departments (name) VALUES ('General'), ('Human Resources'), ('Finance'), ('Information Technology'), ('Customer Support')
ON CONFLICT (name) DO NOTHING;
`;

    console.log(sql);
    console.log('\n--- END OF SQL ---');
    console.log('Paste the above SQL into Supabase Dashboard > SQL Editor > New Query > Run');
}

setup();
