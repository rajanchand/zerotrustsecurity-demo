ALTER TABLE users ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Allow all on users" ON users FOR ALL USING (true)
WITH
    CHECK (true);

ALTER TABLE departments ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Allow all on departments" ON departments FOR ALL USING (true)
WITH
    CHECK (true);

ALTER TABLE devices ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Allow all on devices" ON devices FOR ALL USING (true)
WITH
    CHECK (true);

ALTER TABLE sessions_log ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Allow all on sessions_log" ON sessions_log FOR ALL USING (true)
WITH
    CHECK (true);

ALTER TABLE otp_store ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Allow all on otp_store" ON otp_store FOR ALL USING (true)
WITH
    CHECK (true);

ALTER TABLE risk_logs ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Allow all on risk_logs" ON risk_logs FOR ALL USING (true)
WITH
    CHECK (true);

ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Allow all on audit_log" ON audit_log FOR ALL USING (true)
WITH
    CHECK (true);

ALTER TABLE ip_rules ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Allow all on ip_rules" ON ip_rules FOR ALL USING (true)
WITH
    CHECK (true);