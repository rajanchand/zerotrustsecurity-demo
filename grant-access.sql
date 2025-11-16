-- In Supabase SQL Editortables
GRANT ALL ON users TO anon;

GRANT ALL ON users TO authenticated;

GRANT USAGE,
SELECT
    ON SEQUENCE users_id_seq TO anon;

GRANT USAGE,
SELECT
    ON SEQUENCE users_id_seq TO authenticated;

-- Grant access on departments table
GRANT ALL ON departments TO anon;

GRANT ALL ON departments TO authenticated;

GRANT USAGE,
SELECT
    ON SEQUENCE departments_id_seq TO anon;

GRANT USAGE,
SELECT
    ON SEQUENCE departments_id_seq TO authenticated;

-- Grant access on devices table
GRANT ALL ON devices TO anon;

GRANT ALL ON devices TO authenticated;

GRANT USAGE,
SELECT
    ON SEQUENCE devices_id_seq TO anon;

GRANT USAGE,
SELECT
    ON SEQUENCE devices_id_seq TO authenticated;

-- Grant access on sessions_log table
GRANT ALL ON sessions_log TO anon;

GRANT ALL ON sessions_log TO authenticated;

GRANT USAGE,
SELECT
    ON SEQUENCE sessions_log_id_seq TO anon;

GRANT USAGE,
SELECT
    ON SEQUENCE sessions_log_id_seq TO authenticated;

-- Grant access on otp_store table
GRANT ALL ON otp_store TO anon;

GRANT ALL ON otp_store TO authenticated;

GRANT USAGE,
SELECT
    ON SEQUENCE otp_store_id_seq TO anon;

GRANT USAGE,
SELECT
    ON SEQUENCE otp_store_id_seq TO authenticated;

-- Grant access on risk_logs table
GRANT ALL ON risk_logs TO anon;

GRANT ALL ON risk_logs TO authenticated;

GRANT USAGE,
SELECT
    ON SEQUENCE risk_logs_id_seq TO anon;

GRANT USAGE,
SELECT
    ON SEQUENCE risk_logs_id_seq TO authenticated;

-- Grant access on audit_log table
GRANT ALL ON audit_log TO anon;

GRANT ALL ON audit_log TO authenticated;

GRANT USAGE,
SELECT
    ON SEQUENCE audit_log_id_seq TO anon;

GRANT USAGE,
SELECT
    ON SEQUENCE audit_log_id_seq TO authenticated;

-- Grant access on ip_rules table
GRANT ALL ON ip_rules TO anon;

GRANT ALL ON ip_rules TO authenticated;

GRANT USAGE,
SELECT
    ON SEQUENCE ip_rules_id_seq TO anon;

GRANT USAGE,
SELECT
    ON SEQUENCE ip_rules_id_seq TO authenticated;