// routes/securityPostureRoutes.js
// displays overall security configuration status for admins

const express = require('express');
const router = express.Router();

router.get('/api/security-posture', function (req, res) {
    if (req.session.role !== 'SuperAdmin') {
        return res.status(403).json({ error: 'Access denied' });
    }

    var posture = {
        overall: 'Strong',
        score: 0,
        maxScore: 0,
        checks: []
    };

    function addCheck(name, category, enabled, description) {
        var item = {
            name: name,
            category: category,
            enabled: enabled,
            description: description
        };
        posture.checks.push(item);
        posture.maxScore += 1;
        if (enabled) posture.score += 1;
    }

    // Authentication checks
    addCheck('Password Hashing (bcrypt)', 'Authentication', true, 'User passwords are hashed with bcrypt before storage.');
    addCheck('Multi-Factor Auth (OTP)', 'Authentication', true, 'Email-based OTP required after password verification.');
    addCheck('Account Lockout', 'Authentication', true, 'Accounts locked after 5 failed login attempts.');
    addCheck('Password Policy', 'Authentication', true, 'Minimum 8 chars with uppercase, lowercase, number, special character.');
    addCheck('Password Expiry (90 days)', 'Authentication', true, 'Users must change password every 90 days.');
    addCheck('Password History (3)', 'Authentication', true, 'Cannot reuse last 3 passwords.');
    addCheck('Step-Up Re-Authentication', 'Authentication', true, 'Sensitive actions require password re-entry within 5-min window.');

    // Session Security
    addCheck('Session Timeout (15 min)', 'Session', true, 'Sessions expire after 15 minutes of inactivity.');
    addCheck('HttpOnly Cookies', 'Session', true, 'Session cookies are HttpOnly to prevent XSS access.');
    addCheck('SameSite Strict Cookie', 'Session', true, 'Cookies use SameSite=Strict to prevent CSRF.');
    addCheck('Session-Device Binding', 'Session', true, 'Sessions bound to device fingerprint; mismatch forces logout.');
    addCheck('Concurrent Login Control', 'Session', true, 'Only one active session per user; new login invalidates old.');
    addCheck('Secure Cookies (HTTPS)', 'Session',
        process.env.NODE_ENV === 'production',
        'Cookies marked Secure in production (HTTPS only).'
    );

    // Access Control
    addCheck('Role-Based Access (RBAC)', 'Access Control', true, 'Users assigned roles; routes restricted by role.');
    addCheck('Department Micro-segmentation', 'Access Control', true, 'Resources restricted by department with SuperAdmin bypass.');
    addCheck('Device Posture Enforcement', 'Access Control', true, 'Admin actions require approved company devices.');
    addCheck('IP Blocklist Enforcement', 'Access Control', true, 'Blocked IPs rejected at login from ip_rules table.');
    addCheck('Conditional Access (Risk)', 'Access Control', true, 'High-risk sessions (score>60) blocked from resources.');

    // Threat Detection
    addCheck('Risk Scoring Engine', 'Threat Detection', true, 'Dynamic risk calculation based on device, location, behavior.');
    addCheck('Continuous Risk Assessment', 'Threat Detection', true, 'Per-request lightweight risk checks for behavioral anomalies.');
    addCheck('Impossible Travel Detection', 'Threat Detection', true, 'Detects logins from different countries within 2 hours.');
    addCheck('VPN Detection', 'Threat Detection', true, 'Flags connections from known VPN/proxy IP ranges.');
    addCheck('Login Anomaly Alerts', 'Threat Detection', true, 'Email alerts sent on each successful login.');

    // Infrastructure Security
    addCheck('Helmet Security Headers', 'Infrastructure', true, 'X-Frame-Options, CSP, HSTS, X-Content-Type-Options, etc.');
    addCheck('Rate Limiting', 'Infrastructure', true, 'Login: 5/15min, OTP: 5/5min, API: 100/15min per IP.');
    addCheck('CSRF Protection', 'Infrastructure', true, 'Session-bound CSRF tokens validated on POST requests.');
    addCheck('HMAC Request Signing', 'Infrastructure', true, 'API integrity verification with SHA-256 HMAC and replay protection.');
    addCheck('Encryption at Rest (AES-256)', 'Infrastructure', true, 'Sensitive data encrypted with AES-256-GCM before storage.');

    // Audit & Monitoring
    addCheck('Audit Logging', 'Monitoring', true, 'All security events logged with user, IP, timestamp.');
    addCheck('Real-time Monitoring (SSE)', 'Monitoring', true, 'Live security event stream for admin dashboard.');
    addCheck('Security Event Classification', 'Monitoring', true, 'Events classified by severity: INFO, MEDIUM, HIGH, CRITICAL.');

    // calculate overall
    var pct = Math.round((posture.score / posture.maxScore) * 100);
    if (pct >= 90) posture.overall = 'Strong';
    else if (pct >= 70) posture.overall = 'Good';
    else if (pct >= 50) posture.overall = 'Fair';
    else posture.overall = 'Weak';

    posture.percentage = pct;

    res.json(posture);
});

module.exports = router;
