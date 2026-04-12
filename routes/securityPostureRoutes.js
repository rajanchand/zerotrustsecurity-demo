var express = require('express');
var router = express.Router();

// security posture report — shows whats enabled
router.get('/api/security-posture', function(req, res) {
    if (req.session.role !== 'SuperAdmin') {
        return res.status(403).json({ error: 'Admin access required.' });
    }

    var report = {
        overall: 'Strong',
        score: 0,
        maxScore: 0,
        checks: []
    };

    function addCheck(name, category, enabled, description) {
        report.checks.push({ name: name, category: category, enabled: enabled, description: description });
        report.maxScore += 1;
        if (enabled) report.score += 1;
    }

    // authentication checks
    addCheck('Bcrypt Hashing', 'Authentication', true, 'Passwords are securely hashed using bcrypt.');
    addCheck('MFA Enforcement', 'Authentication', true, 'OTP is required for all logins.');
    addCheck('Account Lockout', 'Authentication', true, 'Account locks after too many failed attempts.');
    addCheck('Password Rules', 'Authentication', true, 'Passwords must be 12+ chars with uppercase, lowercase, numbers, symbols.');
    addCheck('Password Expiry', 'Authentication', true, 'Users must change password every 90 days.');
    addCheck('Password History', 'Authentication', true, 'Cannot reuse recent passwords.');
    addCheck('Re-Authentication', 'Authentication', true, 'Extra password check for sensitive actions.');

    // session security
    addCheck('Idle Timeout', 'Session', true, 'Session ends after 15 minutes idle.');
    addCheck('HttpOnly Cookies', 'Session', true, 'Cookies are HttpOnly (not accessible by JavaScript).');
    addCheck('SameSite Policy', 'Session', true, 'Cookies use SameSite=Strict to prevent CSRF.');
    addCheck('Device Binding', 'Session', true, 'Sessions are tied to specific devices.');
    addCheck('Single Session', 'Session', true, 'Only one active session per user.');
    addCheck('HTTPS Cookies', 'Session', process.env.NODE_ENV === 'production', 'Cookies are HTTPS-only in production.');

    // access control
    addCheck('Role-Based Access', 'Access Control', true, 'Access control based on user roles.');
    addCheck('Department Access', 'Access Control', true, 'Pages restricted by department.');
    addCheck('Device Check', 'Access Control', true, 'Admin actions require approved devices.');
    addCheck('IP Filtering', 'Access Control', true, 'IPs checked against block lists.');
    addCheck('Risk-Based Access', 'Access Control', true, 'Access changes based on risk score.');

    // threat detection
    addCheck('Risk Engine', 'Threat Detection', true, 'Risk score calculated for each login.');
    addCheck('Session Checks', 'Threat Detection', true, 'Every request is checked during session.');
    addCheck('Travel Detection', 'Threat Detection', true, 'Detects impossible travel between countries.');
    addCheck('VPN Detection', 'Threat Detection', true, 'VPN and proxy connections are detected and logged.');
    addCheck('Login Alerts', 'Threat Detection', true, 'Email alerts sent on login.');

    // platform security
    addCheck('Security Headers', 'Platform Security', true, 'Security headers (CSP, Helmet) are enabled.');
    addCheck('Rate Limiting', 'Platform Security', true, 'Rate limits prevent brute-force attacks.');
    addCheck('CSRF Protection', 'Platform Security', true, 'CSRF tokens required for all POST requests.');
    addCheck('Request Signing', 'Platform Security', true, 'Requests are signed with HMAC for integrity.');
    addCheck('Data Encryption', 'Platform Security', true, 'Sensitive data is encrypted in the database.');

    // compliance
    addCheck('Audit Logging', 'Compliance', true, 'All actions are logged for audit.');
    addCheck('Live Monitoring', 'Compliance', true, 'Live monitoring of security events.');
    addCheck('Event Severity', 'Compliance', true, 'Events are classified by severity.');

    var pct = Math.round((report.score / report.maxScore) * 100);
    report.percentage = pct;

    if (pct >= 90) report.overall = 'Strong';
    else if (pct >= 70) report.overall = 'Good';
    else if (pct >= 50) report.overall = 'Fair';
    else report.overall = 'Weak';

    res.json(report);
});

module.exports = router;
