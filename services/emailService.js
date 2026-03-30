// services/emailService.js
// sends transactional emails using the Resend API
// falls back to console logging in dev when no API key is set

var { Resend } = require('resend');

// ── helper: get the Resend client (lazy so missing key doesn't crash startup) ──
function getClient() {
    var key = process.env.RESEND_API_KEY;
    if (!key) return null;
    return new Resend(key);
}

// the address emails are sent FROM — must be verified in your Resend account
// use the Resend onboarding address for quick testing without domain setup
var FROM_ADDRESS = process.env.EMAIL_FROM || 'ZTS Security <onboarding@resend.dev>';
var ADMIN_EMAIL  = process.env.ADMIN_EMAIL || process.env.RESEND_TO_EMAIL || '';

// ────────────────────────────────────────────────────────────────
// Send OTP email to the user
// ────────────────────────────────────────────────────────────────
async function sendOTPEmail(toEmail, username, otpCode) {
    var resend = getClient();
    if (!resend) {
        console.log('  [email] No RESEND_API_KEY — OTP for ' + username + ': ' + otpCode);
        return { sent: false, reason: 'No Resend API key configured' };
    }

    var html = [
        '<div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;padding:24px;">',
        '  <h2 style="color:#0984e3;margin-bottom:4px;">ZTS Zero Trust Security</h2>',
        '  <p style="color:#636e72;font-size:13px;margin-top:0;">Multi-Factor Authentication</p>',
        '  <hr style="border:none;border-top:1px solid #eee;margin:16px 0;">',
        '  <p style="font-size:15px;">Hello <strong>' + username + '</strong>,</p>',
        '  <p style="font-size:14px;color:#2d3436;">Your one-time login code is:</p>',
        '  <div style="background:#f4f5f7;border-radius:8px;padding:20px;text-align:center;margin:20px 0;">',
        '    <span style="font-size:36px;font-weight:700;letter-spacing:10px;color:#0984e3;">' + otpCode + '</span>',
        '  </div>',
        '  <p style="font-size:13px;color:#636e72;">This code expires in <strong>5 minutes</strong>. Do not share it with anyone.</p>',
        '  <p style="font-size:13px;color:#636e72;">If you did not try to log in, contact your administrator immediately.</p>',
        '  <hr style="border:none;border-top:1px solid #eee;margin:16px 0;">',
        '  <p style="font-size:11px;color:#b2bec3;">ZTS — Zero Trust Security Demo | NIST SP 800-207</p>',
        '</div>'
    ].join('\n');

    try {
        var { data, error } = await resend.emails.send({
            from:    FROM_ADDRESS,
            to:      [toEmail],
            subject: 'Your ZTS Login Code: ' + otpCode,
            html:    html
        });

        if (error) {
            console.error('  [email] Resend error sending OTP to ' + toEmail + ':', error.message);
            return { sent: false, reason: error.message };
        }

        console.log('  [email] OTP sent to ' + toEmail + ' (id: ' + (data && data.id) + ')');
        return { sent: true };
    } catch (err) {
        console.error('  [email] Failed to send OTP to ' + toEmail + ':', err.message);
        return { sent: false, reason: err.message };
    }
}

// ────────────────────────────────────────────────────────────────
// Send login alert email to admin
// ────────────────────────────────────────────────────────────────
async function sendLoginAlertEmail(username, ip, country) {
    var resend = getClient();
    if (!resend || !ADMIN_EMAIL) {
        console.log('  [email] No config — Login alert for ' + username + ' skipped');
        return { sent: false, reason: 'No Resend key or admin email configured' };
    }

    var html = [
        '<div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;padding:24px;">',
        '  <h2 style="color:#e17055;margin-bottom:4px;">ZTS Security Alert</h2>',
        '  <p style="color:#636e72;font-size:13px;margin-top:0;">New User Login Detected</p>',
        '  <hr style="border:none;border-top:1px solid #eee;margin:16px 0;">',
        '  <p style="font-size:15px;">A user has just logged into the system.</p>',
        '  <ul style="font-size:14px;color:#2d3436;background:#f4f5f7;border-radius:8px;padding:20px;list-style-type:none;">',
        '    <li style="margin-bottom:8px;"><strong>Username:</strong> ' + username + '</li>',
        '    <li style="margin-bottom:8px;"><strong>IP Address:</strong> ' + ip + '</li>',
        '    <li><strong>Location:</strong> ' + country + '</li>',
        '  </ul>',
        '  <p style="font-size:13px;color:#636e72;">If this looks suspicious, check the session logs in the admin dashboard.</p>',
        '  <hr style="border:none;border-top:1px solid #eee;margin:16px 0;">',
        '  <p style="font-size:11px;color:#b2bec3;">ZTS — Zero Trust Security Demo</p>',
        '</div>'
    ].join('\n');

    try {
        var { error } = await resend.emails.send({
            from:    FROM_ADDRESS,
            to:      [ADMIN_EMAIL],
            subject: 'ZTS Security Alert: New Login Detected',
            html:    html
        });

        if (error) {
            console.error('  [email] Login alert failed:', error.message);
            return { sent: false, reason: error.message };
        }

        console.log('  [email] Login alert sent to admin for ' + username);
        return { sent: true };
    } catch (err) {
        console.error('  [email] Login alert error:', err.message);
        return { sent: false, reason: err.message };
    }
}

// ────────────────────────────────────────────────────────────────
// Send anomaly/security alert email to admin
// ────────────────────────────────────────────────────────────────
async function sendAnomalyAlertEmail(username, ip, country, reason) {
    var resend = getClient();
    if (!resend || !ADMIN_EMAIL) {
        console.log('  [email] No config — Anomaly alert for ' + username + ' skipped');
        return { sent: false, reason: 'No Resend key or admin email configured' };
    }

    var html = [
        '<div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;padding:24px;border:1px solid #ff7675;border-radius:8px;">',
        '  <h2 style="color:#d63031;margin-bottom:4px;">🚨 Critical Security Alert</h2>',
        '  <p style="color:#636e72;font-size:13px;margin-top:0;">Suspicious Login Activity</p>',
        '  <hr style="border:none;border-top:1px solid #eee;margin:16px 0;">',
        '  <div style="background:#fff3f3;border-left:4px solid #d63031;padding:12px 16px;margin:20px 0;">',
        '    <p style="margin:0;font-size:14px;color:#d63031;"><strong>Alert Reason:</strong> ' + reason + '</p>',
        '  </div>',
        '  <ul style="font-size:14px;color:#2d3436;background:#f4f5f7;border-radius:8px;padding:20px;list-style-type:none;margin:0;">',
        '    <li style="margin-bottom:8px;"><strong>Username:</strong> ' + username + '</li>',
        '    <li style="margin-bottom:8px;"><strong>IP Address:</strong> ' + ip + '</li>',
        '    <li><strong>Location:</strong> ' + country + '</li>',
        '  </ul>',
        '  <p style="font-size:13px;color:#636e72;margin-top:20px;">Please investigate in the SuperAdmin dashboard immediately.</p>',
        '  <hr style="border:none;border-top:1px solid #eee;margin:16px 0;">',
        '  <p style="font-size:11px;color:#b2bec3;text-align:center;">ZTS — Zero Trust Security Alerts</p>',
        '</div>'
    ].join('\n');

    try {
        var { error } = await resend.emails.send({
            from:    FROM_ADDRESS,
            to:      [ADMIN_EMAIL],
            subject: '🚨 ZTS Alert: Anomalous Login — ' + reason,
            html:    html
        });

        if (error) {
            console.error('  [email] Anomaly alert failed:', error.message);
            return { sent: false, reason: error.message };
        }

        console.log('  [email] Anomaly alert sent to admin for ' + username);
        return { sent: true };
    } catch (err) {
        console.error('  [email] Anomaly alert error:', err.message);
        return { sent: false, reason: err.message };
    }
}

module.exports = { sendOTPEmail, sendLoginAlertEmail, sendAnomalyAlertEmail };
