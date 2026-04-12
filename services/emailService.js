var { Resend } = require('resend');

// get the email client
function getResendClient() {
    var apiKey = process.env.RESEND_API_KEY;
    if (!apiKey) return null;
    return new Resend(apiKey);
}

var FROM_ADDRESS = process.env.EMAIL_FROM || 'ZTS Security <onboarding@resend.dev>';
var ADMIN_EMAIL = process.env.ADMIN_EMAIL || process.env.RESEND_TO_EMAIL || '';

// send the otp login code to a user by email
async function sendOTPEmail(recipientEmail, username, otpCode) {
    var client = getResendClient();

    if (!client) {
        console.log('[Email] No email service set up. OTP for ' + username + ': ' + otpCode);
        return { dispatched: false, failureReason: 'Email service not configured' };
    }

    var toAddress = process.env.RESEND_TO_OVERRIDE || recipientEmail;

    var html = '<div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;padding:40px;background:#ffffff;border:1px solid #f1f5f9;border-radius:12px;">' +
        '<h2 style="color:#0f172a;margin-bottom:8px;font-size:18px;font-weight:700;">Your Login Code</h2>' +
        '<p style="color:#64748b;font-size:13px;margin:0;">ZTS Admin Portal</p>' +
        '<hr style="border:none;border-top:1px solid #f1f5f9;margin:32px 0;">' +
        '<p style="font-size:14px;color:#334155;line-height:1.6;">Hi <strong>' + username + '</strong>,</p>' +
        '<p style="font-size:14px;color:#334155;line-height:1.6;">Here is your login code:</p>' +
        '<div style="background:#f8fafc;border-radius:8px;padding:32px;text-align:center;margin:32px 0;border:1px solid #e2e8f0;">' +
        '<span style="font-size:36px;font-weight:800;letter-spacing:12px;color:#0f172a;font-family:monospace;">' + otpCode + '</span>' +
        '</div>' +
        '<p style="font-size:12px;color:#94a3b8;line-height:1.6;">This code is valid for <strong>5 minutes</strong>. If you did not request this, please contact your administrator.</p>' +
        '<hr style="border:none;border-top:1px solid #f1f5f9;margin:32px 0;">' +
        '<p style="font-size:11px;color:#94a3b8;text-transform:uppercase;letter-spacing:1px;font-weight:600;">ZTS Admin Portal</p>' +
        '</div>';

    try {
        var result = await client.emails.send({
            from: FROM_ADDRESS,
            to: [toAddress],
            subject: 'Your Login Code - ZTS',
            html: html
        });

        if (result.error) {
            console.error('[Email] Failed to send OTP: ' + result.error.message);
            return { dispatched: false, failureReason: result.error.message };
        }

        console.log('[Email] OTP code sent to: ' + toAddress);
        return { dispatched: true };
    } catch (err) {
        console.error('[Email] Error sending OTP: ' + err.message);
        return { dispatched: false, failureReason: err.message };
    }
}

// send a login alert email to the admin
async function sendLoginAlertEmail(username, ip, location) {
    var client = getResendClient();

    if (!client || !ADMIN_EMAIL) {
        console.log('[Email] Login alert skipped for: ' + username);
        return { dispatched: false, failureReason: 'Email not configured' };
    }

    var html = '<div style="font-family:Arial,sans-serif;max-width:520px;margin:0 auto;padding:40px;background:#ffffff;border:1px solid #f1f5f9;border-radius:12px;">' +
        '<h2 style="color:#0f172a;margin-bottom:8px;font-size:18px;font-weight:700;">Login Alert</h2>' +
        '<p style="color:#64748b;font-size:13px;margin:0;">A user has logged in</p>' +
        '<hr style="border:none;border-top:1px solid #f1f5f9;margin:32px 0;">' +
        '<div style="background:#f8fafc;border-radius:8px;padding:24px;border:1px solid #e2e8f0;">' +
        '<table style="width:100%;font-size:14px;color:#334155;border-collapse:collapse;">' +
        '<tr><td style="padding:8px 0;font-weight:600;width:140px;color:#64748b;">Username</td><td style="font-weight:500;color:#0f172a;">' + username + '</td></tr>' +
        '<tr><td style="padding:8px 0;font-weight:600;color:#64748b;">IP Address</td><td style="font-weight:500;color:#0f172a;">' + ip + '</td></tr>' +
        '<tr><td style="padding:8px 0;font-weight:600;color:#64748b;">Location</td><td style="font-weight:500;color:#0f172a;">' + location + '</td></tr>' +
        '</table></div>' +
        '<p style="font-size:12px;color:#94a3b8;margin-top:24px;line-height:1.6;">This alert was sent automatically after a successful login.</p>' +
        '<hr style="border:none;border-top:1px solid #f1f5f9;margin:32px 0;">' +
        '<p style="font-size:11px;color:#94a3b8;text-transform:uppercase;letter-spacing:1px;font-weight:600;">ZTS Admin Portal</p>' +
        '</div>';

    try {
        var result = await client.emails.send({
            from: FROM_ADDRESS,
            to: [ADMIN_EMAIL],
            subject: 'Login Alert - ' + username + ' - ZTS',
            html: html
        });

        if (result.error) return { dispatched: false, failureReason: result.error.message };
        console.log('[Email] Login alert sent for: ' + username);
        return { dispatched: true };
    } catch (err) {
        return { dispatched: false, failureReason: err.message };
    }
}

// send a security alert email to the admin
async function sendAnomalyAlertEmail(username, ip, location, alertMessage) {
    var client = getResendClient();

    if (!client || !ADMIN_EMAIL) {
        console.log('[Alert] Security alert skipped: ' + alertMessage);
        return { dispatched: false, failureReason: 'Email not configured' };
    }

    var html = '<div style="font-family:Arial,sans-serif;max-width:520px;margin:0 auto;padding:40px;background:#fffafb;border:1px solid #fee2e2;border-radius:12px;">' +
        '<h2 style="color:#991b1b;margin-bottom:4px;font-size:18px;font-weight:700;">Security Alert</h2>' +
        '<p style="color:#b91c1c;font-size:13px;margin:0;font-weight:600;text-transform:uppercase;">Action Required</p>' +
        '<hr style="border:none;border-top:1px solid #fee2e2;margin:32px 0;">' +
        '<div style="background:#ffffff;border-left:4px solid #dc2626;padding:20px;margin:24px 0;border:1px solid #fecaca;border-radius:0 8px 8px 0;">' +
        '<p style="margin:0;font-size:15px;color:#991b1b;font-weight:700;">Issue: ' + alertMessage + '</p>' +
        '</div>' +
        '<div style="background:#fef2f2;border-radius:8px;padding:24px;border:1px solid #fecaca;">' +
        '<table style="width:100%;font-size:14px;color:#7f1d1d;border-collapse:collapse;">' +
        '<tr><td style="padding:8px 0;font-weight:600;width:140px;color:#b91c1c;">Username</td><td style="font-weight:600;">' + username + '</td></tr>' +
        '<tr><td style="padding:8px 0;font-weight:600;color:#b91c1c;">IP Address</td><td style="font-weight:600;">' + ip + '</td></tr>' +
        '<tr><td style="padding:8px 0;font-weight:600;color:#b91c1c;">Location</td><td style="font-weight:600;">' + location + '</td></tr>' +
        '</table></div>' +
        '<p style="font-size:12px;color:#991b1b;margin-top:24px;line-height:1.6;font-weight:500;">Please review this event as soon as possible.</p>' +
        '<hr style="border:none;border-top:1px solid #fee2e2;margin:32px 0;">' +
        '<p style="font-size:11px;color:#f87171;text-transform:uppercase;letter-spacing:1px;font-weight:700;">ZTS Security Alert</p>' +
        '</div>';

    try {
        var result = await client.emails.send({
            from: FROM_ADDRESS,
            to: [ADMIN_EMAIL],
            subject: 'Security Alert: ' + alertMessage + ' - ZTS',
            html: html
        });

        if (result.error) return { dispatched: false, failureReason: result.error.message };
        console.log('[Alert] Security alert sent: ' + alertMessage);
        return { dispatched: true };
    } catch (err) {
        return { dispatched: false, failureReason: err.message };
    }
}

module.exports = {
    sendOTPEmail: sendOTPEmail,
    sendLoginAlertEmail: sendLoginAlertEmail,
    sendAnomalyAlertEmail: sendAnomalyAlertEmail
};
