// services/emailService.js
// sends emails using Gmail via nodemailer

var nodemailer = require('nodemailer');

// create transporter — uses env variables so credentials stay out of code
var transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.SMTP_EMAIL,
        pass: process.env.SMTP_PASSWORD  // use a Gmail App Password,
    }
});

// send the OTP email to the user
async function sendOTPEmail(toEmail, username, otpCode) {
    // if no email credentials set, just log to console (dev mode)
    if (!process.env.SMTP_EMAIL || !process.env.SMTP_PASSWORD) {
        console.log('  [email] No SMTP config — OTP for ' + username + ': ' + otpCode);
        return { sent: false, reason: 'No SMTP credentials configured' };
    }

    var subject = 'Your ZTS Login Code: ' + otpCode;

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
        '  <p style="font-size:13px;color:#636e72;">If you did not try to log in, please contact your administrator immediately.</p>',
        '  <hr style="border:none;border-top:1px solid #eee;margin:16px 0;">',
        '  <p style="font-size:11px;color:#b2bec3;">ZTS — Zero Trust Security Demo  for testing purpose only&nbsp;|&nbsp; NIST SP 800-207</p>',
        '</div>'
    ].join('\n');

    try {
        await transporter.sendMail({
            from: '"ZTS Security" <' + process.env.SMTP_EMAIL + '>',
            to: toEmail,
            subject: subject,
            html: html
        });
        console.log('  [email] OTP sent to ' + toEmail);
        return { sent: true };
    } catch (err) {
        console.error('  [email] Failed to send to ' + toEmail + ':', err.message);
        return { sent: false, reason: err.message };
    }
}

module.exports = { sendOTPEmail };
