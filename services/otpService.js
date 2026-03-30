// services/otpService.js
// OTP generation, verification, and email delivery

var { supabase }                  = require('../db');
var { sendOTPEmail }              = require('./emailService');
var { encrypt, decrypt }          = require('./encryptionService');

async function generateOTP(userId) {
    var code      = String(Math.floor(100000 + Math.random() * 900000));
    var expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();

    // invalidate any old unused OTPs for this user
    await supabase
        .from('otp_store')
        .update({ used: true })
        .eq('user_id', userId)
        .eq('used', false);

    // encrypt before storing
    var encryptedCode = encrypt(code);

    await supabase.from('otp_store').insert({
        user_id:    userId,
        code:       encryptedCode,
        expires_at: expiresAt
    });

    // always print to console so dev can see it regardless of email status
    console.log('\n  ╔══════════════════════════════╗');
    console.log('  ║  OTP for user ID ' + userId + ': ' + code + '  ║');
    console.log('  ╚══════════════════════════════╝\n');

    var { data: user } = await supabase
        .from('users')
        .select('email, username')
        .eq('id', userId)
        .single();

    if (user && user.email) {
        // When using Resend sandbox (onboarding@resend.dev), emails can only
        // be delivered to the account owner. RESEND_TO_EMAIL overrides the
        // recipient so you still receive the OTP during dev/testing.
        var toAddress = process.env.RESEND_TO_EMAIL || user.email;
        sendOTPEmail(toAddress, user.username, code).catch(function () {
            console.log('  [email] Could not send OTP email — use the code printed above');
        });
    }

    return code;
}

async function verifyOTP(userId, code) {
    // fetch recent unused OTPs for this user
    var { data: rows } = await supabase
        .from('otp_store')
        .select('*')
        .eq('user_id', userId)
        .eq('used', false)
        .order('created_at', { ascending: false })
        .limit(5);

    if (!rows || rows.length === 0) {
        return { valid: false, reason: 'Invalid OTP code.' };
    }

    // try to match against encrypted and plain-text codes
    var matchedRow = null;
    for (var i = 0; i < rows.length; i++) {
        var storedCode   = rows[i].code;
        var decryptedCode = decrypt(storedCode);
        if (decryptedCode === code || storedCode === code) {
            matchedRow = rows[i];
            break;
        }
    }

    if (!matchedRow) {
        return { valid: false, reason: 'Invalid OTP code.' };
    }

    var now    = new Date();
    var expiry = new Date(matchedRow.expires_at);
    if (now > expiry) {
        return { valid: false, reason: 'OTP has expired. Please log in again to get a new code.' };
    }

    await supabase.from('otp_store').update({ used: true }).eq('id', matchedRow.id);

    return { valid: true };
}

// get the current active OTP for a user (dev helper — only used in development mode)
async function getActiveOTP(userId) {
    var { data: rows } = await supabase
        .from('otp_store')
        .select('code, expires_at')
        .eq('user_id', userId)
        .eq('used', false)
        .order('created_at', { ascending: false })
        .limit(1);

    if (!rows || rows.length === 0) return null;

    var row       = rows[0];
    var decrypted = decrypt(row.code);
    var expired   = new Date() > new Date(row.expires_at);

    return { code: decrypted, expired: expired, expires_at: row.expires_at };
}

module.exports = { generateOTP, verifyOTP, getActiveOTP };
