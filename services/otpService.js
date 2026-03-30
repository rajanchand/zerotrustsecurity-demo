// services/otpService.js
// OTP generation and verification

var { supabase }       = require('../db');
var { sendOTPEmail }   = require('./emailService');
var { encrypt, decrypt } = require('./encryptionService');

async function generateOTP(userId) {
    var code      = String(Math.floor(100000 + Math.random() * 900000));
    var expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();

    // invalidate any unused OTPs still open for this user
    await supabase
        .from('otp_store')
        .update({ used: true })
        .eq('user_id', userId)
        .eq('used', false);

    // encrypt the code before writing to database
    var encryptedCode = encrypt(code);

    await supabase.from('otp_store').insert({
        user_id:    userId,
        code:       encryptedCode,
        expires_at: expiresAt
    });

    // look up the user's registered email and send the code
    var { data: user } = await supabase
        .from('users')
        .select('email, username')
        .eq('id', userId)
        .single();

    if (user && user.email) {
        sendOTPEmail(user.email, user.username, code).catch(function () {
            console.error('  [otp] Failed to send OTP email for user ' + userId);
        });
    }

    return code;
}

async function verifyOTP(userId, code) {
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

    var matchedRow = null;
    for (var i = 0; i < rows.length; i++) {
        var decryptedCode = decrypt(rows[i].code);
        if (decryptedCode === code || rows[i].code === code) {
            matchedRow = rows[i];
            break;
        }
    }

    if (!matchedRow) {
        return { valid: false, reason: 'Invalid OTP code.' };
    }

    if (new Date() > new Date(matchedRow.expires_at)) {
        return { valid: false, reason: 'OTP has expired. Please log in again to get a new code.' };
    }

    await supabase.from('otp_store').update({ used: true }).eq('id', matchedRow.id);

    return { valid: true };
}

module.exports = { generateOTP, verifyOTP };
