// services/otpService.js
// OTP generation, verification, and email delivery

const { supabase } = require('../db');
const { sendOTPEmail } = require('./emailService');
const { encrypt, decrypt } = require('./encryptionService');

async function generateOTP(userId) {
    const code = String(Math.floor(100000 + Math.random() * 900000));
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();

    // expire all old unused OTPs for this user
    await supabase
        .from('otp_store')
        .update({ used: true })
        .eq('user_id', userId)
        .eq('used', false);

    // encrypt the OTP code before storing
    const encryptedCode = encrypt(code);

    await supabase.from('otp_store').insert({
        user_id: userId,
        code: encryptedCode,
        expires_at: expiresAt
    });

    const { data: user } = await supabase
        .from('users')
        .select('email, username')
        .eq('id', userId)
        .single();

    if (user && user.email) {
        await sendOTPEmail(user.email, user.username, code);
    } else {
        console.log(`OTP for user ${userId}: ${code} (no email configured)`);
    }

    return code;
}

async function verifyOTP(userId, code) {
    // fetch all unused OTPs for this user (check encrypted values)
    const { data: rows } = await supabase
        .from('otp_store')
        .select('*')
        .eq('user_id', userId)
        .eq('used', false)
        .order('created_at', { ascending: false })
        .limit(5);

    if (!rows || rows.length === 0) {
        return { valid: false, reason: 'Invalid OTP code.' };
    }

    // find matching OTP (may be encrypted or plaintext for backwards compat)
    var matchedRow = null;
    for (var i = 0; i < rows.length; i++) {
        var storedCode = rows[i].code;
        var decryptedCode = decrypt(storedCode);
        if (decryptedCode === code) {
            matchedRow = rows[i];
            break;
        }
    }

    if (!matchedRow) {
        return { valid: false, reason: 'Invalid OTP code.' };
    }

    const now = new Date();
    const expiry = new Date(matchedRow.expires_at);
    if (now > expiry) {
        return { valid: false, reason: 'OTP has expired. Please request a new one.' };
    }

    await supabase.from('otp_store').update({ used: true }).eq('id', matchedRow.id);

    return { valid: true };
}

module.exports = { generateOTP, verifyOTP };
