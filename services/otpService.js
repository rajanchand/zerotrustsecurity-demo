// services/otpService.js
// one-time password generation and verification

var { supabase } = require('../db');

// create a 6-digit OTP code
async function generateOTP(userId) {
    var code = String(Math.floor(100000 + Math.random() * 900000));
    var expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();

    // mark any old unused OTPs
    await supabase
        .from('otp_store')
        .update({ used: true })
        .eq('user_id', userId)
        .eq('used', false);

    // save the new code
    await supabase.from('otp_store').insert({
        user_id: userId,
        code: code,
        expires_at: expiresAt
    });

    console.log('OTP for user ' + userId + ': ' + code);
    return code;
}

// check if the entered code is valid
async function verifyOTP(userId, code) {
    var { data: row } = await supabase
        .from('otp_store')
        .select('*')
        .eq('user_id', userId)
        .eq('code', code)
        .eq('used', false)
        .order('created_at', { ascending: false })
        .limit(1)
        .single();

    if (!row) {
        return { valid: false, reason: 'Invalid OTP code.' };
    }

    var now = new Date();
    var expiry = new Date(row.expires_at);
    if (now > expiry) {
        return { valid: false, reason: 'OTP has expired. Please request a new one.' };
    }

    // mark it as used
    await supabase.from('otp_store').update({ used: true }).eq('id', row.id);

    return { valid: true };
}

module.exports = { generateOTP, verifyOTP };
