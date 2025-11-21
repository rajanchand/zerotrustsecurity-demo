// services/otpService.js
// generates and verifies one-time passwords
// sends the OTP to the user's registered email

var { supabase } = require('../db');
var { sendOTPEmail } = require('./emailService');

// generate a 6-digit OTP and send it to the user's email
async function generateOTP(userId) {
    var code = String(Math.floor(100000 + Math.random() * 900000));
    var expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();

    // expire all old unused OTPs for this user
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

    // look up the user's email and username
    var { data: user } = await supabase
        .from('users')
        .select('email, username')
        .eq('id', userId)
        .single();

    if (user && user.email) {
        // send OTP to the user's registered email
        await sendOTPEmail(user.email, user.username, code);
    } else {
        // fallback: print to console if no email on record
        console.log('OTP for user ' + userId + ': ' + code + ' (no email configured)');
    }

    return code;
}

// verify the code entered by the user
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

    // mark as used
    await supabase.from('otp_store').update({ used: true }).eq('id', row.id);

    return { valid: true };
}

module.exports = { generateOTP, verifyOTP };
