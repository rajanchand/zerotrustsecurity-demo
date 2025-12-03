const { supabase } = require('../db');
const { sendOTPEmail } = require('./emailService');

async function generateOTP(userId) {
    const code = String(Math.floor(100000 + Math.random() * 900000));
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();

    // expire all old unused OTPs for this user
    await supabase
        .from('otp_store')
        .update({ used: true })
        .eq('user_id', userId)
        .eq('used', false);

    await supabase.from('otp_store').insert({
        user_id: userId,
        code: code,
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
    const { data: row } = await supabase
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

    const now = new Date();
    const expiry = new Date(row.expires_at);
    if (now > expiry) {
        return { valid: false, reason: 'OTP has expired. Please request a new one.' };
    }

    await supabase.from('otp_store').update({ used: true }).eq('id', row.id);

    return { valid: true };
}

module.exports = { generateOTP, verifyOTP };
