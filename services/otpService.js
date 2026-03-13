const crypto = require('crypto');
const { supabase } = require('../db');
const { sendOTPEmail } = require('./emailService');
const { encrypt, decrypt } = require('./encryptionService');

/**
 * Generate and send an OTP code to a user.
 * @param {string|number} userId - The user's ID.
 */
const generateOTP = async (userId) => {
    const otpCode = String(100000 + crypto.randomInt(900000));
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();

    // Mark old codes as used
    await supabase
        .from('otp_store')
        .update({ used: true })
        .eq('user_id', userId)
        .eq('used', false);

    const encryptedCode = encrypt(otpCode);

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

    if (user?.email) {
        console.log(`\n[OTP] Code: ${otpCode} | User: ${user.username}\n`);

        sendOTPEmail(user.email, user.username, otpCode).catch(() => {
            console.error(`[OTP] Failed to send code for user ID: ${userId}`);
        });
    }

    return otpCode;
};

/**
 * Verify an OTP code for a user.
 * @param {string|number} userId - The user's ID.
 * @param {string} inputCode - The code the user entered.
 */
const verifyOTP = async (userId, inputCode) => {
    const { data: activeCodes } = await supabase
        .from('otp_store')
        .select('*')
        .eq('user_id', userId)
        .eq('used', false)
        .order('created_at', { ascending: false })
        .limit(5);

    if (!activeCodes?.length) {
        return { valid: false, reason: 'No active code found.' };
    }

    let matchedCode = null;
    for (const record of activeCodes) {
        const decrypted = decrypt(record.code);
        if (decrypted === inputCode || record.code === inputCode) {
            matchedCode = record;
            break;
        }
    }

    if (!matchedCode) {
        return { valid: false, reason: 'Wrong code. Please try again.' };
    }

    if (new Date() > new Date(matchedCode.expires_at)) {
        return { valid: false, reason: 'Code has expired. Please request a new one.' };
    }

    await supabase
        .from('otp_store')
        .update({ used: true })
        .eq('id', matchedCode.id);

    return { valid: true };
};

module.exports = { generateOTP, verifyOTP };
