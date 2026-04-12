var crypto = require('crypto');
var { supabase } = require('../db');
var { sendOTPEmail } = require('./emailService');
var { encrypt, decrypt } = require('./encryptionService');

// generate a 6 digit otp and send it to the user
async function generateOTP(userId) {
    var otpCode = String(100000 + crypto.randomInt(900000));
    var expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();

    // mark old codes as used first
    await supabase
        .from('otp_store')
        .update({ used: true })
        .eq('user_id', userId)
        .eq('used', false);

    var encryptedCode = encrypt(otpCode);

    await supabase.from('otp_store').insert({
        user_id: userId,
        code: encryptedCode,
        expires_at: expiresAt
    });

    var { data: user } = await supabase
        .from('users')
        .select('email, username')
        .eq('id', userId)
        .single();

    if (user && user.email) {
        // only log otp to console in dev mode
        if (process.env.NODE_ENV !== 'production') {
            console.log('\n[OTP] Code: ' + otpCode + ' | User: ' + user.username + '\n');
        }

        sendOTPEmail(user.email, user.username, otpCode).catch(function() {
            console.error('[OTP] Failed to send code for user ID: ' + userId);
        });
    }

    return otpCode;
}

// verify the otp code user entered
async function verifyOTP(userId, inputCode) {
    var { data: activeCodes } = await supabase
        .from('otp_store')
        .select('*')
        .eq('user_id', userId)
        .eq('used', false)
        .order('created_at', { ascending: false })
        .limit(5);

    if (!activeCodes || !activeCodes.length) {
        return { valid: false, reason: 'No active code found.' };
    }

    var matchedCode = null;
    for (var i = 0; i < activeCodes.length; i++) {
        var record = activeCodes[i];
        var decrypted = decrypt(record.code);
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
}

module.exports = { generateOTP: generateOTP, verifyOTP: verifyOTP };
