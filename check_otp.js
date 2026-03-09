#!/usr/bin/env node
// check_otp.js
// Utility to check/decrypt the latest OTP for a user for debugging on VPS.

require('dotenv').config();
const { supabase } = require('./db');
const { decrypt } = require('./services/encryptionService');

async function checkOtp(username) {
    if (!username) {
        console.log('\nUsage: node check_otp.js <username>');
        process.exit(1);
    }

    try {
        // 1. Find user by username
        const { data: user, error: userError } = await supabase
            .from('users')
            .select('id, email')
            .eq('username', username)
            .single();

        if (userError || !user) {
            console.error(`\n[Error] User "${username}" not found.`);
            if (userError) console.error(`Details: ${userError.message}`);
            process.exit(1);
        }

        console.log(`\nChecking OTP for: ${username} (ID: ${user.id}, Email: ${user.email})`);

        // 2. Get latest unused OTP
        const { data: rows, error: otpError } = await supabase
            .from('otp_store')
            .select('*')
            .eq('user_id', user.id)
            .eq('used', false)
            .order('created_at', { ascending: false })
            .limit(1);

        if (otpError) {
            console.error(`[Error] Failed to fetch OTP: ${otpError.message}`);
            process.exit(1);
        }

        if (!rows || rows.length === 0) {
            console.log('\n[Result] No active/unused OTP found for this user.');
            return;
        }

        const row = rows[0];
        const decryptedCode = decrypt(row.code);

        const now = new Date();
        const expiry = new Date(row.expires_at);
        const isExpired = now > expiry;

        console.log('\n=========================================');
        console.log('           OTP INFORMATION               ');
        console.log('=========================================');
        console.log(`Code:       \x1b[32m${decryptedCode}\x1b[0m`); // Green text for code
        console.log(`Expires At: ${expiry.toLocaleString()}`);
        console.log(`Created At: ${new Date(row.created_at).toLocaleString()}`);
        console.log(`Status:     ${isExpired ? '\x1b[31mExpired\x1b[0m' : '\x1b[32mActive\x1b[0m'}`);
        console.log('=========================================\n');

    } catch (err) {
        console.error('\n[Exception] An error occurred:', err.message);
    }
}

const usernameArg = process.argv[2];
checkOtp(usernameArg);
