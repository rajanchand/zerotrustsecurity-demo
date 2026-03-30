require('dotenv').config();
const { generateOTP } = require('./services/otpService');

async function run() {
    console.log('Testing OTP generation for user ID 7 (rajan.chand)...');
    try {
        const code = await generateOTP(7);
        console.log('Generated OTP:', code);
    } catch (e) {
        console.error('Error:', e);
    }
    process.exit(0);
}

run();
