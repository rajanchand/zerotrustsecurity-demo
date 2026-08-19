var rateLimit = require('express-rate-limit');

var isProduction = process.env.NODE_ENV === 'production';

// login attempts: 50 per 2 mins for demo and brute-force protection
var loginLimiter = rateLimit({
    windowMs: 2 * 60 * 1000,
    max: 50,
    message: { success: false, message: 'Too many login attempts. Please wait 1 minute.' },
    standardHeaders: true,
    legacyHeaders: false,
    validate: { xForwardedForHeader: false }
});

// otp attempts: 30 per 2 mins
var otpLimiter = rateLimit({
    windowMs: 2 * 60 * 1000,
    max: 30,
    message: { success: false, message: 'Too many OTP attempts. Please wait 1 minute.' },
    standardHeaders: true,
    legacyHeaders: false,
    validate: { xForwardedForHeader: false }
});

// general api limit: 200 per 15 mins in prod
var apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: isProduction ? 200 : 2000,
    message: { error: 'Too many requests. Please slow down.' },
    standardHeaders: true,
    legacyHeaders: false,
    validate: { xForwardedForHeader: false }
});

module.exports = {
    loginLimiter: loginLimiter,
    otpLimiter: otpLimiter,
    apiLimiter: apiLimiter
};
