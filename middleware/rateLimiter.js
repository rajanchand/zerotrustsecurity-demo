var rateLimit = require('express-rate-limit');

var isProduction = process.env.NODE_ENV === 'production';

// Limit login attempts (10 per 15 min in production)
var loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: isProduction ? 10 : 200,
    message: { success: false, message: 'Too many login attempts. Please wait 15 minutes.' },
    standardHeaders: true,
    legacyHeaders: false,
    validate: { xForwardedForHeader: false }
});

// Limit OTP attempts (5 per 5 min in production)
var otpLimiter = rateLimit({
    windowMs: 5 * 60 * 1000,
    max: isProduction ? 5 : 100,
    message: { success: false, message: 'Too many OTP attempts. Please wait 5 minutes.' },
    standardHeaders: true,
    legacyHeaders: false,
    validate: { xForwardedForHeader: false }
});

// General API rate limit (200 per 15 min in production)
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
