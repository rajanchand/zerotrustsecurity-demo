var rateLimit = require('express-rate-limit');

var isProduction = process.env.NODE_ENV === 'production';

// login attempts: 10 per 15 mins in prod
var loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: isProduction ? 10 : 200,
    message: { success: false, message: 'Too many login attempts. Please wait 15 minutes.' },
    standardHeaders: true,
    legacyHeaders: false,
    validate: { xForwardedForHeader: false }
});

// otp attempts: 5 per 5 mins in prod
var otpLimiter = rateLimit({
    windowMs: 5 * 60 * 1000,
    max: isProduction ? 5 : 100,
    message: { success: false, message: 'Too many OTP attempts. Please wait 5 minutes.' },
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
