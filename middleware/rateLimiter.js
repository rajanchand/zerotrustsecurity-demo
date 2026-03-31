// middleware/rateLimiter.js
// brute-force protection using sliding window rate limiting
// Production: strict limits | Development: relaxed for testing

const rateLimit = require('express-rate-limit');

const isProd = process.env.NODE_ENV === 'production';

// login endpoint: 10 attempts / 15 min (production) | 200 / 15 min (dev)
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: isProd ? 10 : 200,
    message: { success: false, message: 'Too many login attempts. Please try again after 15 minutes.' },
    standardHeaders: true,
    legacyHeaders: false,
    validate: { xForwardedForHeader: false }
});

// OTP endpoint: 5 attempts / 5 min (production) | 100 / 5 min (dev)
const otpLimiter = rateLimit({
    windowMs: 5 * 60 * 1000,
    max: isProd ? 5 : 100,
    message: { success: false, message: 'Too many OTP attempts. Please try again after 5 minutes.' },
    standardHeaders: true,
    legacyHeaders: false,
    validate: { xForwardedForHeader: false }
});

// general API: 200 requests / 15 min (production) | 2000 / 15 min (dev)
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: isProd ? 200 : 2000,
    message: { error: 'Too many requests. Please slow down.' },
    standardHeaders: true,
    legacyHeaders: false,
    validate: { xForwardedForHeader: false }
});

module.exports = { loginLimiter, otpLimiter, apiLimiter };
