// middleware/csrf.js
// double-submit CSRF protection using session-bound tokens

const crypto = require('crypto');

function generateCSRFToken(req) {
    if (!req.session.csrfToken) {
        req.session.csrfToken = crypto.randomBytes(32).toString('hex');
    }
    return req.session.csrfToken;
}

// paths that are exempt from CSRF (pre-auth or public)
const EXEMPT_PATHS = ['/login', '/logout', '/verify-otp', '/otp'];

function csrfProtection(req, res, next) {
    // only check POST/PUT/DELETE methods
    if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') {
        return next();
    }

    // skip CSRF for exempt paths
    if (EXEMPT_PATHS.includes(req.path)) {
        return next();
    }

    // skip if not authenticated yet
    if (!req.session || !req.session.userId) {
        return next();
    }

    var token = req.headers['x-csrf-token'] || req.body._csrfToken;

    if (!token || token !== req.session.csrfToken) {
        var { logSecurityEvent } = require('../services/monitorService');
        logSecurityEvent({
            event_type: 'CSRF_VIOLATION',
            user_id: req.session.userId,
            username: req.session.username || 'unknown',
            ip: req.ip,
            details: { path: req.path, method: req.method }
        }).catch(function () { });

        return res.status(403).json({ success: false, message: 'CSRF token invalid. Please refresh the page.' });
    }

    next();
}

module.exports = { generateCSRFToken, csrfProtection };
