var crypto = require('crypto');

// timing safe comparison to prevent timing attacks
function safeCompare(a, b) {
    if (!a || !b || a.length !== b.length) {
        return false;
    }
    return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

// create a csrf token if session doesnt have one
function generateCSRFToken(req) {
    if (!req.session.csrfToken) {
        req.session.csrfToken = crypto.randomBytes(32).toString('hex');
    }
    return req.session.csrfToken;
}

// paths that skip csrf checking
var SKIP_PATHS = ['/logout'];

// check csrf token on POST/PUT/DELETE requests
function csrfProtection(req, res, next) {
    // GET requests dont need csrf
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
        return next();
    }

    // skip excluded paths
    if (SKIP_PATHS.includes(req.path)) {
        return next();
    }

    var token = req.headers['x-csrf-token'] || req.body._csrfToken;

    if (!token || !safeCompare(token, req.session.csrfToken)) {
        var { logSecurityEvent } = require('../services/monitorService');

        logSecurityEvent({
            event_type: 'CSRF_STATE_VIOLATION',
            user_id: req.session.userId,
            username: req.session.username || 'System',
            ip: req.ip,
            details: { path: req.path, method: req.method }
        }).catch(function() {});

        return res.status(403).json({
            success: false,
            message: 'Session expired. Please refresh the page and try again.'
        });
    }

    next();
}

module.exports = {
    generateCSRFToken: generateCSRFToken,
    csrfProtection: csrfProtection
};
