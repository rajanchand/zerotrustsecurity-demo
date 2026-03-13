var crypto = require('crypto');

// HMAC secret for request signing
var HMAC_SECRET = process.env.HMAC_SECRET || process.env.SESSION_SECRET || 'zts-hmac-default';

// Requests older than 5 minutes are rejected
var MAX_AGE = 5 * 60 * 1000;

/**
 * Middleware: verify HMAC signature on requests.
 * If no signature header is sent, skip (not all requests need it).
 */
function verifyHMAC(req, res, next) {
    var signature = req.headers['x-hmac-signature'];
    var timestamp = req.headers['x-hmac-timestamp'];

    // No signature? Skip HMAC check
    if (!signature) {
        req.hmacVerified = false;
        return next();
    }

    if (!timestamp) {
        return res.status(400).json({ success: false, message: 'Request timestamp is required.' });
    }

    var ts = parseInt(timestamp);
    var now = Date.now();

    if (isNaN(ts) || Math.abs(now - ts) > MAX_AGE) {
        return res.status(403).json({ success: false, message: 'Request expired. Please try again.' });
    }

    // Build the expected signature
    var sessionToken = req.session?.sessionToken || '';
    var body = JSON.stringify(req.body || {});
    var payload = sessionToken + body + timestamp;

    var expected = crypto
        .createHmac('sha256', HMAC_SECRET)
        .update(payload)
        .digest('hex');

    // Compare using timing-safe method
    var isValid = false;
    if (signature.length === expected.length) {
        isValid = crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
    }

    if (!isValid) {
        var { logSecurityEvent } = require('../services/monitorService');

        logSecurityEvent({
            event_type: 'INTEGRITY_VIOLATION',
            user_id: req.session?.userId || null,
            username: req.session?.username || 'System',
            ip: req.ip,
            details: {
                path: req.path,
                method: req.method,
                reason: 'HMAC signature mismatch'
            }
        }).catch(function() {});

        return res.status(403).json({ success: false, message: 'Request verification failed.' });
    }

    req.hmacVerified = true;
    next();
}

/**
 * Generate an HMAC signature for a request.
 */
function generateHMAC(sessionToken, requestBody, timestamp) {
    var payload = sessionToken + JSON.stringify(requestBody || {}) + timestamp;
    return crypto.createHmac('sha256', HMAC_SECRET).update(payload).digest('hex');
}

module.exports = { verifyHMAC: verifyHMAC, generateHMAC: generateHMAC };
