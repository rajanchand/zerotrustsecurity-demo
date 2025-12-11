// middleware/hmacVerify.js
// API request integrity verification using HMAC-SHA256 signatures

const crypto = require('crypto');

const HMAC_SECRET = process.env.HMAC_SECRET || process.env.SESSION_SECRET || 'zts-hmac-default';
const MAX_TIMESTAMP_DRIFT = 5 * 60 * 1000; // 5 minutes — replay protection

function verifyHMAC(req, res, next) {
    var signature = req.headers['x-hmac-signature'];
    var timestamp = req.headers['x-hmac-timestamp'];

    // skip if no signature header present (allow graceful degradation)
    if (!signature) {
        // mark request as unsigned for audit
        req.hmacVerified = false;
        return next();
    }

    // check timestamp freshness (replay protection)
    if (!timestamp) {
        return res.status(400).json({ success: false, message: 'Missing HMAC timestamp.' });
    }

    var ts = parseInt(timestamp);
    var now = Date.now();
    if (isNaN(ts) || Math.abs(now - ts) > MAX_TIMESTAMP_DRIFT) {
        return res.status(403).json({ success: false, message: 'Request expired or invalid timestamp.' });
    }

    // build the payload to sign: sessionToken + body + timestamp
    var sessionToken = (req.session && req.session.sessionToken) || '';
    var body = JSON.stringify(req.body || {});
    var payload = sessionToken + body + timestamp;

    var expectedSignature = crypto
        .createHmac('sha256', HMAC_SECRET)
        .update(payload)
        .digest('hex');

    if (signature !== expectedSignature) {
        var { logSecurityEvent } = require('../services/monitorService');
        logSecurityEvent({
            event_type: 'HMAC_VIOLATION',
            user_id: req.session ? req.session.userId : null,
            username: req.session ? req.session.username : 'unknown',
            ip: req.ip,
            details: { path: req.path, method: req.method, reason: 'Invalid HMAC signature' }
        }).catch(function () { });

        return res.status(403).json({ success: false, message: 'Invalid request signature.' });
    }

    req.hmacVerified = true;
    next();
}

// utility: generate HMAC for testing/client use
function generateHMAC(sessionToken, body, timestamp) {
    var payload = sessionToken + JSON.stringify(body || {}) + timestamp;
    return crypto.createHmac('sha256', HMAC_SECRET).update(payload).digest('hex');
}

module.exports = { verifyHMAC, generateHMAC };
