// middleware/riskCheck.js
// continuous risk assessment — evaluates risk on every request

var { logSecurityEvent } = require('../services/monitorService');

// per-user request tracking for behavioral anomaly detection
var requestTracker = {};

function flagHighRisk(req, res, next) {
    if (!req.session || !req.session.userId) {
        return next();
    }

    var userId = req.session.userId;
    var now = Date.now();

    // 1. Static risk check from login
    if (req.session.riskScore) {
        req.session.highRisk = req.session.riskScore > 60;
    }

    // 2. CONTINUOUS RISK: detect behavioral anomalies per-request

    // initialize tracker for this user
    if (!requestTracker[userId]) {
        requestTracker[userId] = { requests: [], lastIP: req.ip, riskDelta: 0 };
    }
    var tracker = requestTracker[userId];

    // add current request timestamp
    tracker.requests.push(now);

    // keep only last 2 minutes of requests
    var twoMinAgo = now - 2 * 60 * 1000;
    tracker.requests = tracker.requests.filter(function (t) { return t > twoMinAgo; });

    // Normalise the client IP once — used for velocity logging and IP-change detection
    var rawIp    = req.headers['x-forwarded-for'] || req.ip || '127.0.0.1';
    var currentIP = rawIp.split(',')[0].trim().replace('::ffff:', '');

    // Check: request velocity anomaly (>200 requests in 2 minutes = genuine automation/attack)
    if (tracker.requests.length > 200) {
        var now2 = Date.now();
        // only log once per 60 seconds per user to prevent flooding
        if (!tracker.lastAnomalyLog || (now2 - tracker.lastAnomalyLog) > 60000) {
            tracker.lastAnomalyLog = now2;
            tracker.riskDelta = Math.min(tracker.riskDelta + 10, 40);
            logSecurityEvent({
                event_type: 'BEHAVIORAL_ANOMALY',
                user_id: userId,
                username: req.session.username || 'unknown',
                ip: req.ip,
                details: { reason: 'High request velocity', count: tracker.requests.length, window: '2min' }
            }).catch(function () { });
        }
    }

    // Check: IP changed mid-session (use the same normalised currentIP throughout)
    if (tracker.lastIP && tracker.lastIP !== currentIP) {
        tracker.riskDelta = Math.min(tracker.riskDelta + 20, 40);
        logSecurityEvent({
            event_type: 'IP_CHANGE_MIDSESSION',
            user_id: userId,
            username: req.session.username || 'unknown',
            ip: currentIP,
            details: { reason: 'IP address changed during active session', previous_ip: tracker.lastIP, new_ip: currentIP }
        }).catch(function () { });
        tracker.lastIP = currentIP;
    }

    // Apply continuous risk delta to session risk score
    if (tracker.riskDelta > 0) {
        var baseScore = req.session.riskScore || 0;
        var effectiveScore = Math.min(baseScore + tracker.riskDelta, 100);
        req.session.highRisk = effectiveScore > 60;

        // slowly decay risk delta over time
        tracker.riskDelta = Math.max(0, tracker.riskDelta - 1);
    }

    next();
}

// Cleanup stale trackers every 10 minutes.
// Remove entries that have had no requests in the last 10 minutes OR have an empty request list.
setInterval(function () {
    var cutoff = Date.now() - 10 * 60 * 1000;
    Object.keys(requestTracker).forEach(function (uid) {
        var t = requestTracker[uid];
        var lastSeen = t.requests.length ? t.requests[t.requests.length - 1] : 0;
        if (lastSeen < cutoff) {
            delete requestTracker[uid];
        }
    });
}, 10 * 60 * 1000).unref(); // .unref() so this timer doesn't prevent process from exiting cleanly

module.exports = { flagHighRisk };
