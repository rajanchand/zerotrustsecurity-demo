var { logSecurityEvent } = require('../services/monitorService');

/**
 * Middleware: monitor user behaviour and flag high-risk activity.
 * Checks for too many requests or IP address changes.
 */
function flagHighRisk(req, res, next) {
    if (!req.session?.userId) {
        return next();
    }

    var userId = req.session.userId;
    var now = Date.now();

    // Check if user already has a risk score from login
    if (req.session.riskScore) {
        req.session.highRisk = req.session.riskScore > 60;
    }

    // Set up tracking for this user
    if (!req.session.requestTracker) {
        req.session.requestTracker = {
            requests: [],
            lastIP: req.ip,
            riskBoost: 0
        };
    }

    var tracker = req.session.requestTracker;
    tracker.requests.push(now);

    // Only keep requests from the last 2 minutes
    var twoMinutesAgo = now - 2 * 60 * 1000;
    tracker.requests = tracker.requests.filter(function(t) { return t > twoMinutesAgo; });

    // Get clean IP address
    var ip = (req.headers['x-forwarded-for'] || req.ip || '127.0.0.1')
        .split(',')[0]
        .trim()
        .replace('::ffff:', '');

    // Too many requests in 2 minutes? Add risk
    if (tracker.requests.length > 200) {
        if (!tracker.lastWarning || (now - tracker.lastWarning) > 60000) {
            tracker.lastWarning = now;
            tracker.riskBoost = Math.min(tracker.riskBoost + 10, 40);

            logSecurityEvent({
                event_type: 'RISK_ALERT',
                user_id: userId,
                username: req.session.username || 'System',
                ip: req.ip,
                details: { reason: 'Too many requests', count: tracker.requests.length }
            }).catch(function() {});
        }
    }

    // IP address changed mid-session? Add risk
    if (tracker.lastIP && tracker.lastIP !== ip) {
        tracker.riskBoost = Math.min(tracker.riskBoost + 20, 40);

        logSecurityEvent({
            event_type: 'NETWORK_CHANGE',
            user_id: userId,
            username: req.session.username || 'System',
            ip: ip,
            details: { previous_ip: tracker.lastIP, current_ip: ip }
        }).catch(function() {});

        tracker.lastIP = ip;
    }

    // Apply risk boost to session
    if (tracker.riskBoost > 0) {
        var currentRisk = req.session.riskScore || 0;
        var totalRisk = Math.min(currentRisk + tracker.riskBoost, 100);
        req.session.highRisk = totalRisk > 60;

        // Slowly reduce the boost over time
        tracker.riskBoost = Math.max(0, tracker.riskBoost - 1);
    }

    next();
}

module.exports = { flagHighRisk: flagHighRisk };
