var { logSecurityEvent } = require('../services/monitorService');
var geoService = require('../services/geoService');

// track user behaviour and flag risky activity
// looks at request rate and ip changes
async function flagHighRisk(req, res, next) {
    if (!req.session?.userId) {
        return next();
    }

    var userId = req.session.userId;
    var now = Date.now();

    // carry over risk score from login
    if (req.session.riskScore) {
        req.session.highRisk = req.session.riskScore > 60;
    }

    // setup tracking for this user if not done yet
    if (!req.session.requestTracker) {
        req.session.requestTracker = {
            count: 0,
            windowStart: now,
            lastIP: req.ip,
            riskBoost: 0
        };
    }

    var tracker = req.session.requestTracker;
    tracker.count++;

    // reset counter every 2 minutes
    var twoMinutesAgo = now - 2 * 60 * 1000;
    if (tracker.windowStart < twoMinutesAgo) {
        tracker.count = 1;
        tracker.windowStart = now;
    }

    // get clean ip address
    var ip = (req.headers['x-forwarded-for'] || req.ip || '127.0.0.1')
        .split(',')[0]
        .trim()
        .replace('::ffff:', '');

    // too many requests in 2 minutes, add risk
    if (tracker.count > 200) {
        var geoData1 = await geoService.getGeoFromIP(ip);
        var country1 = geoData1.country || 'Unknown';

        if (!tracker.lastWarning || (now - tracker.lastWarning) > 60000) {
            tracker.lastWarning = now;
            tracker.riskBoost = Math.min(tracker.riskBoost + 10, 40);

            logSecurityEvent({
                event_type: 'RISK_ALERT',
                user_id: userId,
                username: req.session.username || 'System',
                ip: ip,
                location: country1,
                details: { reason: 'Too many requests', count: tracker.count }
            }).catch(function() {});
        }
    }

    if (tracker.lastIP && tracker.lastIP !== ip) {
        var geoData2 = await geoService.getGeoFromIP(ip);
        var country2 = geoData2.country || 'Unknown';

        tracker.riskBoost = Math.min(tracker.riskBoost + 20, 40);

        logSecurityEvent({
            event_type: 'NETWORK_CHANGE',
            user_id: userId,
            username: req.session.username || 'System',
            ip: ip,
            location: country2,
            details: { previous_ip: tracker.lastIP, current_ip: ip }
        }).catch(function() {});

        tracker.lastIP = ip;
    }

    // apply the risk boost
    if (tracker.riskBoost > 0) {
        var currentRisk = req.session.riskScore || 0;
        var totalRisk = Math.min(currentRisk + tracker.riskBoost, 100);
        req.session.highRisk = totalRisk > 60;

        // slowly reduce the boost over time
        tracker.riskBoost = Math.max(0, tracker.riskBoost - 1);
    }

    next();
}

module.exports = { flagHighRisk: flagHighRisk };
