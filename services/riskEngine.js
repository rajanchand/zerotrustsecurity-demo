var { supabase } = require('../db');
var { logSecurityEvent } = require('./monitorService');

// How many points each risk factor adds
var RISK_POINTS = {
    NEW_DEVICE: 25,
    NEW_COUNTRY: 30,
    FAILED_LOGINS: 20,
    VPN: 30,
    OFF_HOURS: 15,
    ADMIN_UNKNOWN_IP: 40
};

/**
 * Get risk level from score: Low (0-30), Medium (31-60), High (61+)
 */
function getRiskLevel(score) {
    if (score <= 30) return 'Low';
    if (score <= 60) return 'Medium';
    return 'High';
}

/**
 * Calculate risk score for a login attempt.
 * Returns { score, level, factors }
 */
async function calculateRisk(data) {
    var score = 0;
    var factors = [];

    if (data.isNewDevice) {
        score += RISK_POINTS.NEW_DEVICE;
        factors.push({ factor: 'Unknown device', points: RISK_POINTS.NEW_DEVICE });
    }

    if (data.isNewCountry) {
        score += RISK_POINTS.NEW_COUNTRY;
        factors.push({ factor: 'New location', points: RISK_POINTS.NEW_COUNTRY });
    }

    if (data.failedAttempts >= 3) {
        score += RISK_POINTS.FAILED_LOGINS;
        factors.push({ factor: 'Failed logins (' + data.failedAttempts + ' attempts)', points: RISK_POINTS.FAILED_LOGINS });
    }

    if (data.isVPN) {
        score += RISK_POINTS.VPN;
        factors.push({ factor: 'VPN detected', points: RISK_POINTS.VPN });
    }

    if (data.isAdminUnknownIP && ['SuperAdmin', 'IT'].includes(data.role)) {
        score += RISK_POINTS.ADMIN_UNKNOWN_IP;
        factors.push({ factor: 'Admin on unknown network', points: RISK_POINTS.ADMIN_UNKNOWN_IP });
    }

    if (data.isUnusualHours) {
        score += RISK_POINTS.OFF_HOURS;
        factors.push({ factor: 'Off-hours login', points: RISK_POINTS.OFF_HOURS });
    }

    // Adjust for network trust (can add or reduce risk)
    if (data.networkTrustModifier) {
        score += data.networkTrustModifier;
        if (data.networkTrustModifier < 0) {
            factors.push({ factor: 'Known network', points: data.networkTrustModifier });
        } else if (data.networkTrustModifier > 0) {
            factors.push({ factor: 'Untrusted network', points: data.networkTrustModifier });
        }
    }

    // Keep score between 0 and 100
    score = Math.min(100, Math.max(0, score));

    var level = getRiskLevel(score);

    // Save to database
    await supabase.from('risk_logs').insert({
        user_id: data.userId,
        score: score,
        level: level,
        factors_json: JSON.stringify({
            factors: factors,
            ip: data.ip || 'Unknown',
            country: data.country || data.location || 'Unknown'
        })
    });

    // Log security event if risk > 0
    if (score > 0) {
        logSecurityEvent({
            event_type: 'RISK_SCORE_THRESHOLD_ADJUSTED',
            user_id: data.userId,
            username: data.username || 'System',
            ip: data.ip || '',
            risk_score: score,
            details: { level: level, factors: factors, role: data.role }
        }).catch(function() {});
    }

    return {
        score: score,
        level: level,
        factors: factors
    };
}

/**
 * Get risk history for a user.
 */
async function getRiskHistory(userId, limit) {
    limit = limit || 20;
    var { data: logs } = await supabase
        .from('risk_logs')
        .select('*')
        .eq('user_id', userId)
        .order('created_at', { ascending: false })
        .limit(limit);

    return logs || [];
}

/**
 * Get all risk logs (for admin view).
 */
async function getAllRiskHistory(limit) {
    limit = limit || 50;
    var { data: logs } = await supabase
        .from('risk_logs')
        .select('*')
        .order('created_at', { ascending: false })
        .limit(limit);

    if (!logs || logs.length === 0) return [];

    // Get usernames for each log
    var userIds = [];
    logs.forEach(function(log) {
        if (log.user_id && userIds.indexOf(log.user_id) === -1) {
            userIds.push(log.user_id);
        }
    });

    var userMap = {};
    if (userIds.length > 0) {
        var { data: users } = await supabase
            .from('users')
            .select('id, username, role')
            .in('id', userIds);

        (users || []).forEach(function(u) { userMap[u.id] = u; });
    }

    return logs.map(function(log) {
        var user = userMap[log.user_id] || {};
        return {
            id: log.id,
            user_id: log.user_id,
            score: log.score,
            level: log.level,
            factors_json: log.factors_json,
            created_at: log.created_at,
            username: user.username || 'Unknown',
            role: user.role || 'N/A'
        };
    });
}

module.exports = {
    calculateRisk: calculateRisk,
    getRiskHistory: getRiskHistory,
    getAllRiskHistory: getAllRiskHistory,
    RISK_WEIGHTS: RISK_POINTS,
    getRiskLevel: getRiskLevel
};
