// services/riskEngine.js

var { supabase } = require('../db');
var { logSecurityEvent } = require('./monitorService');

var RISK_WEIGHTS = {
    NEW_DEVICE: 25,
    NEW_COUNTRY: 30,
    FAILED_LOGINS: 20,
    VPN_DETECTED: 15,
    ADMIN_UNKNOWN_IP: 35
};

function getRiskLevel(score) {
    if (score <= 30) return 'Low';
    if (score <= 60) return 'Medium';
    return 'High';
}

// calculate the risk score for a login attempt
async function calculateRisk(params) {
    var score = 0;
    var factors = [];

    if (params.isNewDevice) {
        score += RISK_WEIGHTS.NEW_DEVICE;
        factors.push({ factor: 'New Device Detected', points: RISK_WEIGHTS.NEW_DEVICE });
    }

    if (params.isNewCountry) {
        score += RISK_WEIGHTS.NEW_COUNTRY;
        factors.push({ factor: 'New Country / Location', points: RISK_WEIGHTS.NEW_COUNTRY });
    }

    if (params.failedAttempts >= 3) {
        score += RISK_WEIGHTS.FAILED_LOGINS;
        factors.push({ factor: 'Multiple Failed Logins (' + params.failedAttempts + ')', points: RISK_WEIGHTS.FAILED_LOGINS });
    }

    if (params.isVPN) {
        score += RISK_WEIGHTS.VPN_DETECTED;
        factors.push({ factor: 'VPN Connection Detected', points: RISK_WEIGHTS.VPN_DETECTED });
    }

    if (params.isAdminUnknownIP && (params.role === 'SuperAdmin' || params.role === 'IT')) {
        score += RISK_WEIGHTS.ADMIN_UNKNOWN_IP;
        factors.push({ factor: 'Admin Login from Unknown IP', points: RISK_WEIGHTS.ADMIN_UNKNOWN_IP });
    }

    // cap at 100
    if (score > 100) score = 100;

    var level = getRiskLevel(score);

    // save to database
    await supabase.from('risk_logs').insert({
        user_id: params.userId,
        score: score,
        level: level,
        factors_json: JSON.stringify(factors)
    });

    // emit to SIEM monitor
    if (score > 0) {
        logSecurityEvent({
            event_type: 'RISK_SCORE_CHANGED',
            user_id: params.userId,
            username: params.username || '',
            ip: params.ip || '',
            risk_score: score,
            details: { level: level, factors: factors, role: params.role }
        }).catch(function() {});
    }

    return { score: score, level: level, factors: factors };
}

// get risk history for a user
async function getRiskHistory(userId, limit) {
    limit = limit || 20;
    var { data } = await supabase
        .from('risk_logs')
        .select('*')
        .eq('user_id', userId)
        .order('created_at', { ascending: false })
        .limit(limit);

    return data || [];
}

// get risk history for all users (admin view)
async function getAllRiskHistory(limit) {
    limit = limit || 50;
    var { data: logs } = await supabase
        .from('risk_logs')
        .select('*')
        .order('created_at', { ascending: false })
        .limit(limit);

    if (!logs || !logs.length) return [];

    // get unique user IDs
    var userIds = [];
    logs.forEach(function (r) {
        if (r.user_id && userIds.indexOf(r.user_id) === -1) userIds.push(r.user_id);
    });

    var userMap = {};
    if (userIds.length > 0) {
        var { data: users } = await supabase.from('users').select('id, username, role').in('id', userIds);
        (users || []).forEach(function (u) { userMap[u.id] = u; });
    }

    return logs.map(function (row) {
        var u = userMap[row.user_id] || {};
        return {
            id: row.id,
            user_id: row.user_id,
            score: row.score,
            level: row.level,
            factors_json: row.factors_json,
            created_at: row.created_at,
            username: u.username || 'Unknown',
            role: u.role || 'Unknown'
        };
    });
}

module.exports = { calculateRisk, getRiskHistory, getAllRiskHistory, RISK_WEIGHTS, getRiskLevel };
