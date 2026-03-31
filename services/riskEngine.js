// services/riskEngine.js
// Calculates a contextual risk score for each login attempt using a
// weighted factor model (NIST SP 800-207 Continuous Verification principle).
// Higher scores indicate more anomalous access patterns.

const { supabase } = require('../db');
const { logSecurityEvent } = require('./monitorService');

// Risk factor weights — total score determines trust level:
//   0-30   => Low    (trusted, may skip MFA on repeat devices)
//   31-60  => Medium (requires OTP verification)
//   61+    => High   (triggers alert + admin notification)
const RISK_WEIGHTS = {
    NEW_DEVICE:       25,  // first time logging in from this device fingerprint
    NEW_COUNTRY:      30,  // login from a country not seen before for this user
    MULTIPLE_FAILURES: 20, // repeated wrong password attempts in this session
    VPN_ANONYMIZER:   30,  // connection originates from a known VPN/proxy range
    UNUSUAL_HOURS:    15,  // login outside standard business hours (6am-10pm)
    ADMIN_UNKNOWN_IP: 40   // admin or IT role logging in from a non-whitelisted IP
};

function getRiskLevel(score) {
    if (score <= 30) return 'Low';
    if (score <= 60) return 'Medium';
    return 'High';
}

// Calculate dynamically requested risk
// params: { userId, isNewDevice, isNewCountry, failedAttempts, isVPN, isAdminUnknownIP, role, isUnusualHours }
async function calculateRisk(params) {
    let score = 0;
    const factors = [];

    // 1. Device Trust
    if (params.isNewDevice) {
        score += RISK_WEIGHTS.NEW_DEVICE;
        factors.push({ factor: 'New Device Detected', points: RISK_WEIGHTS.NEW_DEVICE });
    }

    // 2. Location Anomaly
    if (params.isNewCountry) {
        score += RISK_WEIGHTS.NEW_COUNTRY;
        factors.push({ factor: 'New Country / Location', points: RISK_WEIGHTS.NEW_COUNTRY });
    }

    // 3. Authentication Behavior
    if (params.failedAttempts >= 3) {
        score += RISK_WEIGHTS.MULTIPLE_FAILURES; // Changed from FAILED_LOGINS
        factors.push({ factor: `Multiple Failed Logins (${params.failedAttempts})`, points: RISK_WEIGHTS.MULTIPLE_FAILURES });
    }

    // 4. Network Context
    if (params.isVPN) {
        score += RISK_WEIGHTS.VPN_ANONYMIZER; // Changed from VPN_DETECTED
        factors.push({ factor: 'VPN Connection Detected', points: RISK_WEIGHTS.VPN_ANONYMIZER });
    }

    // 5. Privileged Access
    if (params.isAdminUnknownIP && (params.role === 'SuperAdmin' || params.role === 'IT')) {
        score += RISK_WEIGHTS.ADMIN_UNKNOWN_IP;
        factors.push({ factor: 'Admin Login from Unknown IP', points: RISK_WEIGHTS.ADMIN_UNKNOWN_IP });
    }

    // 6. Remote Work Context: Working Hours Anomaly
    if (params.isUnusualHours) {
        score += RISK_WEIGHTS.UNUSUAL_HOURS;
        factors.push({ factor: 'Login outside typical business hours', points: RISK_WEIGHTS.UNUSUAL_HOURS });
    }

    if (score > 100) score = 100;

    const level = getRiskLevel(score);

    await supabase.from('risk_logs').insert({
        user_id: params.userId,
        score: score,
        level: level,
        factors_json: JSON.stringify({
            factors: factors,
            ip: params.ip || '',
            country: params.country || params.location || ''
        })
    });

    if (score > 0) {
        logSecurityEvent({
            event_type: 'RISK_SCORE_CHANGED',
            user_id: params.userId,
            username: params.username || '',
            ip: params.ip || '',
            risk_score: score,
            details: { level: level, factors: factors, role: params.role }
        }).catch(() => {});
    }

    return { score, level, factors };
}

async function getRiskHistory(userId, limit = 20) {
    const { data } = await supabase
        .from('risk_logs')
        .select('*')
        .eq('user_id', userId)
        .order('created_at', { ascending: false })
        .limit(limit);

    return data || [];
}

async function getAllRiskHistory(limit = 50) {
    const { data: logs } = await supabase
        .from('risk_logs')
        .select('*')
        .order('created_at', { ascending: false })
        .limit(limit);

    if (!logs || !logs.length) return [];

    const userIds = [];
    logs.forEach(r => {
        if (r.user_id && !userIds.includes(r.user_id)) userIds.push(r.user_id);
    });

    const userMap = {};
    if (userIds.length > 0) {
        const { data: users } = await supabase.from('users').select('id, username, role').in('id', userIds);
        (users || []).forEach(u => { userMap[u.id] = u; });
    }

    return logs.map(row => {
        const u = userMap[row.user_id] || {};
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
