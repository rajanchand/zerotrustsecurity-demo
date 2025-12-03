// services/monitorService.js

const { supabase } = require('../db');

// list of active SSE response objects (one per browser tab)
let clients = [];

var SEVERITY = {
    LOGIN_SUCCESS: 'INFO',
    LOGIN_FAILED: 'HIGH',
    OTP_SENT: 'INFO',
    OTP_SUCCESS: 'INFO',
    OTP_FAILED: 'HIGH',
    ACCESS_DENIED: 'CRITICAL',
    ROLE_CHANGED: 'HIGH',
    USER_CREATED: 'MEDIUM',
    USER_DELETED: 'CRITICAL',
    DEVICE_NEW: 'MEDIUM',
    LOCATION_NEW: 'MEDIUM',
    VPN_DETECTED: 'HIGH',
    IMPOSSIBLE_TRAVEL: 'CRITICAL',
    RISK_SCORE_CHANGED: 'MEDIUM',
    USER_BLOCKED: 'HIGH',
    USER_UNBLOCKED: 'MEDIUM',
    FORCE_LOGOUT: 'HIGH'
};

function getSeverity(eventType) {
    return SEVERITY[eventType] || 'INFO';
}

function addClient(res) {
    clients.push(res);
    res.on('close', () => {
        clients = clients.filter(c => c !== res);
    });
}

function broadcast(event) {
    const data = `data: ${JSON.stringify(event)}\n\n`;
    clients.forEach(res => {
        try { res.write(data); } catch (e) { }
    });
}

async function logSecurityEvent(opts) {
    const event = {
        event_type: opts.event_type || 'UNKNOWN',
        severity: opts.severity || getSeverity(opts.event_type),
        user_id: opts.user_id || null,
        username: opts.username || 'system',
        ip: opts.ip || '',
        location: opts.location || '',
        device_id: opts.device_id || null,
        risk_score: opts.risk_score || 0,
        details: opts.details || {},
        timestamp: new Date().toISOString()
    };

    try {
        const { data } = await supabase
            .from('security_events')
            .insert(event)
            .select()
            .single();
        if (data && data.id) {
            event.id = data.id;
            event.timestamp = data.timestamp;
        }
    } catch (e) { }

    try {
        await supabase.from('audit_log').insert({
            user_id: event.user_id,
            action: event.event_type,
            detail: JSON.stringify(event.details),
            ip: event.ip
        });
    } catch (e) { }

    broadcast(event);

    return event;
}

async function getRecentEvents(limit = 100) {
    try {
        const { data, error } = await supabase
            .from('security_events')
            .select('*')
            .order('timestamp', { ascending: false })
            .limit(limit);

        if (!error && data && data.length > 0) {
            return data;
        }
    } catch (e) { }

    try {
        const { data: logs } = await supabase
            .from('audit_log')
            .select('id, user_id, action, detail, ip, created_at')
            .order('created_at', { ascending: false })
            .limit(limit);

        if (!logs) return [];

        const userIds = [];
        logs.forEach(r => {
            if (r.user_id && !userIds.includes(r.user_id)) userIds.push(r.user_id);
        });

        const userMap = {};
        if (userIds.length > 0) {
            const { data: users } = await supabase
                .from('users')
                .select('id, username')
                .in('id', userIds);
            (users || []).forEach(u => { userMap[u.id] = u.username; });
        }

        return logs.map(row => {
            let details = {};
            try { details = JSON.parse(row.detail || '{}'); } catch (e) { details = { note: row.detail }; }
            return {
                id: row.id,
                event_type: row.action,
                severity: getSeverity(row.action),
                user_id: row.user_id,
                username: userMap[row.user_id] || 'system',
                ip: row.ip || '',
                location: '',
                risk_score: 0,
                details: details,
                timestamp: row.created_at
            };
        });
    } catch (e) {
        return [];
    }
}

async function getStats24h() {
    const since = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    let rows = [];

    try {
        const { data } = await supabase
            .from('security_events')
            .select('event_type, severity, risk_score')
            .gte('timestamp', since);
        if (data && data.length > 0) rows = data;
    } catch (e) { }

    if (rows.length === 0) {
        try {
            const { data: logs } = await supabase
                .from('audit_log')
                .select('action')
                .gte('created_at', since);
            rows = (logs || []).map(r => ({ event_type: r.action, severity: getSeverity(r.action), risk_score: 0 }));
        } catch (e) { }
    }

    return {
        total: rows.length,
        critical: rows.filter(e => e.severity === 'CRITICAL').length,
        high: rows.filter(e => e.severity === 'HIGH').length,
        login_failed: rows.filter(e => e.event_type === 'LOGIN_FAILED').length,
        blocked: rows.filter(e => e.event_type === 'USER_BLOCKED').length,
        access_denied: rows.filter(e => e.event_type === 'ACCESS_DENIED').length,
        vpn_detected: rows.filter(e => e.event_type === 'VPN_DETECTED').length,
        avg_risk: rows.length
            ? Math.round(rows.reduce((s, e) => s + (e.risk_score || 0), 0) / rows.length)
            : 0
    };
}

module.exports = { logSecurityEvent, addClient, getRecentEvents, getStats24h };
