// services/monitorService.js
// Broadcasts security events to connected SSE clients
// Falls back to audit_log if security_events table doesn't exist yet

var { supabase } = require('../db');

// list of active SSE response objects (one per browser tab)
var clients = [];

var SEVERITY = {
    LOGIN_SUCCESS:      'INFO',
    LOGIN_FAILED:       'HIGH',
    OTP_SENT:           'INFO',
    OTP_SUCCESS:        'INFO',
    OTP_FAILED:         'HIGH',
    ACCESS_DENIED:      'CRITICAL',
    ROLE_CHANGED:       'HIGH',
    USER_CREATED:       'MEDIUM',
    USER_DELETED:       'CRITICAL',
    DEVICE_NEW:         'MEDIUM',
    LOCATION_NEW:       'MEDIUM',
    VPN_DETECTED:       'HIGH',
    IMPOSSIBLE_TRAVEL:  'CRITICAL',
    RISK_SCORE_CHANGED: 'MEDIUM',
    USER_BLOCKED:       'HIGH',
    USER_UNBLOCKED:     'MEDIUM',
    FORCE_LOGOUT:       'HIGH'
};

function getSeverity(eventType) {
    return SEVERITY[eventType] || 'INFO';
}

// add a new SSE client (called when /api/monitor/stream is opened)
function addClient(res) {
    clients.push(res);
    res.on('close', function () {
        clients = clients.filter(function (c) { return c !== res; });
    });
}

// push an event to all connected browser tabs
function broadcast(event) {
    var data = 'data: ' + JSON.stringify(event) + '\n\n';
    clients.forEach(function (res) {
        try { res.write(data); } catch (e) {}
    });
}

// log a security event: write to DB + push live
async function logSecurityEvent(opts) {
    var event = {
        event_type:  opts.event_type || 'UNKNOWN',
        severity:    opts.severity   || getSeverity(opts.event_type),
        user_id:     opts.user_id    || null,
        username:    opts.username   || 'system',
        ip:          opts.ip         || '',
        location:    opts.location   || '',
        device_id:   opts.device_id  || null,
        risk_score:  opts.risk_score || 0,
        details:     opts.details    || {},
        timestamp:   new Date().toISOString()
    };

    // try writing to security_events table
    try {
        var { data } = await supabase
            .from('security_events')
            .insert(event)
            .select()
            .single();
        if (data && data.id) {
            event.id = data.id;
            event.timestamp = data.timestamp;
        }
    } catch (e) {
        // table might not exist yet — that's fine, broadcast still works
    }

    // always write to audit_log (this table always exists)
    try {
        await supabase.from('audit_log').insert({
            user_id:    event.user_id,
            action:     event.event_type,
            detail:     JSON.stringify(event.details),
            ip:         event.ip
        });
    } catch (e) {}

    // push to all live browser tabs
    broadcast(event);

    return event;
}

// get recent events for the initial page load
// tries security_events first, falls back to audit_log
async function getRecentEvents(limit) {
    limit = limit || 100;

    // try security_events table first
    try {
        var { data, error } = await supabase
            .from('security_events')
            .select('*')
            .order('timestamp', { ascending: false })
            .limit(limit);

        if (!error && data && data.length > 0) {
            return data;
        }
    } catch (e) {}

    // fallback: read from audit_log and reshape into the same format
    try {
        var { data: logs } = await supabase
            .from('audit_log')
            .select('id, user_id, action, detail, ip, created_at')
            .order('created_at', { ascending: false })
            .limit(limit);

        if (!logs) return [];

        // get usernames from user IDs
        var userIds = [];
        logs.forEach(function (r) {
            if (r.user_id && userIds.indexOf(r.user_id) === -1) userIds.push(r.user_id);
        });

        var userMap = {};
        if (userIds.length > 0) {
            var { data: users } = await supabase
                .from('users')
                .select('id, username')
                .in('id', userIds);
            (users || []).forEach(function (u) { userMap[u.id] = u.username; });
        }

        return logs.map(function (row) {
            var details = {};
            try { details = JSON.parse(row.detail || '{}'); } catch (e) { details = { note: row.detail }; }
            return {
                id:         row.id,
                event_type: row.action,
                severity:   getSeverity(row.action),
                user_id:    row.user_id,
                username:   userMap[row.user_id] || 'system',
                ip:         row.ip || '',
                location:   '',
                risk_score: 0,
                details:    details,
                timestamp:  row.created_at
            };
        });
    } catch (e) {
        return [];
    }
}

// 24-hour stats (works from audit_log if security_events doesn't exist)
async function getStats24h() {
    var since = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    var rows = [];

    try {
        var { data } = await supabase
            .from('security_events')
            .select('event_type, severity, risk_score')
            .gte('timestamp', since);
        if (data && data.length > 0) rows = data;
    } catch (e) {}

    if (rows.length === 0) {
        // fallback to audit_log
        try {
            var { data: logs } = await supabase
                .from('audit_log')
                .select('action')
                .gte('created_at', since);
            rows = (logs || []).map(function (r) {
                return { event_type: r.action, severity: getSeverity(r.action), risk_score: 0 };
            });
        } catch (e) {}
    }

    return {
        total:        rows.length,
        critical:     rows.filter(function (e) { return e.severity === 'CRITICAL'; }).length,
        high:         rows.filter(function (e) { return e.severity === 'HIGH'; }).length,
        login_failed: rows.filter(function (e) { return e.event_type === 'LOGIN_FAILED'; }).length,
        blocked:      rows.filter(function (e) { return e.event_type === 'USER_BLOCKED'; }).length,
        access_denied:rows.filter(function (e) { return e.event_type === 'ACCESS_DENIED'; }).length,
        vpn_detected: rows.filter(function (e) { return e.event_type === 'VPN_DETECTED'; }).length,
        avg_risk:     rows.length
            ? Math.round(rows.reduce(function (s, e) { return s + (e.risk_score || 0); }, 0) / rows.length)
            : 0
    };
}

module.exports = { logSecurityEvent, addClient, getRecentEvents, getStats24h };
