var { supabase } = require('../db');

// active sse connections for live monitoring
var liveClients = [];

// severity levels for different event types
var SEVERITY = {
    LOGIN_SUCCESS: 'INFO',
    LOGIN_FAILED: 'HIGH',
    LOGIN_BLOCKED: 'CRITICAL',
    LOGIN_LOCKED: 'HIGH',
    LOGIN_PASSWORD_OK: 'INFO',
    LOGIN_SUSPENDED: 'MEDIUM',
    OTP_SENT: 'INFO',
    OTP_SUCCESS: 'INFO',
    OTP_FAILED: 'HIGH',
    ACCESS_DENIED: 'CRITICAL',
    ROLE_CHANGED: 'HIGH',
    USER_CREATED: 'MEDIUM',
    USER_DELETED: 'CRITICAL',
    USER_EDITED: 'MEDIUM',
    USER_ACTIVATED: 'MEDIUM',
    DEVICE_NEW: 'MEDIUM',
    DEVICE_APPROVED: 'MEDIUM',
    DEVICE_REJECTED: 'MEDIUM',
    DEVICE_AUTO_APPROVED: 'MEDIUM',
    DEVICE_PENDING: 'MEDIUM',
    LOCATION_NEW: 'MEDIUM',
    LOCATION_ALERT: 'HIGH',
    LOCATION_APPROVED: 'MEDIUM',
    LOCATION_REJECTED: 'MEDIUM',
    LOCATION_REQUEST: 'INFO',
    VPN_DETECTED: 'HIGH',
    IMPOSSIBLE_TRAVEL: 'CRITICAL',
    GEO_FENCE_VIOLATION: 'CRITICAL',
    RISK_SCORE_CHANGED: 'MEDIUM',
    RISK_SCORE_THRESHOLD_ADJUSTED: 'MEDIUM',
    USER_BLOCKED: 'HIGH',
    USER_UNBLOCKED: 'MEDIUM',
    USER_SUSPENDED: 'HIGH',
    AUTO_BLOCK: 'CRITICAL',
    FORCE_LOGOUT: 'HIGH',
    PASSWORD_RESET: 'HIGH',
    PASSWORD_CHANGED: 'MEDIUM',
    PROFILE_UPDATED: 'INFO',
    SESSION_REVOKED: 'CRITICAL',
    STEP_UP_CHALLENGE: 'MEDIUM',
    NETWORK_CHANGE: 'MEDIUM',
    NETWORK_POLICY_MODIFIED: 'HIGH',
    NETWORK_POLICY_ESTABLISHED: 'HIGH',
    NETWORK_POLICY_RESCINDED: 'HIGH',
    CSRF_VIOLATION: 'CRITICAL',
    HMAC_VIOLATION: 'CRITICAL',
    SESSION_HIJACK_ATTEMPT: 'CRITICAL',
    IP_CHANGE_MIDSESSION: 'HIGH',
    IP_BLOCKED: 'HIGH',
    RISK_ALERT: 'HIGH',
    PERMISSIONS_UPDATED: 'HIGH',
    PERMISSIONS_BULK_UPDATED: 'HIGH',
    INTEGRITY_VIOLATION: 'CRITICAL',
    CSRF_STATE_VIOLATION: 'CRITICAL',
    SEGMENTATION_VIOLATION: 'CRITICAL'
};

function getSeverity(eventType) {
    return SEVERITY[eventType] || 'INFO';
}

// add a client to the live event stream
function addClient(res) {
    liveClients.push(res);
    res.on('close', function() {
        liveClients = liveClients.filter(function(c) { return c !== res; });
    });
}

// send event to all connected live monitoring clients
function broadcast(event) {
    var data = 'data: ' + JSON.stringify(event) + '\n\n';
    liveClients.forEach(function(client) {
        try {
            client.write(data);
        } catch (err) {
            // client disconnected
        }
    });
}

// log a security event to the db and send to live clients
async function logSecurityEvent(params) {
    var correlationId = params.correlation_id || (params.req ? params.req.correlationId : null) || null;

    var event = {
        event_type: params.event_type || 'UNKNOWN',
        severity: params.severity || getSeverity(params.event_type),
        user_id: params.user_id || null,
        username: params.username || 'System',
        ip: params.ip || '',
        location: params.location || '',
        device_id: params.device_id || null,
        risk_score: params.risk_score || 0,
        details: params.details || {},
        correlation_id: correlationId,
        timestamp: new Date().toISOString()
    };

    // save to security_events table
    var { data: saved, error: saveError } = await supabase
        .from('security_events')
        .insert(event)
        .select()
        .single();

    // fallback if correlation_id column doesnt exist yet
    if (saveError && saveError.code === '42703') {
        var fallback = Object.assign({}, event);
        delete fallback.correlation_id;
        var { data: fbData } = await supabase
            .from('security_events')
            .insert(fallback)
            .select()
            .single();

        if (fbData) {
            event.id = fbData.id;
            event.timestamp = fbData.timestamp;
        }
    } else if (saved && saved.id) {
        event.id = saved.id;
        event.timestamp = saved.timestamp;
    }

    // also save to audit_log
    try {
        var auditRecord = {
            user_id: event.user_id,
            action: event.event_type,
            detail: JSON.stringify(event.details),
            ip: event.ip,
            correlation_id: event.correlation_id
        };

        var { error: auditError } = await supabase.from('audit_log').insert(auditRecord);

        if (auditError && auditError.code === '42703') {
            delete auditRecord.correlation_id;
            await supabase.from('audit_log').insert(auditRecord);
        }
    } catch (err) {
        // audit save failed, not critical
    }

    // send to live monitoring
    broadcast(event);
    return event;
}

// get recent security events for the monitoring page
async function getRecentEvents(limit) {
    limit = limit || 100;
    try {
        var { data: events, error } = await supabase
            .from('security_events')
            .select('*')
            .order('timestamp', { ascending: false })
            .limit(limit);

        if (!error && events && events.length > 0) return events;
    } catch (err) {
        // fall through to audit log
    }

    try {
        var { data: auditLogs } = await supabase
            .from('audit_log')
            .select('id, user_id, action, detail, ip, created_at')
            .order('created_at', { ascending: false })
            .limit(limit);

        if (!auditLogs) return [];

        // get usernames
        var userIds = [];
        auditLogs.forEach(function(log) {
            if (log.user_id && userIds.indexOf(log.user_id) === -1) {
                userIds.push(log.user_id);
            }
        });
        var userMap = {};

        if (userIds.length > 0) {
            var { data: users } = await supabase.from('users').select('id, username').in('id', userIds);
            if (users) {
                users.forEach(function(u) { userMap[u.id] = u.username; });
            }
        }

        return auditLogs.map(function(log) {
            var details = {};
            try {
                details = JSON.parse(log.detail || '{}');
            } catch (err) {
                details = { raw: log.detail };
            }
            return {
                id: log.id,
                event_type: log.action,
                severity: getSeverity(log.action),
                user_id: log.user_id,
                username: userMap[log.user_id] || 'System',
                ip: log.ip || '',
                location: '',
                risk_score: 0,
                details: details,
                timestamp: log.created_at
            };
        });
    } catch (err) {
        return [];
    }
}

// get stats for the last 24 hours
async function getStats24h() {
    var since = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    var rows = [];

    try {
        var { data: events } = await supabase
            .from('security_events')
            .select('event_type, severity, risk_score')
            .gte('timestamp', since);

        if (events && events.length > 0) rows = events;
    } catch (err) {
        // fall through to audit log
    }

    if (rows.length === 0) {
        try {
            var { data: auditLogs } = await supabase
                .from('audit_log')
                .select('action')
                .gte('created_at', since);

            rows = (auditLogs || []).map(function(log) {
                return {
                    event_type: log.action,
                    severity: getSeverity(log.action),
                    risk_score: 0
                };
            });
        } catch (err) {
            // stats not available
        }
    }

    return {
        total: rows.length,
        critical: rows.filter(function(r) { return r.severity === 'CRITICAL'; }).length,
        high: rows.filter(function(r) { return r.severity === 'HIGH'; }).length,
        login_failed: rows.filter(function(r) { return r.event_type === 'LOGIN_FAILED'; }).length,
        blocked: rows.filter(function(r) { return r.event_type === 'USER_BLOCKED'; }).length,
        access_denied: rows.filter(function(r) { return r.event_type === 'ACCESS_DENIED' || r.event_type === 'SEGMENTATION_VIOLATION'; }).length,
        vpn_detected: rows.filter(function(r) { return r.event_type === 'VPN_DETECTED'; }).length,
        avg_risk: rows.length
            ? Math.round(rows.reduce(function(sum, r) { return sum + (r.risk_score || 0); }, 0) / rows.length)
            : 0
    };
}

module.exports = {
    logSecurityEvent: logSecurityEvent,
    addClient: addClient,
    getRecentEvents: getRecentEvents,
    getStats24h: getStats24h
};
