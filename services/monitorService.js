var { supabase } = require('../db');

// Active live-monitoring connections
var liveClients = [];

// Severity levels for each event type
var SEVERITY = {
    LOGIN_SUCCESS: 'INFO',
    LOGIN_FAILED: 'HIGH',
    LOGIN_BLOCKED: 'CRITICAL',
    LOGIN_LOCKED: 'HIGH',
    OTP_SENT: 'INFO',
    OTP_SUCCESS: 'INFO',
    OTP_FAILED: 'HIGH',
    ACCESS_DENIED: 'CRITICAL',
    ROLE_CHANGED: 'HIGH',
    USER_CREATED: 'MEDIUM',
    USER_DELETED: 'CRITICAL',
    USER_EDITED: 'MEDIUM',
    DEVICE_NEW: 'MEDIUM',
    DEVICE_APPROVED: 'MEDIUM',
    DEVICE_REJECTED: 'MEDIUM',
    LOCATION_NEW: 'MEDIUM',
    LOCATION_ALERT: 'HIGH',
    VPN_DETECTED: 'HIGH',
    IMPOSSIBLE_TRAVEL: 'CRITICAL',
    GEO_FENCE_VIOLATION: 'CRITICAL',
    RISK_SCORE_CHANGED: 'MEDIUM',
    USER_BLOCKED: 'HIGH',
    USER_UNBLOCKED: 'MEDIUM',
    USER_SUSPENDED: 'HIGH',
    FORCE_LOGOUT: 'HIGH',
    PASSWORD_RESET: 'HIGH',
    PASSWORD_CHANGED: 'MEDIUM',
    SESSION_REVOKED: 'CRITICAL',
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

/**
 * Get severity level for an event type.
 */
function getSeverity(eventType) {
    return SEVERITY[eventType] || 'INFO';
}

/**
 * Add a new client for live event streaming (SSE).
 */
function addClient(res) {
    liveClients.push(res);
    res.on('close', function() {
        liveClients = liveClients.filter(function(c) { return c !== res; });
    });
}

/**
 * Send an event to all live monitoring clients.
 */
function broadcast(event) {
    var data = 'data: ' + JSON.stringify(event) + '\n\n';
    liveClients.forEach(function(client) {
        try {
            client.write(data);
        } catch (err) {
            // Client disconnected, ignore
        }
    });
}

/**
 * Log a security event to the database and broadcast to live clients.
 */
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

    // Save to security_events table
    var { data: saved, error: saveError } = await supabase
        .from('security_events')
        .insert(event)
        .select()
        .single();

    // If column doesn't exist, try without correlation_id
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

    // Also save to audit_log table
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
        // Audit log save failed - not critical
    }

    // Send to live monitoring clients
    broadcast(event);
    return event;
}

/**
 * Get recent security events for the live monitoring page.
 */
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
        // Fall back to audit log
    }

    try {
        var { data: auditLogs } = await supabase
            .from('audit_log')
            .select('id, user_id, action, detail, ip, created_at')
            .order('created_at', { ascending: false })
            .limit(limit);

        if (!auditLogs) return [];

        // Get usernames
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

/**
 * Get stats for the last 24 hours.
 */
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
        // Fall back to audit log
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
            // Stats unavailable
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
