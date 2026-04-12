var { supabase } = require('../db');

// save an event to the audit log
async function logEvent(userId, action, detail, ip, correlationId) {
    try {
        var record = {
            user_id: userId,
            action: action,
            detail: detail || '',
            ip: ip || '',
            correlation_id: correlationId || null
        };

        var { data, error } = await supabase
            .from('audit_log')
            .insert(record)
            .select()
            .single();

        // if correlation_id column doesnt exist yet, try without it
        if (error && error.code === '42703') {
            var fallback = {
                user_id: record.user_id,
                action: record.action,
                detail: record.detail,
                ip: record.ip
            };
            var result = await supabase.from('audit_log').insert(fallback).select().single();
            if (result.error) throw result.error;
            return result.data;
        }

        if (error) throw error;
        return data;
    } catch (err) {
        console.error('[Audit] Failed to save log for ' + action + ':', err && err.message);
    }
}

// get audit logs for a specific user
async function getUserAuditLog(userId, limit) {
    if (!limit) limit = 30;
    var { data } = await supabase
        .from('audit_log')
        .select('*')
        .eq('user_id', userId)
        .order('created_at', { ascending: false })
        .limit(limit);

    return data || [];
}

// get all audit logs with usernames attached
async function getAllAuditLogs(limit) {
    if (!limit) limit = 100;
    var { data: logs } = await supabase
        .from('audit_log')
        .select('*')
        .order('created_at', { ascending: false })
        .limit(limit);

    if (!logs || !logs.length) return [];

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

        if (users) {
            users.forEach(function(u) { userMap[u.id] = u; });
        }
    }

    return logs.map(function(log) {
        var user = userMap[log.user_id] || {};
        return {
            id: log.id,
            user_id: log.user_id,
            action: log.action,
            detail: log.detail,
            ip: log.ip,
            created_at: log.created_at,
            correlation_id: log.correlation_id,
            username: user.username || 'System',
            role: user.role || 'System'
        };
    });
}

module.exports = {
    logEvent: logEvent,
    getUserAuditLog: getUserAuditLog,
    getAllAuditLogs: getAllAuditLogs
};
