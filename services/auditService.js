const { supabase } = require('../db');

/**
 * Save an event to the audit log.
 * @param {string|number} userId - The user's ID.
 * @param {string} action - What happened (e.g. LOGIN_SUCCESS).
 * @param {string} detail - Extra info about the event.
 * @param {string} ip - The user's IP address.
 * @param {string} [correlationId] - Optional ID for linking related events.
 */
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

        // If correlation_id column doesn't exist, try without it
        if (error?.code === '42703') {
            var fallback = { ...record };
            delete fallback.correlation_id;
            var result = await supabase.from('audit_log').insert(fallback).select().single();
            if (result.error) throw result.error;
            return result.data;
        }

        if (error) throw error;
        return data;
    } catch (err) {
        console.error('[Audit] Failed to save log for ' + action + ':', err?.message);
    }
}

/**
 * Get audit logs for a specific user.
 */
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

/**
 * Get all audit logs with usernames attached.
 */
async function getAllAuditLogs(limit) {
    if (!limit) limit = 100;
    var { data: logs } = await supabase
        .from('audit_log')
        .select('*')
        .order('created_at', { ascending: false })
        .limit(limit);

    if (!logs?.length) return [];

    var userIds = [...new Set(logs.map(function(log) { return log.user_id; }).filter(Boolean))];

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
        return {
            ...log,
            username: userMap[log.user_id]?.username || 'System',
            role: userMap[log.user_id]?.role || 'System'
        };
    });
}

module.exports = { logEvent, getUserAuditLog, getAllAuditLogs };
