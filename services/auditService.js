// services/auditService.js
// Records security events and user actions to the audit_log table.
// Used throughout the app to maintain a tamper-evident trail for compliance.

const { supabase } = require('../db');

/**
 * Writes a single security event to audit_log.
 * @param {number|null} userId  - ID of the affected user (null for system events)
 * @param {string}      action  - Event type in SCREAMING_SNAKE_CASE (e.g. LOGIN_FAILED)
 * @param {string}      detail  - Human-readable description
 * @param {string}      ip      - Originating IP address
 */
async function logEvent(userId, action, detail, ip) {
  await supabase.from('audit_log').insert({
    user_id: userId,
    action: action,
    detail: detail || '',
    ip: ip || ''
  });
}

async function getUserAuditLog(userId, limit = 30) {
  const { data } = await supabase
    .from('audit_log')
    .select('*')
    .eq('user_id', userId)
    .order('created_at', { ascending: false })
    .limit(limit);

  return data || [];
}

async function getAllAuditLogs(limit = 100) {
  const { data: logs } = await supabase
    .from('audit_log')
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
    return Object.assign({}, row, {
      username: u.username || 'System',
      role: u.role || ''
    });
  });
}

module.exports = { logEvent, getUserAuditLog, getAllAuditLogs };
