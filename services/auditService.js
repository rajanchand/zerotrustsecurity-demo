// services/auditService.js
// logs every important security event

var { supabase } = require('../db');

// log a security event
async function logEvent(userId, action, detail, ip) {
  await supabase.from('audit_log').insert({
    user_id: userId,
    action: action,
    detail: detail || '',
    ip: ip || ''
  });
}

// get audit logs for a specific user
async function getUserAuditLog(userId, limit) {
  limit = limit || 30;
  var { data } = await supabase
    .from('audit_log')
    .select('*')
    .eq('user_id', userId)
    .order('created_at', { ascending: false })
    .limit(limit);

  return data || [];
}

// get all audit logs (admin)
async function getAllAuditLogs(limit) {
  limit = limit || 100;
  var { data: logs } = await supabase
    .from('audit_log')
    .select('*')
    .order('created_at', { ascending: false })
    .limit(limit);

  if (!logs || !logs.length) return [];

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
    return Object.assign({}, row, {
      username: u.username || 'System',
      role: u.role || ''
    });
  });
}

module.exports = { logEvent, getUserAuditLog, getAllAuditLogs };
