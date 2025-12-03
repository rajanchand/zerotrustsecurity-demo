const { supabase } = require('../db');

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
