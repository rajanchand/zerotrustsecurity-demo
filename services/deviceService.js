// services/deviceService.js
// device fingerprinting, registration, and approval

var { supabase } = require('../db');

// check if device already exists for this user
// tries fingerprint match first, then browser+OS as fallback
async function findDevice(userId, fingerprint, browser, os) {
  // first try exact fingerprint match
  var { data } = await supabase
    .from('devices')
    .select('*')
    .eq('user_id', userId)
    .eq('fingerprint', fingerprint)
    .single();

  if (data) return data;

  // fallback: match by browser and OS (same device, fingerprint may have changed)
  if (browser && os) {
    var { data: fallback } = await supabase
      .from('devices')
      .select('*')
      .eq('user_id', userId)
      .eq('browser', browser)
      .eq('os', os)
      .limit(1)
      .single();

    if (fallback) {
      // update the fingerprint to the new one so it matches next time
      await supabase.from('devices').update({ fingerprint: fingerprint }).eq('id', fallback.id);
      return fallback;
    }
  }

  return null;
}

// register a new device or update last seen
async function registerDevice(userId, info) {
  var existing = await findDevice(userId, info.fingerprint, info.browser, info.os);

  if (existing) {
    // already known, update last seen and IP
    await supabase
      .from('devices')
      .update({ last_seen: new Date().toISOString(), ip: info.ip, country: info.country })
      .eq('id', existing.id);

    return { isNew: false, device: existing };
  }

  // check if user has SuperAdmin role to auto-approve
  let isSuperAdmin = false;
  try {
      const { data: user } = await supabase.from('users').select('role').eq('id', userId).single();
      if (user && user.role === 'SuperAdmin') isSuperAdmin = true;
  } catch(e) {}

  // brand new device
  var label = (info.browser || 'Unknown') + ' on ' + (info.os || 'Unknown');
  var { data: newDevice, error } = await supabase
    .from('devices')
    .insert({
      user_id: userId,
      fingerprint: info.fingerprint,
      browser: info.browser,
      os: info.os,
      ip: info.ip,
      country: info.country,
      approved: isSuperAdmin, // Auto-approve SuperAdmin devices
      label: label
    })
    .select()
    .single();

  return { isNew: true, device: newDevice };
}

// get all devices for a user
async function getUserDevices(userId) {
  var { data } = await supabase
    .from('devices')
    .select('*')
    .eq('user_id', userId)
    .order('last_seen', { ascending: false });

  return data || [];
}

// get all devices (for admin)
async function getAllDevices() {
  var { data: devices } = await supabase
    .from('devices')
    .select('*')
    .order('first_seen', { ascending: false });

  if (!devices || !devices.length) return [];

  // get unique user IDs
  var userIds = [];
  devices.forEach(function (d) {
    if (d.user_id && userIds.indexOf(d.user_id) === -1) userIds.push(d.user_id);
  });

  // fetch users separately
  var userMap = {};
  if (userIds.length > 0) {
    var { data: users } = await supabase
      .from('users')
      .select('id, username, role')
      .in('id', userIds);

    (users || []).forEach(function (u) { userMap[u.id] = u; });
  }

  return devices.map(function (d) {
    var u = userMap[d.user_id] || {};
    return Object.assign({}, d, {
      username: u.username || 'Unknown',
      user_role: u.role || 'Unknown'
    });
  });
}

// get pending (unapproved) devices
async function getPendingDevices() {
  var { data: devices } = await supabase
    .from('devices')
    .select('*')
    .eq('approved', false)
    .order('first_seen', { ascending: false });

  if (!devices || !devices.length) return [];

  // get unique user IDs
  var userIds = [];
  devices.forEach(function (d) {
    if (d.user_id && userIds.indexOf(d.user_id) === -1) userIds.push(d.user_id);
  });

  // fetch users separately
  var userMap = {};
  if (userIds.length > 0) {
    var { data: users } = await supabase
      .from('users')
      .select('id, username, role')
      .in('id', userIds);

    (users || []).forEach(function (u) { userMap[u.id] = u; });
  }

  return devices.map(function (d) {
    var u = userMap[d.user_id] || {};
    return Object.assign({}, d, {
      username: u.username || 'Unknown',
      user_role: u.role || 'Unknown'
    });
  });
}

// approve a device
async function approveDevice(deviceId, approvedBy) {
  var { data, error } = await supabase
    .from('devices')
    .update({ approved: true, approved_by: approvedBy })
    .eq('id', deviceId)
    .select()
    .single();

  return data;
}

// reject (delete) a device
async function rejectDevice(deviceId) {
  await supabase.from('devices').delete().eq('id', deviceId);
}

// device health for a user
async function getDeviceHealth(userId) {
  var devices = await getUserDevices(userId);
  var total = devices.length;
  var approved = devices.filter(function (d) { return d.approved; }).length;
  var pending = total - approved;

  return {
    total: total,
    approved: approved,
    pending: pending,
    healthScore: total > 0 ? Math.round((approved / total) * 100) : 100,
    devices: devices
  };
}

module.exports = {
  findDevice, registerDevice, getUserDevices, getAllDevices,
  getPendingDevices, approveDevice, rejectDevice, getDeviceHealth
};
