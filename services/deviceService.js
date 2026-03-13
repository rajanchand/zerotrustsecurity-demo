var { supabase } = require('../db');

/**
 * Find a device in the database by fingerprint or browser+OS match.
 */
async function findDevice(userId, fingerprint, browser, os) {
    // Try exact fingerprint match first
    var { data: device } = await supabase
        .from('devices')
        .select('*')
        .eq('user_id', userId)
        .eq('fingerprint', fingerprint)
        .single();

    if (device) return device;

    // Try matching by browser + OS
    if (browser && os) {
        var { data: matches } = await supabase
            .from('devices')
            .select('*')
            .eq('user_id', userId)
            .eq('browser', browser)
            .eq('os', os)
            .limit(1);

        var match = matches && matches[0];
        if (match) {
            // Update the fingerprint for this device
            await supabase
                .from('devices')
                .update({ fingerprint: fingerprint })
                .eq('id', match.id);
            return match;
        }
    }

    return null;
}

/**
 * Register a device. If the device exists, update its last seen time.
 * If it's new, add it to the database.
 * Returns { isNew: true/false, device: {...} }
 */
async function registerDevice(userId, info) {
    var existing = await findDevice(userId, info.fingerprint, info.browser, info.os);

    if (existing) {
        // Update last seen
        await supabase
            .from('devices')
            .update({
                last_seen: new Date().toISOString(),
                ip: info.ip,
                country: info.country
            })
            .eq('id', existing.id);

        return { isNew: false, device: existing };
    }

    // Check if user is SuperAdmin (auto-approve)
    var autoApprove = false;
    try {
        var { data: user } = await supabase.from('users').select('role').eq('id', userId).single();
        if (user && user.role === 'SuperAdmin') autoApprove = true;
    } catch (err) {
        // Not critical
    }

    var label = (info.browser || 'Unknown') + ' (' + (info.os || 'Unknown') + ')';
    var { data: newDevice } = await supabase
        .from('devices')
        .insert({
            user_id: userId,
            fingerprint: info.fingerprint,
            browser: info.browser,
            os: info.os,
            ip: info.ip,
            country: info.country,
            approved: autoApprove,
            trust_level: autoApprove ? 'Managed' : 'Pending',
            label: label
        })
        .select()
        .single();

    return { isNew: true, device: newDevice };
}

/**
 * Get all devices for a user.
 */
async function getUserDevices(userId) {
    var { data: devices } = await supabase
        .from('devices')
        .select('*')
        .eq('user_id', userId)
        .order('last_seen', { ascending: false });

    return devices || [];
}

/**
 * Get all devices in the system (admin view).
 */
async function getAllDevices() {
    var { data: devices } = await supabase
        .from('devices')
        .select('*')
        .order('first_seen', { ascending: false });

    if (!devices || devices.length === 0) return [];

    // Get usernames for each device
    var userIds = [];
    devices.forEach(function(d) {
        if (d.user_id && userIds.indexOf(d.user_id) === -1) {
            userIds.push(d.user_id);
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

    return devices.map(function(d) {
        var user = userMap[d.user_id] || {};
        return Object.assign({}, d, {
            username: user.username || 'Unknown',
            user_role: user.role || 'N/A'
        });
    });
}

/**
 * Get all devices waiting for approval.
 */
async function getPendingDevices() {
    var { data: devices } = await supabase
        .from('devices')
        .select('*')
        .eq('approved', false)
        .order('first_seen', { ascending: false });

    if (!devices || devices.length === 0) return [];

    var userIds = [];
    devices.forEach(function(d) {
        if (d.user_id && userIds.indexOf(d.user_id) === -1) {
            userIds.push(d.user_id);
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

    return devices.map(function(d) {
        var user = userMap[d.user_id] || {};
        return Object.assign({}, d, {
            username: user.username || 'Unknown',
            user_role: user.role || 'N/A'
        });
    });
}

/**
 * Approve a device.
 */
async function approveDevice(deviceId, approvedBy, trustLevel) {
    trustLevel = trustLevel || 'Managed';

    var { data: existing } = await supabase
        .from('devices')
        .select('id')
        .eq('id', deviceId)
        .single();

    if (!existing) return { success: false, message: 'Device not found.' };

    var { data: updated, error } = await supabase
        .from('devices')
        .update({
            approved: true,
            approved_by: approvedBy,
            trust_level: trustLevel
        })
        .eq('id', deviceId)
        .select()
        .single();

    if (error) return { success: false, message: error.message };
    return { success: true, device: updated };
}

/**
 * Remove a device from the system.
 */
async function rejectDevice(deviceId) {
    await supabase.from('devices').delete().eq('id', deviceId);
}

/**
 * Get device health stats for a user.
 */
async function getDeviceHealth(userId) {
    var devices = await getUserDevices(userId);
    var total = devices.length;
    var approved = devices.filter(function(d) { return d.approved; }).length;

    return {
        total: total,
        approved: approved,
        pending: total - approved,
        healthScore: total > 0 ? Math.round((approved / total) * 100) : 100,
        devices: devices
    };
}

module.exports = {
    findDevice: findDevice,
    registerDevice: registerDevice,
    getUserDevices: getUserDevices,
    getAllDevices: getAllDevices,
    getPendingDevices: getPendingDevices,
    approveDevice: approveDevice,
    rejectDevice: rejectDevice,
    getDeviceHealth: getDeviceHealth
};
