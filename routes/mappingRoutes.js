var express = require('express');
var bcrypt = require('bcryptjs');
var path = require('path');
var { supabase } = require('../db');
var { logEvent } = require('../services/auditService');
var { logSecurityEvent } = require('../services/monitorService');
var { getPendingDevices, approveDevice, rejectDevice, getAllDevices } = require('../services/deviceService');
var { validatePassword } = require('../middleware/passwordPolicy');
var { requireReAuth } = require('../middleware/stepUpAuth');
var { requirePermission } = require('../middleware/permissions');

var router = express.Router();

// allowed permission keys
var VALID_PERMISSIONS = [
    'user_view', 'user_create', 'user_edit', 'user_delete', 'user_suspend', 'user_approve',
    'device_approve', 'network_manage', 'monitor_live', 'dept_manage'
];

// check if a permissions object only has valid keys
function validatePermissions(permissions) {
    if (!permissions || typeof permissions !== 'object') return false;
    var keys = Object.keys(permissions);
    return keys.every(function(key) { return VALID_PERMISSIONS.includes(key); });
}

// --- Page Routes ---

router.get('/mapping', function(req, res) {
    res.sendFile(path.join(__dirname, '..', 'views', 'mapping.html'));
});

router.get('/register-device', function(req, res) {
    if (req.session.role === 'HR') return res.status(403).send('You do not have permission.');
    res.sendFile(path.join(__dirname, '..', 'views', 'register-device.html'));
});

router.get('/admin/user-access', function(req, res) {
    if (req.session.role !== 'SuperAdmin') return res.status(403).send('SuperAdmin access required.');
    res.sendFile(path.join(__dirname, '..', 'views', 'user-access.html'));
});

// --- User Management ---

// list all users
router.get('/api/mapping/users', requirePermission('user_view'), async function(req, res) {
    try {
        var { data: users } = await supabase
            .from('users')
            .select('id, username, role, email, department, status, failed_attempts, created_at')
            .order('id', { ascending: true });

        res.json(users || []);
    } catch (err) {
        console.error('[Users] Load error:', err);
        res.status(500).json({ error: 'Failed to load users.' });
    }
});

// create a new user
router.post('/api/mapping/users/create', requirePermission('user_create'), requireReAuth, async function(req, res) {
    try {
        var { data: deviceCheck } = await supabase
            .from('devices')
            .select('approved')
            .eq('user_id', req.session.userId)
            .eq('fingerprint', req.session.deviceFingerprint)
            .single();

        if (!deviceCheck || !deviceCheck.approved) {
            return res.json({ success: false, message: 'Please register your device first.' });
        }

        var username = req.body.username;
        var password = req.body.password;
        var role = req.body.role;
        var email = req.body.email;
        var department = req.body.department;

        if (!username || !password || !role || !email) {
            return res.json({ success: false, message: 'Please fill in all fields (username, password, role, email).' });
        }

        var policyCheck = validatePassword(password);
        if (!policyCheck.valid) {
            return res.json({ success: false, message: policyCheck.errors.join(' ') });
        }

        var { data: existingUser } = await supabase
            .from('users')
            .select('id')
            .eq('username', username)
            .maybeSingle();

        if (existingUser) {
            return res.json({ success: false, message: 'This username already exists.' });
        }

        var hash = bcrypt.hashSync(password, 10);

        var { error: createError } = await supabase.from('users').insert({
            username: username,
            password_hash: hash,
            role: role,
            email: email || '',
            department: department || 'General Operations',
            status: 'active'
        });

        if (createError) return res.json({ success: false, message: createError.message });

        await logEvent(req.session.userId, 'USER_CREATED', 'Created user: ' + username + ' (Role: ' + role + ')', req.ip);
        await logSecurityEvent({
            event_type: 'USER_CREATED',
            user_id: req.session.userId,
            username: req.session.username,
            ip: req.ip,
            details: { target_username: username, role: role, department: department || 'General Operations' }
        });

        res.json({ success: true, message: 'User created.' });
    } catch (err) {
        console.error('[Users] Create error:', err);
        res.status(500).json({ success: false, message: 'Failed to create user.' });
    }
});

// delete a user and clean up related data
router.post('/api/mapping/users/delete', requirePermission('user_delete'), requireReAuth, async function(req, res) {
    try {
        var { data: deviceCheck } = await supabase
            .from('devices')
            .select('approved')
            .eq('user_id', req.session.userId)
            .eq('fingerprint', req.session.deviceFingerprint)
            .single();

        if (!deviceCheck || !deviceCheck.approved) {
            return res.json({ success: false, message: 'Please register your device first.' });
        }

        var targetId = req.body.userId;

        if (targetId === req.session.userId) {
            return res.json({ success: false, message: 'You cannot delete your own account.' });
        }

        var { data: targetUser } = await supabase.from('users').select('username').eq('id', targetId).single();
        if (!targetUser) return res.json({ success: false, message: 'User not found.' });

        // clean up foreign key references first
        await supabase.from('departments').update({ head_user_id: null }).eq('head_user_id', targetId);
        await supabase.from('departments').update({ created_by: null }).eq('created_by', targetId);
        await supabase.from('security_events').update({ resolved_by: null }).eq('resolved_by', targetId);
        await supabase.from('security_events').update({ user_id: null }).eq('user_id', targetId);
        await supabase.from('devices').update({ approved_by: null }).eq('approved_by', targetId);
        await supabase.from('ip_rules').update({ created_by: null }).eq('created_by', targetId);

        // delete the users own data
        await supabase.from('devices').delete().eq('user_id', targetId);
        await supabase.from('otp_store').delete().eq('user_id', targetId);
        await supabase.from('risk_logs').delete().eq('user_id', targetId);
        await supabase.from('sessions_log').delete().eq('user_id', targetId);
        await supabase.from('password_history').delete().eq('user_id', targetId);
        await supabase.from('audit_log').update({ user_id: null }).eq('user_id', targetId);

        var { error: deleteError } = await supabase.from('users').delete().eq('id', targetId);
        if (deleteError) return res.json({ success: false, message: deleteError.message });

        await logEvent(req.session.userId, 'USER_DELETED', 'Deleted user: ' + targetUser.username, req.ip);
        await logSecurityEvent({
            event_type: 'USER_DELETED',
            user_id: req.session.userId,
            username: req.session.username,
            ip: req.ip,
            details: { deleted_user: targetUser.username, id: targetId }
        });
        res.json({ success: true, message: 'User deleted.' });
    } catch (err) {
        console.error('[Users] Delete error:', err);
        res.status(500).json({ success: false, message: 'Failed to delete.' });
    }
});

// change a users role (superadmin only)
router.post('/api/mapping/users/change-role', requireReAuth, async function(req, res) {
    if (req.session.role !== 'SuperAdmin') {
        return res.json({ success: false, message: 'SuperAdmin access required to change roles.' });
    }
    try {
        var { data: deviceCheck } = await supabase
            .from('devices')
            .select('approved')
            .eq('user_id', req.session.userId)
            .eq('fingerprint', req.session.deviceFingerprint)
            .single();

        if (!deviceCheck || !deviceCheck.approved) {
            return res.json({ success: false, message: 'Please register your device first.' });
        }

        var targetId = req.body.userId;
        var newRole = req.body.newRole;
        var { data: targetUser } = await supabase.from('users').select('username, role').eq('id', targetId).single();
        if (!targetUser) return res.json({ success: false, message: 'User not found.' });

        await supabase.from('users').update({ role: newRole }).eq('id', targetId);

        await logEvent(req.session.userId, 'ROLE_CHANGED', 'Role changed: ' + targetUser.username + ' (' + targetUser.role + ' -> ' + newRole + ')', req.ip);
        await logSecurityEvent({
            event_type: 'ROLE_CHANGED',
            user_id: req.session.userId,
            username: req.session.username,
            ip: req.ip,
            details: { target_user: targetUser.username, old_role: targetUser.role, new_role: newRole }
        });
        res.json({ success: true, message: 'Role updated.' });
    } catch (err) {
        console.error('[Users] Role change error:', err);
        res.status(500).json({ success: false, message: 'Failed to update role.' });
    }
});

// edit user details
router.post('/api/mapping/users/edit', requirePermission('user_edit'), async function(req, res) {
    try {
        var { data: deviceCheck } = await supabase
            .from('devices')
            .select('approved')
            .eq('user_id', req.session.userId)
            .eq('fingerprint', req.session.deviceFingerprint)
            .single();

        if (!deviceCheck || !deviceCheck.approved) {
            return res.json({ success: false, message: 'Please register your device first.' });
        }

        var targetId = req.body.userId;
        var newUsername = req.body.username;
        var newRole = req.body.role;
        var newEmail = req.body.email;
        var newPhone = req.body.phone;
        var newDept = req.body.department;

        var { data: existingUser } = await supabase.from('users').select('username').eq('id', targetId).single();
        if (!existingUser) return res.json({ success: false, message: 'User not found.' });

        if (newUsername && newUsername !== existingUser.username) {
            var { data: conflictUser } = await supabase.from('users').select('id').eq('username', newUsername).maybeSingle();
            if (conflictUser && conflictUser.id !== targetId) {
                return res.json({ success: false, message: 'This username is already taken.' });
            }
        }

        var updates = {};
        if (newUsername) updates.username = newUsername;
        if (newRole) updates.role = newRole;
        if (newEmail !== undefined) updates.email = newEmail;
        if (newPhone !== undefined) updates.phone = newPhone;
        if (newDept) updates.department = newDept;

        var { error: updateError } = await supabase.from('users').update(updates).eq('id', targetId);
        if (updateError) return res.json({ success: false, message: updateError.message });

        await logEvent(req.session.userId, 'USER_EDITED', 'User updated: ID ' + targetId, req.ip);
        res.json({ success: true, message: 'User updated.' });
    } catch (err) {
        console.error('[Users] Edit error:', err);
        res.status(500).json({ success: false, message: 'Failed to update user.' });
    }
});

// suspend a user
router.post('/api/mapping/users/suspend', requirePermission('user_suspend'), async function(req, res) {
    try {
        var { data: deviceCheck } = await supabase
            .from('devices')
            .select('approved')
            .eq('user_id', req.session.userId)
            .eq('fingerprint', req.session.deviceFingerprint)
            .single();

        if (!deviceCheck || !deviceCheck.approved) {
            return res.json({ success: false, message: 'Please register your device first.' });
        }

        var targetId = req.body.userId;
        var { data: targetUser } = await supabase.from('users').select('username').eq('id', targetId).single();
        if (!targetUser) return res.json({ success: false, message: 'User not found.' });

        await supabase.from('users').update({ status: 'suspended', active_session_token: null }).eq('id', targetId);

        await logEvent(req.session.userId, 'USER_SUSPENDED', 'Suspended user: ' + targetUser.username, req.ip);
        await logSecurityEvent({
            event_type: 'USER_BLOCKED',
            user_id: req.session.userId,
            username: req.session.username,
            ip: req.ip,
            details: { target_user: targetUser.username, action: 'suspended' }
        });
        res.json({ success: true, message: 'User suspended.' });
    } catch (err) {
        console.error('[Users] Suspend error:', err);
        res.status(500).json({ success: false, message: 'Failed to suspend user.' });
    }
});

// block a user
router.post('/api/mapping/users/block', requirePermission('user_suspend'), async function(req, res) {
    try {
        var { data: deviceCheck } = await supabase
            .from('devices')
            .select('approved')
            .eq('user_id', req.session.userId)
            .eq('fingerprint', req.session.deviceFingerprint)
            .single();

        if (!deviceCheck || !deviceCheck.approved) {
            return res.json({ success: false, message: 'Please register your device first.' });
        }

        var targetId = req.body.userId;
        var { data: targetUser } = await supabase.from('users').select('username').eq('id', targetId).single();
        if (!targetUser) return res.json({ success: false, message: 'User not found.' });

        await supabase.from('users').update({ status: 'blocked', active_session_token: null }).eq('id', targetId);

        await logEvent(req.session.userId, 'USER_BLOCKED', 'Blocked user: ' + targetUser.username, req.ip);
        await logSecurityEvent({
            event_type: 'USER_BLOCKED',
            user_id: req.session.userId,
            username: req.session.username,
            ip: req.ip,
            details: { target_user: targetUser.username, action: 'blocked' }
        });
        res.json({ success: true, message: 'User blocked.' });
    } catch (err) {
        console.error('[Users] Block error:', err);
        res.status(500).json({ success: false, message: 'Failed to block user.' });
    }
});

// revoke a users session (superadmin only)
router.post('/api/mapping/users/revoke-session', async function(req, res) {
    if (req.session.role !== 'SuperAdmin') {
        return res.json({ success: false, message: 'SuperAdmin access required.' });
    }
    try {
        var { data: deviceCheck } = await supabase
            .from('devices')
            .select('approved')
            .eq('user_id', req.session.userId)
            .eq('fingerprint', req.session.deviceFingerprint)
            .single();

        if (!deviceCheck || !deviceCheck.approved) {
            return res.json({ success: false, message: 'Please register your device first.' });
        }

        var targetId = req.body.userId;
        var { data: targetUser } = await supabase.from('users').select('username').eq('id', targetId).single();
        if (!targetUser) return res.json({ success: false, message: 'User not found.' });

        await supabase.from('users').update({ active_session_token: null }).eq('id', targetId);

        await logEvent(req.session.userId, 'SESSION_REVOKED', 'Ended session for: ' + targetUser.username, req.ip);
        await logSecurityEvent({
            event_type: 'SESSION_REVOKED',
            user_id: req.session.userId,
            username: req.session.username,
            ip: req.ip,
            details: { target_user: targetUser.username, action: 'session_terminated' }
        });
        res.json({ success: true, message: 'Session ended.' });
    } catch (err) {
        console.error('[Users] Session end error:', err);
        res.status(500).json({ success: false, message: 'Failed to end session.' });
    }
});

// reset a users password (superadmin only)
router.post('/api/mapping/users/reset-password', requirePermission('user_edit'), requireReAuth, async function(req, res) {
    if (req.session.role !== 'SuperAdmin') {
        return res.json({ success: false, message: 'SuperAdmin access required.' });
    }
    try {
        var targetId = req.body.userId;
        var newPassword = req.body.newPassword;
        if (!targetId || !newPassword) return res.json({ success: false, message: 'User ID and new password are required.' });

        var policyCheck = validatePassword(newPassword);
        if (!policyCheck.valid) return res.json({ success: false, message: policyCheck.errors.join(' ') });

        var { data: targetUser } = await supabase.from('users').select('username').eq('id', targetId).single();
        if (!targetUser) return res.json({ success: false, message: 'User not found.' });

        var hash = bcrypt.hashSync(newPassword, 10);
        await supabase.from('users').update({
            password_hash: hash,
            active_session_token: null,
            password_changed_at: new Date().toISOString()
        }).eq('id', targetId);

        await logEvent(req.session.userId, 'PASSWORD_RESET', 'Admin reset password for: ' + targetUser.username, req.ip);
        await logSecurityEvent({
            event_type: 'PASSWORD_RESET',
            severity: 'HIGH',
            user_id: req.session.userId,
            username: req.session.username,
            ip: req.ip,
            details: { action_taken: 'credential_reset', target_user: targetUser.username }
        });

        res.json({ success: true, message: 'Password reset done.' });
    } catch (err) {
        console.error('[Users] Password reset error:', err);
        res.status(500).json({ success: false, message: 'Failed to update user.' });
    }
});

// activate a blocked or suspended user
router.post('/api/mapping/users/activate', requirePermission('user_approve'), async function(req, res) {
    try {
        var { data: deviceCheck } = await supabase
            .from('devices')
            .select('approved')
            .eq('user_id', req.session.userId)
            .eq('fingerprint', req.session.deviceFingerprint)
            .single();

        if (!deviceCheck || !deviceCheck.approved) {
            return res.json({ success: false, message: 'Please register your device first.' });
        }

        var targetId = req.body.userId;
        var { data: targetUser } = await supabase.from('users').select('username').eq('id', targetId).single();
        if (!targetUser) return res.json({ success: false, message: 'User not found.' });

        await supabase.from('users').update({ status: 'active', failed_attempts: 0 }).eq('id', targetId);

        await logEvent(req.session.userId, 'USER_ACTIVATED', 'Activated user: ' + targetUser.username, req.ip);
        await logSecurityEvent({
            event_type: 'USER_UNBLOCKED',
            user_id: req.session.userId,
            username: req.session.username,
            ip: req.ip,
            details: { target_user: targetUser.username }
        });
        res.json({ success: true, message: 'User activated.' });
    } catch (err) {
        console.error('[Users] Activate error:', err);
        res.status(500).json({ success: false, message: 'Failed to activate user.' });
    }
});

// --- Department Management ---

// list departments
router.get('/api/mapping/departments', async function(req, res) {
    if (req.session.role === 'HR') return res.json([]);
    try {
        var { data: departments } = await supabase.from('departments').select('*').order('name');
        if (!departments) return res.json([]);

        var { data: allUsers } = await supabase.from('users').select('id, username, department');

        var userMap = {};
        var deptCounts = {};
        (allUsers || []).forEach(function(u) {
            userMap[u.id] = u.username;
            var deptName = (u.department || '').toLowerCase();
            deptCounts[deptName] = (deptCounts[deptName] || 0) + 1;
        });

        var deptList = departments.map(function(dept) {
            return {
                id: dept.id,
                name: dept.name,
                created_at: dept.created_at,
                created_by_name: dept.created_by ? (userMap[dept.created_by] || '-') : '-',
                head_name: dept.head_user_id ? (userMap[dept.head_user_id] || '-') : '-',
                total_users: deptCounts[dept.name.toLowerCase()] || 0,
                work_hours_start: dept.work_hours_start,
                work_hours_end: dept.work_hours_end,
                timezone: dept.timezone || 'UTC'
            };
        });

        res.json(deptList);
    } catch (err) {
        console.error('[Departments] Error:', err);
        res.json([]);
    }
});

// create a department
router.post('/api/mapping/departments/create', async function(req, res) {
    if (req.session.role !== 'SuperAdmin') {
        return res.json({ success: false, message: 'SuperAdmin access required.' });
    }
    try {
        var { data: deviceCheck } = await supabase
            .from('devices')
            .select('approved')
            .eq('user_id', req.session.userId)
            .eq('fingerprint', req.session.deviceFingerprint)
            .single();

        if (!deviceCheck || !deviceCheck.approved) {
            return res.json({ success: false, message: 'Please register your device first.' });
        }

        var deptName = (req.body.name || '').trim();
        if (!deptName) return res.json({ success: false, message: 'Department name is required.' });

        var deptData = { name: deptName, created_by: req.session.userId };
        if (req.body.head_user_id) deptData.head_user_id = parseInt(req.body.head_user_id);

        var { error: insertError } = await supabase.from('departments').insert(deptData);
        if (insertError) return res.json({ success: false, message: 'Error: ' + insertError.message });

        await logEvent(req.session.userId, 'DEPT_CREATED', 'Department created: ' + deptName, req.ip);
        res.json({ success: true, message: 'Department created.' });
    } catch (err) {
        console.error('[Departments] Create error:', err);
        res.status(500).json({ success: false, message: 'Something went wrong.' });
    }
});

// delete a department
router.post('/api/mapping/departments/delete', async function(req, res) {
    if (req.session.role !== 'SuperAdmin') {
        return res.json({ success: false, message: 'SuperAdmin access required.' });
    }
    try {
        var { data: deviceCheck } = await supabase
            .from('devices')
            .select('approved')
            .eq('user_id', req.session.userId)
            .eq('fingerprint', req.session.deviceFingerprint)
            .single();

        if (!deviceCheck || !deviceCheck.approved) {
            return res.json({ success: false, message: 'Please register your device first.' });
        }

        var deptId = req.body.departmentId;
        var { data: targetDept } = await supabase.from('departments').select('name').eq('id', deptId).single();
        if (!targetDept) return res.json({ success: false, message: 'Department not found.' });

        await supabase.from('departments').delete().eq('id', deptId);

        await logEvent(req.session.userId, 'DEPT_DELETED', 'Department deleted: ' + targetDept.name, req.ip);
        res.json({ success: true, message: 'Department deleted.' });
    } catch (err) {
        console.error('[Departments] Delete error:', err);
        res.status(500).json({ success: false, message: 'Something went wrong.' });
    }
});

// change department head
router.post('/api/mapping/departments/update-head', async function(req, res) {
    if (req.session.role !== 'SuperAdmin') {
        return res.json({ success: false, message: 'SuperAdmin access required.' });
    }
    try {
        var { data: deviceCheck } = await supabase
            .from('devices')
            .select('approved')
            .eq('user_id', req.session.userId)
            .eq('fingerprint', req.session.deviceFingerprint)
            .single();

        if (!deviceCheck || !deviceCheck.approved) {
            return res.json({ success: false, message: 'Please register your device first.' });
        }

        var deptId = req.body.departmentId;
        var headUserId = req.body.head_user_id ? parseInt(req.body.head_user_id) : null;

        var { data: targetDept } = await supabase.from('departments').select('name').eq('id', deptId).single();
        if (!targetDept) return res.json({ success: false, message: 'Department not found.' });

        var { error: updateError } = await supabase.from('departments').update({ head_user_id: headUserId }).eq('id', deptId);
        if (updateError) return res.json({ success: false, message: updateError.message });

        await logEvent(req.session.userId, 'DEPT_HEAD_CHANGED', 'Department head changed: ' + targetDept.name + ' -> user ' + headUserId, req.ip);
        res.json({ success: true, message: 'Department head updated.' });
    } catch (err) {
        console.error('[Departments] Head change error:', err);
        res.status(500).json({ success: false, message: 'Something went wrong.' });
    }
});

// update department working hours
router.post('/api/mapping/departments/update-hours', requireReAuth, async function(req, res) {
    if (req.session.role !== 'SuperAdmin') {
        return res.status(403).json({ success: false, message: 'SuperAdmin access required.' });
    }
    try {
        var deptName = req.body.deptName;
        var startHour = req.body.startHour;
        var endHour = req.body.endHour;
        var tz = req.body.timezone;

        if (!deptName || isNaN(startHour) || isNaN(endHour)) {
            return res.json({ success: false, message: 'Missing required fields: start time and end time needed.' });
        }

        var { error: updateError } = await supabase
            .from('departments')
            .update({
                work_hours_start: parseInt(startHour),
                work_hours_end: parseInt(endHour),
                timezone: tz || 'UTC'
            })
            .eq('name', deptName);

        if (updateError) throw updateError;

        await logEvent(req.session.userId, 'DEPT_HOURS_UPDATED', 'Working hours updated for: ' + deptName, req.ip);
        res.json({ success: true, message: 'Working hours updated for ' + deptName + '.' });
    } catch (err) {
        console.error('[Hours Update] Error:', err);
        res.status(500).json({ success: false, message: 'Failed to update working hours.' });
    }
});

// --- Device Management ---

// get pending devices
router.get('/api/mapping/devices/pending', async function(req, res) {
    if (req.session.role === 'HR') return res.json([]);
    try {
        var pendingDevices = await getPendingDevices();
        res.json(pendingDevices);
    } catch (err) {
        console.error('[Devices] Error loading pending:', err);
        res.json([]);
    }
});

// get all devices
router.get('/api/mapping/devices/all', async function(req, res) {
    if (req.session.role === 'HR') return res.json([]);
    try {
        var allDevices = await getAllDevices();
        res.json(allDevices);
    } catch (err) {
        console.error('[Devices] Error loading devices:', err);
        res.json([]);
    }
});

// approve a device
router.post('/api/mapping/devices/approve', requirePermission('device_approve'), requireReAuth, async function(req, res) {
    if (req.session.role === 'HR') {
        return res.json({ success: false, message: 'You do not have permission.' });
    }
    try {
        var deviceId = req.body.deviceId;
        var roleLevel = req.body.trustLevel;
        if (!deviceId) return res.json({ success: false, message: 'Device ID is required.' });

        var headUserId = req.session.userId;
        var assignedRole = roleLevel || 'System Managed';
        await approveDevice(deviceId, headUserId, assignedRole);

        var { data: targetDevice } = await supabase.from('devices').select('user_id').eq('id', deviceId).single();
        var userId = targetDevice ? targetDevice.user_id : 'unknown';

        await logEvent(headUserId, 'DEVICE_APPROVED', 'Device approved: ' + deviceId + ' (Role: ' + assignedRole + ') ' + userId, req.ip);
        await logSecurityEvent({
            event_type: 'DEVICE_APPROVED',
            user_id: headUserId,
            username: req.session.username,
            ip: req.ip,
            details: { deviceId: deviceId, targetUser: userId, role: assignedRole }
        });

        res.json({ success: true, message: 'Device approved as ' + assignedRole + '.' });
    } catch (err) {
        console.error('[Devices] Approve error:', err);
        res.status(500).json({ success: false, message: 'Failed to approve device.' });
    }
});

// reject/remove a device
router.post('/api/mapping/devices/reject', async function(req, res) {
    if (req.session.role === 'HR') {
        return res.json({ success: false, message: 'You do not have permission.' });
    }
    try {
        var { data: deviceCheck } = await supabase
            .from('devices')
            .select('approved')
            .eq('user_id', req.session.userId)
            .eq('fingerprint', req.session.deviceFingerprint)
            .single();

        if (!deviceCheck || !deviceCheck.approved) {
            return res.json({ success: false, message: 'Please register your device first.' });
        }

        var deviceId = req.body.deviceId;
        await rejectDevice(deviceId);

        await logEvent(req.session.userId, 'DEVICE_REJECTED', 'Device removed: ' + deviceId, req.ip);
        res.json({ success: true, message: 'Device has been removed.' });
    } catch (err) {
        console.error('[Devices] Remove error:', err);
        res.status(500).json({ success: false, message: 'Failed to remove device.' });
    }
});

// --- Permissions ---

// get all users with permissions
router.get('/api/mapping/permissions', async function(req, res) {
    if (req.session.role !== 'SuperAdmin') {
        return res.status(403).json({ success: false, message: 'SuperAdmin access required.' });
    }

    try {
        var { data: users, error: loadError } = await supabase
            .from('users')
            .select('id, username, role, permissions')
            .order('username', { ascending: true });

        if (loadError) throw loadError;
        res.json(users || []);
    } catch (err) {
        console.error('[Permissions] Error loading:', err);
        res.status(500).json({ success: false, message: 'Failed to load permissions.' });
    }
});

// update permissions for one user
router.post('/api/mapping/permissions/update', requireReAuth, async function(req, res) {
    if (req.session.role !== 'SuperAdmin') {
        return res.status(403).json({ success: false, message: 'SuperAdmin access required.' });
    }

    try {
        var targetId = req.body.userId;
        var newPerms = req.body.permissions;

        if (!targetId || !newPerms) {
            return res.json({ success: false, message: 'Missing required field: permissions.' });
        }

        var { data: targetUser } = await supabase.from('users').select('username').eq('id', targetId).single();
        if (!targetUser) return res.json({ success: false, message: 'User not found.' });

        if (!validatePermissions(newPerms)) {
            return res.json({ success: false, message: 'Cannot change SuperAdmin permissions.' });
        }

        var { error: updateError } = await supabase
            .from('users')
            .update({ permissions: newPerms })
            .eq('id', targetId);

        if (updateError) throw updateError;

        await logEvent(req.session.userId, 'PERMISSIONS_UPDATED', 'Updated permissions for ' + targetUser.username, req.ip);
        await logSecurityEvent({
            event_type: 'PERMISSIONS_UPDATED',
            user_id: req.session.userId,
            username: req.session.username,
            ip: req.ip,
            details: { target_user: targetUser.username, new_permissions: newPerms }
        });

        res.json({ success: true, message: 'Permissions updated for ' + targetUser.username + '.' });
    } catch (err) {
        console.error('[Permissions] Error:', err);
        res.status(500).json({ success: false, message: 'Failed to update permissions.' });
    }
});

// bulk update permissions
router.post('/api/mapping/permissions/bulk-update', requireReAuth, async function(req, res) {
    if (req.session.role !== 'SuperAdmin') {
        return res.status(403).json({ success: false, message: 'SuperAdmin access required.' });
    }

    try {
        var updates = req.body.updates;

        if (!updates || !Array.isArray(updates)) {
            return res.json({ success: false, message: 'Missing required fields for update.' });
        }

        for (var i = 0; i < updates.length; i++) {
            if (!updates[i].userId || !validatePermissions(updates[i].permissions)) {
                return res.json({ success: false, message: 'Invalid permission value.' });
            }
        }

        var results = [];
        for (var j = 0; j < updates.length; j++) {
            var { error: updateError } = await supabase
                .from('users')
                .update({ permissions: updates[j].permissions })
                .eq('id', updates[j].userId);

            results.push({ userId: updates[j].userId, success: !updateError });
        }

        await logEvent(req.session.userId, 'PERMISSIONS_BULK_UPDATED', 'Bulk permissions update for ' + updates.length + ' users', req.ip);

        res.json({
            success: true,
            message: 'Processed ' + updates.length + ' permission updates.',
            results: results
        });
    } catch (err) {
        console.error('[Bulk Update] Error:', err);
        res.status(500).json({ success: false, message: 'Failed to update permissions.' });
    }
});

// --- Trusted Locations ---

// get pending location requests
router.get('/api/mapping/trusted-locations/pending', async function(req, res) {
    if (req.session.role !== 'SuperAdmin' && req.session.role !== 'IT') {
        return res.status(403).json({ error: 'Admin access required.' });
    }
    try {
        var { data: pendingLocations, error: loadError } = await supabase
            .from('trusted_locations')
            .select('\
                id, label, country, ip_address, status, created_at,\
                users!trusted_locations_user_id_fkey ( id, username, department )\
            ')
            .eq('status', 'pending')
            .order('created_at', { ascending: false });

        if (loadError) throw loadError;
        res.json(pendingLocations || []);
    } catch (err) {
        console.error('[Locations] Error loading:', err);
        res.status(500).json([]);
    }
});

// approve a location
router.post('/api/mapping/trusted-locations/approve', requireReAuth, async function(req, res) {
    if (req.session.role !== 'SuperAdmin' && req.session.role !== 'IT') {
        return res.status(403).json({ success: false, message: 'Admin access required.' });
    }
    try {
        var locationId = req.body.id;
        if (!locationId) return res.json({ success: false, message: 'Missing required field: location ID.' });

        var { error: updateError } = await supabase
            .from('trusted_locations')
            .update({ status: 'approved', approved_by: req.session.userId })
            .eq('id', locationId);

        if (updateError) throw updateError;

        await logEvent(req.session.userId, 'LOCATION_APPROVED', 'Trusted location approved: ID ' + locationId, req.ip);
        res.json({ success: true, message: 'Location approved.' });
    } catch (err) {
        console.error('[Locations] Approve error:', err);
        res.status(500).json({ success: false, message: 'Failed to approve location.' });
    }
});

// reject a location
router.post('/api/mapping/trusted-locations/reject', requireReAuth, async function(req, res) {
    if (req.session.role !== 'SuperAdmin' && req.session.role !== 'IT') {
        return res.status(403).json({ success: false, message: 'Admin access required.' });
    }
    try {
        var locationId = req.body.id;
        if (!locationId) return res.json({ success: false, message: 'Missing required field: location ID.' });

        var { error: updateError } = await supabase
            .from('trusted_locations')
            .update({ status: 'rejected', approved_by: req.session.userId })
            .eq('id', locationId);

        if (updateError) throw updateError;

        await logEvent(req.session.userId, 'LOCATION_REJECTED', 'Location removed: ID ' + locationId, req.ip);
        res.json({ success: true, message: 'Location has been removed.' });
    } catch (err) {
        console.error('[Locations] Remove error:', err);
        res.status(500).json({ success: false, message: 'Failed to remove location.' });
    }
});

module.exports = router;
