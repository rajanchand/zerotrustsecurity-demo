// routes/mappingRoutes.js
// Admin panel routes: user management, department management, device approval.
// All endpoints in this file require SuperAdmin or IT role (enforced in server.js).

var express  = require('express');
var bcrypt   = require('bcryptjs');
var path     = require('path');
var { supabase }                                                           = require('../db');
var { logEvent }                                                           = require('../services/auditService');
var { logSecurityEvent }                                                   = require('../services/monitorService');
var { getPendingDevices, approveDevice, rejectDevice, getAllDevices }      = require('../services/deviceService');
var { validatePassword }                                                   = require('../middleware/passwordPolicy');
var { requireReAuth }                                                      = require('../middleware/stepUpAuth');
var { requirePermission }                                                  = require('../middleware/permissions');

var router = express.Router();

// ── Page Routes ─────────────────────────────────────────────

router.get('/mapping', function (req, res) {
    res.sendFile(path.join(__dirname, '..', 'views', 'mapping.html'));
});

router.get('/register-device', function (req, res) {
    if (req.session.role === 'HR') return res.status(403).send('Forbidden for HR.');
    res.sendFile(path.join(__dirname, '..', 'views', 'register-device.html'));
});

router.get('/admin/user-access', function (req, res) {
    if (req.session.role !== 'SuperAdmin') return res.status(403).send('Forbidden.');
    res.sendFile(path.join(__dirname, '..', 'views', 'user-access.html'));
});

// ── User Management API ──────────────────────────────────────

// get all users
router.get('/api/mapping/users', requirePermission('user_view'), async function (req, res) {
    try {
        var { data: users } = await supabase
            .from('users')
            .select('id, username, role, email, department, status, failed_attempts, created_at')
            .order('id', { ascending: true });

        res.json(users || []);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});

// create new user
router.post('/api/mapping/users/create', requirePermission('user_create'), requireReAuth, async function (req, res) {
    try {
        // DEVICE POSTURE ENFORCEMENT
        var { data: currentDevice } = await supabase
            .from('devices')
            .select('approved')
            .eq('user_id', req.session.userId)
            .eq('fingerprint', req.session.deviceFingerprint)
            .single();

        if (!currentDevice || !currentDevice.approved) {
            return res.json({ success: false, message: 'Access denied: Active Admin actions require an approved company device.' });
        }

        var { username, password, role, email, department } = req.body;

        if (!username || !password || !role) {
            return res.json({ success: false, message: 'Username, password, and role are required.' });
        }

        // PASSWORD POLICY enforcement
        var policy = validatePassword(password);
        if (!policy.valid) {
            return res.json({ success: false, message: policy.errors.join(' ') });
        }

        // check if username already exists
        var { data: existing } = await supabase
            .from('users')
            .select('id')
            .eq('username', username)
            .single();

        if (existing) {
            return res.json({ success: false, message: 'Username already exists.' });
        }

        var hash = bcrypt.hashSync(password, 10);

        var { error } = await supabase.from('users').insert({
            username: username,
            password_hash: hash,
            role: role,
            email: email || '',
            department: department || 'General',
            status: 'active'
        });

        if (error) {
            return res.json({ success: false, message: 'Failed to create user: ' + error.message });
        }

        await logEvent(req.session.userId, 'USER_CREATED', 'Created user: ' + username + ' (' + role + ')', req.ip);
        await logSecurityEvent({
            event_type: 'USER_CREATED',
            user_id: req.session.userId,
            username: req.session.username,
            ip: req.ip,
            details: { new_user: username, role: role, department: department || 'General' }
        });
        res.json({ success: true, message: 'User created successfully.' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

// approve device
router.post('/api/mapping/devices/approve', requirePermission('device_approve'), requireReAuth, async function (req, res) {
    if (req.session.role === 'HR') {
        return res.json({ success: false, message: 'Access denied: HR cannot approve devices.' });
    }
    try {
        var { deviceId, trustLevel } = req.body;
        if (!deviceId) return res.json({ success: false });

        var adminId = req.session.userId;
        var approvedLevel = trustLevel || 'Managed';
        await approveDevice(deviceId, adminId, approvedLevel);

        var { data: target } = await supabase.from('devices').select('user_id, fingerprint').eq('id', deviceId).single();
        var tId = target ? target.user_id : 'unknown';

        await logEvent(adminId, 'DEVICE_APPROVED', 'Approved device ' + deviceId + ' (' + approvedLevel + ') for user ' + tId, req.ip);

        await logSecurityEvent({
            event_type: 'DEVICE_APPROVED',
            user_id: adminId,
            username: req.session.username,
            ip: req.ip,
            details: { action: 'device_approved', target_device: deviceId, target_user: tId, trust_level: approvedLevel }
        });

        res.json({ success: true, message: 'Device approved as ' + approvedLevel });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

// delete user
router.post('/api/mapping/users/delete', requirePermission('user_delete'), requireReAuth, async function (req, res) {
    try {
        // DEVICE POSTURE ENFORCEMENT
        var { data: currentDevice } = await supabase
            .from('devices')
            .select('approved')
            .eq('user_id', req.session.userId)
            .eq('fingerprint', req.session.deviceFingerprint)
            .single();

        if (!currentDevice || !currentDevice.approved) {
            return res.json({ success: false, message: 'Access denied: Active Admin actions require an approved company device.' });
        }

        var userId = req.body.userId;

        // cannot delete yourself
        if (userId === req.session.userId) {
            return res.json({ success: false, message: 'You cannot delete your own account.' });
        }

        var { data: user } = await supabase.from('users').select('username').eq('id', userId).single();

        if (!user) {
            return res.json({ success: false, message: 'User not found.' });
        }

        // clear approved_by references on other users' devices (foreign key)
        await supabase.from('devices').update({ approved_by: null }).eq('approved_by', userId);

        // clear ip_rules created_by references (foreign key)
        await supabase.from('ip_rules').update({ created_by: null }).eq('created_by', userId);

        // delete related records in proper order
        await supabase.from('devices').delete().eq('user_id', userId);
        await supabase.from('otp_store').delete().eq('user_id', userId);
        await supabase.from('risk_logs').delete().eq('user_id', userId);
        await supabase.from('sessions_log').delete().eq('user_id', userId);

        // keep audit log but remove user_id reference (data stays in database)
        await supabase.from('audit_log').update({ user_id: null }).eq('user_id', userId);

        // now safe to delete the user
        var { error } = await supabase.from('users').delete().eq('id', userId);

        if (error) {
            return res.json({ success: false, message: 'Delete failed: ' + error.message });
        }

        await logEvent(req.session.userId, 'USER_DELETED', 'Deleted user: ' + user.username, req.ip);
        await logSecurityEvent({
            event_type: 'USER_DELETED',
            user_id: req.session.userId,
            username: req.session.username,
            ip: req.ip,
            details: { deleted_user: user.username, deleted_user_id: userId }
        });
        res.json({ success: true, message: 'User "' + user.username + '" deleted. Audit records preserved.' });
    } catch (err) {
        console.error('Delete user error:', err);
        res.status(500).json({ success: false, message: 'Server error: ' + err.message });
    }
});

// change user role
router.post('/api/mapping/users/change-role', requireReAuth, async function (req, res) {
    if (req.session.role !== 'SuperAdmin') {
        return res.json({ success: false, message: 'Access denied: Only SuperAdmin can change roles.' });
    }
    try {
        // DEVICE POSTURE ENFORCEMENT
        var { data: currentDevice } = await supabase
            .from('devices')
            .select('approved')
            .eq('user_id', req.session.userId)
            .eq('fingerprint', req.session.deviceFingerprint)
            .single();

        if (!currentDevice || !currentDevice.approved) {
            return res.json({ success: false, message: 'Access denied: Active Admin actions require an approved company device.' });
        }

        var { userId, newRole } = req.body;

        var { data: user } = await supabase.from('users').select('username, role').eq('id', userId).single();
        if (!user) return res.json({ success: false, message: 'User not found.' });

        await supabase.from('users').update({ role: newRole }).eq('id', userId);

        await logEvent(req.session.userId, 'ROLE_CHANGED', user.username + ': ' + user.role + ' -> ' + newRole, req.ip);
        await logSecurityEvent({
            event_type: 'ROLE_CHANGED',
            user_id: req.session.userId,
            username: req.session.username,
            ip: req.ip,
            details: { target_user: user.username, target_user_id: userId, old_role: user.role, new_role: newRole }
        });
        res.json({ success: true, message: 'Role updated.' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

// edit user details (username, role, email, department)
router.post('/api/mapping/users/edit', requirePermission('user_edit'), async function (req, res) {
    try {
        // DEVICE POSTURE ENFORCEMENT
        var { data: currentDevice } = await supabase
            .from('devices')
            .select('approved')
            .eq('user_id', req.session.userId)
            .eq('fingerprint', req.session.deviceFingerprint)
            .single();

        if (!currentDevice || !currentDevice.approved) {
            return res.json({ success: false, message: 'Access denied: Active Admin actions require an approved company device.' });
        }

        var { userId, username, role, email, department } = req.body;

        var { data: user } = await supabase.from('users').select('username').eq('id', userId).single();
        if (!user) return res.json({ success: false, message: 'User not found.' });

        // check if new username is already taken by another user
        if (username && username !== user.username) {
            var { data: existing } = await supabase.from('users').select('id').eq('username', username).single();
            if (existing && existing.id !== userId) {
                return res.json({ success: false, message: 'Username "' + username + '" is already taken.' });
            }
        }

        var updates = {};
        if (username) updates.username = username;
        if (role) updates.role = role;
        if (email !== undefined) updates.email = email;
        if (department) updates.department = department;

        var { error } = await supabase.from('users').update(updates).eq('id', userId);
        if (error) return res.json({ success: false, message: 'Update failed: ' + error.message });

        var changes = [];
        if (username && username !== user.username) changes.push('username: ' + user.username + ' -> ' + username);
        if (role) changes.push('role: ' + role);
        if (email !== undefined) changes.push('email: ' + email);
        if (department) changes.push('dept: ' + department);

        await logEvent(req.session.userId, 'USER_EDITED', 'Edited user ID ' + userId + ': ' + changes.join(', '), req.ip);
        res.json({ success: true, message: 'User updated successfully.' });
    } catch (err) {
        console.error('Edit user error:', err);
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

// suspend user
router.post('/api/mapping/users/suspend', requirePermission('user_suspend'), async function (req, res) {
    try {
        // DEVICE POSTURE ENFORCEMENT
        var { data: currentDevice } = await supabase
            .from('devices')
            .select('approved')
            .eq('user_id', req.session.userId)
            .eq('fingerprint', req.session.deviceFingerprint)
            .single();

        if (!currentDevice || !currentDevice.approved) {
            return res.json({ success: false, message: 'Access denied: Active Admin actions require an approved company device.' });
        }

        var userId = req.body.userId;

        var { data: user } = await supabase.from('users').select('username').eq('id', userId).single();
        if (!user) return res.json({ success: false, message: 'User not found.' });

        await supabase.from('users').update({ status: 'suspended' }).eq('id', userId);

        await logEvent(req.session.userId, 'USER_SUSPENDED', 'Suspended user: ' + user.username, req.ip);
        await logSecurityEvent({
            event_type: 'USER_BLOCKED',
            user_id: req.session.userId,
            username: req.session.username,
            ip: req.ip,
            details: { target_user: user.username, action: 'suspended' }
        });
        res.json({ success: true, message: 'User suspended.' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

// block user
router.post('/api/mapping/users/block', requirePermission('user_suspend'), async function (req, res) {
    try {
        // DEVICE POSTURE ENFORCEMENT
        var { data: currentDevice } = await supabase
            .from('devices')
            .select('approved')
            .eq('user_id', req.session.userId)
            .eq('fingerprint', req.session.deviceFingerprint)
            .single();

        if (!currentDevice || !currentDevice.approved) {
            return res.json({ success: false, message: 'Access denied: Active Admin actions require an approved company device.' });
        }

        var userId = req.body.userId;

        var { data: user } = await supabase.from('users').select('username').eq('id', userId).single();
        if (!user) return res.json({ success: false, message: 'User not found.' });

        await supabase.from('users').update({ status: 'blocked' }).eq('id', userId);

        await logEvent(req.session.userId, 'USER_BLOCKED', 'Blocked user: ' + user.username, req.ip);
        await logSecurityEvent({
            event_type: 'USER_BLOCKED',
            user_id: req.session.userId,
            username: req.session.username,
            ip: req.ip,
            details: { target_user: user.username, action: 'blocked' }
        });
        res.json({ success: true, message: 'User blocked.' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

// activate user (unblock / unsuspend)
router.post('/api/mapping/users/revoke-session', async function (req, res) {
    if (req.session.role !== 'SuperAdmin') {
        return res.json({ success: false, message: 'Access denied: Only SuperAdmin can revoke sessions.' });
    }
    try {
        // DEVICE POSTURE ENFORCEMENT
        var { data: currentDevice } = await supabase
            .from('devices')
            .select('approved')
            .eq('user_id', req.session.userId)
            .eq('fingerprint', req.session.deviceFingerprint)
            .single();

        if (!currentDevice || !currentDevice.approved) {
            return res.json({ success: false, message: 'Access denied: Active Admin actions require an approved company device.' });
        }

        var userId = req.body.userId;

        var { data: user } = await supabase.from('users').select('username').eq('id', userId).single();
        if (!user) return res.json({ success: false, message: 'User not found.' });

        // Zero Trust Kill Switch: Erase the active session token
        await supabase.from('users').update({ active_session_token: null }).eq('id', userId);

        await logEvent(req.session.userId, 'SESSION_REVOKED', 'Revoked active sessions for user: ' + user.username, req.ip);
        await logSecurityEvent({
            event_type: 'SESSION_REVOKED',
            user_id: req.session.userId,
            username: req.session.username,
            ip: req.ip,
            details: { target_user: user.username, action: 'session_revoked', reason: 'Admin forced kill switch' }
        });
        res.json({ success: true, message: 'User sessions instantly revoked.' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

// activate user (unblock / unsuspend)
router.post('/api/mapping/users/activate', requirePermission('user_approve'), async function (req, res) {
    try {
        // DEVICE POSTURE ENFORCEMENT
        var { data: currentDevice } = await supabase
            .from('devices')
            .select('approved')
            .eq('user_id', req.session.userId)
            .eq('fingerprint', req.session.deviceFingerprint)
            .single();

        if (!currentDevice || !currentDevice.approved) {
            return res.json({ success: false, message: 'Access denied: Active Admin actions require an approved company device.' });
        }

        var userId = req.body.userId;

        var { data: user } = await supabase.from('users').select('username').eq('id', userId).single();
        if (!user) return res.json({ success: false, message: 'User not found.' });

        await supabase.from('users').update({ status: 'active', failed_attempts: 0 }).eq('id', userId);

        await logEvent(req.session.userId, 'USER_ACTIVATED', 'Activated user: ' + user.username, req.ip);
        await logSecurityEvent({
            event_type: 'USER_UNBLOCKED',
            user_id: req.session.userId,
            username: req.session.username,
            ip: req.ip,
            details: { target_user: user.username }
        });
        res.json({ success: true, message: 'User activated.' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

// --- department management ---

router.get('/api/mapping/departments', async function (req, res) {
    if (req.session.role === 'HR') return res.json([]);
    try {
        var { data: depts } = await supabase.from('departments').select('*').order('name');
        if (!depts) return res.json([]);

        // fetch all users for lookups
        var { data: allUsers } = await supabase.from('users').select('id, username, department');

        var userMap = {};
        var deptUserCounts = {};
        (allUsers || []).forEach(function (u) {
            userMap[u.id] = u.username;
            var dName = (u.department || '').toLowerCase();
            deptUserCounts[dName] = (deptUserCounts[dName] || 0) + 1;
        });

        var enriched = depts.map(function (d) {
            return {
                id: d.id,
                name: d.name,
                created_at: d.created_at,
                created_by: d.created_by,
                created_by_name: d.created_by ? (userMap[d.created_by] || 'Unknown') : '-',
                head_user_id: d.head_user_id,
                head_name: d.head_user_id ? (userMap[d.head_user_id] || 'Unknown') : '-',
                total_users: deptUserCounts[d.name.toLowerCase()] || 0
            };
        });

        res.json(enriched);
    } catch (err) {
        console.error('Departments fetch error:', err);
        res.json([]);
    }
});

router.post('/api/mapping/departments/create', async function (req, res) {
    if (req.session.role !== 'SuperAdmin') {
        return res.json({ success: false, message: 'Access denied: Only SuperAdmin can create departments.' });
    }
    try {
        // DEVICE POSTURE ENFORCEMENT
        var { data: currentDevice } = await supabase
            .from('devices')
            .select('approved')
            .eq('user_id', req.session.userId)
            .eq('fingerprint', req.session.deviceFingerprint)
            .single();

        if (!currentDevice || !currentDevice.approved) {
            return res.json({ success: false, message: 'Access denied: Active Admin actions require an approved company device.' });
        }

        var name = (req.body.name || '').trim();
        if (!name) return res.json({ success: false, message: 'Department name is required.' });

        var insertData = { name: name, created_by: req.session.userId };
        if (req.body.head_user_id) {
            insertData.head_user_id = parseInt(req.body.head_user_id);
        }

        var { error } = await supabase.from('departments').insert(insertData);
        if (error) return res.json({ success: false, message: 'Department already exists or error: ' + error.message });

        await logEvent(req.session.userId, 'DEPT_CREATED', 'Created department: ' + name, req.ip);
        res.json({ success: true, message: 'Department created.' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

router.post('/api/mapping/departments/delete', async function (req, res) {
    if (req.session.role !== 'SuperAdmin') {
        return res.json({ success: false, message: 'Access denied: Only SuperAdmin can delete departments.' });
    }
    try {
        // DEVICE POSTURE ENFORCEMENT
        var { data: currentDevice } = await supabase
            .from('devices')
            .select('approved')
            .eq('user_id', req.session.userId)
            .eq('fingerprint', req.session.deviceFingerprint)
            .single();

        if (!currentDevice || !currentDevice.approved) {
            return res.json({ success: false, message: 'Access denied: Active Admin actions require an approved company device.' });
        }

        var deptId = req.body.departmentId;

        var { data: dept } = await supabase.from('departments').select('name').eq('id', deptId).single();
        if (!dept) return res.json({ success: false, message: 'Department not found.' });

        await supabase.from('departments').delete().eq('id', deptId);

        await logEvent(req.session.userId, 'DEPT_DELETED', 'Deleted department: ' + dept.name, req.ip);
        res.json({ success: true, message: 'Department deleted.' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

router.post('/api/mapping/departments/update-head', async function (req, res) {
    if (req.session.role !== 'SuperAdmin') {
        return res.json({ success: false, message: 'Access denied: Only SuperAdmin can update departments.' });
    }
    try {
        // DEVICE POSTURE ENFORCEMENT
        var { data: currentDevice } = await supabase
            .from('devices')
            .select('approved')
            .eq('user_id', req.session.userId)
            .eq('fingerprint', req.session.deviceFingerprint)
            .single();

        if (!currentDevice || !currentDevice.approved) {
            return res.json({ success: false, message: 'Access denied: Active Admin actions require an approved company device.' });
        }

        var deptId = req.body.departmentId;
        var headUserId = req.body.head_user_id ? parseInt(req.body.head_user_id) : null;

        var { data: dept } = await supabase.from('departments').select('name').eq('id', deptId).single();
        if (!dept) return res.json({ success: false, message: 'Department not found.' });

        var { error } = await supabase.from('departments').update({ head_user_id: headUserId }).eq('id', deptId);
        if (error) return res.json({ success: false, message: 'Update failed: ' + error.message });

        await logEvent(req.session.userId, 'DEPT_HEAD_CHANGED', 'Changed head for ' + dept.name + ' to user ID ' + headUserId, req.ip);
        res.json({ success: true, message: 'Department head updated.' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

// --- device registration / approval ---

router.get('/api/mapping/devices/pending', async function (req, res) {
    if (req.session.role === 'HR') return res.json([]);
    try {
        var devices = await getPendingDevices();
        res.json(devices);
    } catch (err) {
        res.json([]);
    }
});

router.get('/api/mapping/devices/all', async function (req, res) {
    if (req.session.role === 'HR') return res.json([]);
    try {
        var devices = await getAllDevices();
        res.json(devices);
    } catch (err) {
        res.json([]);
    }
});



router.post('/api/mapping/devices/reject', async function (req, res) {
    if (req.session.role === 'HR') {
        return res.json({ success: false, message: 'Access denied: HR cannot reject devices.' });
    }
    try {
        // DEVICE POSTURE ENFORCEMENT
        var { data: currentDevice } = await supabase
            .from('devices')
            .select('approved')
            .eq('user_id', req.session.userId)
            .eq('fingerprint', req.session.deviceFingerprint)
            .single();

        if (!currentDevice || !currentDevice.approved) {
            return res.json({ success: false, message: 'Access denied: Active Admin actions require an approved company device.' });
        }

        var deviceId = req.body.deviceId;
        await rejectDevice(deviceId);

        await logEvent(req.session.userId, 'DEVICE_REJECTED', 'Rejected device ID: ' + deviceId, req.ip);
        res.json({ success: true, message: 'Device rejected.' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

// ── Permission Management API (User Access Dashboard) ────────────────────

// GET /api/mapping/permissions — Fetch users with their permissions (SuperAdmin ONLY)
router.get('/api/mapping/permissions', async function (req, res) {
    if (req.session.role !== 'SuperAdmin') {
        return res.status(403).json({ success: false, message: 'Forbidden' });
    }

    try {
        var { data: users, error } = await supabase
            .from('users')
            .select('id, username, role, permissions')
            .order('username', { ascending: true });

        if (error) throw error;
        res.json(users || []);
    } catch (err) {
        console.error('Fetch permissions error:', err);
        res.status(500).json({ success: false, message: 'Failed to fetch user permissions.' });
    }
});

// POST /api/mapping/permissions/update — Update user granular permissions (SuperAdmin ONLY)
router.post('/api/mapping/permissions/update', requireReAuth, async function (req, res) {
    if (req.session.role !== 'SuperAdmin') {
        return res.status(403).json({ success: false, message: 'Forbidden' });
    }

    try {
        var { userId, permissions } = req.body;

        if (!userId || !permissions) {
            return res.json({ success: false, message: 'User ID and permissions object are required.' });
        }

        // Fetch target user to log their name
        var { data: targetUser } = await supabase.from('users').select('username').eq('id', userId).single();
        if (!targetUser) return res.json({ success: false, message: 'User not found.' });

        var { error } = await supabase
            .from('users')
            .update({ permissions: permissions })
            .eq('id', userId);

        if (error) throw error;

        await logEvent(req.session.userId, 'PERMISSIONS_UPDATED', 'Updated granular permissions for user: ' + targetUser.username, req.ip);
        await logSecurityEvent({
            event_type: 'PERMISSIONS_UPDATED',
            user_id: req.session.userId,
            username: req.session.username,
            ip: req.ip,
            details: { target_user: targetUser.username, target_user_id: userId, permissions: permissions }
        });

        res.json({ success: true, message: 'Permissions updated successfully for ' + targetUser.username });
    } catch (err) {
        console.error('Update permissions error:', err);
        res.status(500).json({ success: false, message: 'Server error: ' + err.message });
    }
});

module.exports = router;
