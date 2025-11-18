// routes/mappingRoutes.js
// user management, department management, device registration
// only accessible by SuperAdmin and Admin roles

var express = require('express');
var bcrypt = require('bcryptjs');
var path = require('path');
var { supabase } = require('../db');
var { logEvent } = require('../services/auditService');
var { getPendingDevices, approveDevice, rejectDevice, getAllDevices } = require('../services/deviceService');

var router = express.Router();
var { logSecurityEvent } = require('../services/monitorService');

// --- pages ---

router.get('/mapping', function (req, res) {
    res.sendFile(path.join(__dirname, '..', 'views', 'mapping.html'));
});

router.get('/register-device', function (req, res) {
    res.sendFile(path.join(__dirname, '..', 'views', 'register-device.html'));
});

// --- user management API ---

// get all users
router.get('/api/mapping/users', async function (req, res) {
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
router.post('/api/mapping/users/create', async function (req, res) {
    try {
        var { username, password, role, email, department } = req.body;

        if (!username || !password || !role) {
            return res.json({ success: false, message: 'Username, password, and role are required.' });
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

// delete user
router.post('/api/mapping/users/delete', async function (req, res) {
    try {
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
router.post('/api/mapping/users/change-role', async function (req, res) {
    try {
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
router.post('/api/mapping/users/edit', async function (req, res) {
    try {
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
router.post('/api/mapping/users/suspend', async function (req, res) {
    try {
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
router.post('/api/mapping/users/block', async function (req, res) {
    try {
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
router.post('/api/mapping/users/activate', async function (req, res) {
    try {
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
    try {
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
    try {
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
    try {
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
    try {
        var devices = await getPendingDevices();
        res.json(devices);
    } catch (err) {
        res.json([]);
    }
});

router.get('/api/mapping/devices/all', async function (req, res) {
    try {
        var devices = await getAllDevices();
        res.json(devices);
    } catch (err) {
        res.json([]);
    }
});

router.post('/api/mapping/devices/approve', async function (req, res) {
    try {
        var deviceId = req.body.deviceId;
        await approveDevice(deviceId, req.session.userId);

        await logEvent(req.session.userId, 'DEVICE_APPROVED', 'Approved device ID: ' + deviceId, req.ip);
        res.json({ success: true, message: 'Device approved.' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

router.post('/api/mapping/devices/reject', async function (req, res) {
    try {
        var deviceId = req.body.deviceId;
        await rejectDevice(deviceId);

        await logEvent(req.session.userId, 'DEVICE_REJECTED', 'Rejected device ID: ' + deviceId, req.ip);
        res.json({ success: true, message: 'Device rejected.' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

module.exports = router;
