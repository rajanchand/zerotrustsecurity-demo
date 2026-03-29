const express = require('express');
const bcrypt = require('bcryptjs');
const path = require('path');
const { supabase } = require('../db');
const { logEvent } = require('../services/auditService');
const { logSecurityEvent } = require('../services/monitorService');
const { getPendingDevices, approveDevice, rejectDevice, getAllDevices } = require('../services/deviceService');
const { validatePassword } = require('../middleware/passwordPolicy');
const { requireReAuth } = require('../middleware/stepUpAuth');
const { requirePermission } = require('../middleware/permissions');

const router = express.Router();

/**
 * Defines the allowed permission levels for users.
 */
const VALID_PERMISSIONS = [
    'user_view', 'user_create', 'user_edit', 'user_delete', 'user_suspend', 'user_approve',
    'device_approve', 'network_manage', 'monitor_live', 'dept_manage'
];

/**
 * Validates whether a provided permissions value is valid.
 * @param {Object} permissions - The collection of permissions to validate.
 */
const validatePermissions = (permissions) => {
    if (!permissions || typeof permissions !== 'object') return false;
    const keys = Object.keys(permissions);
    return keys.every(key => VALID_PERMISSIONS.includes(key));
};

// --- System View Routes ---

router.get('/mapping', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'views', 'mapping.html'));
});

router.get('/register-device', (req, res) => {
    if (req.session.role === 'HR') return res.status(403).send('You do not have permission.');
    res.sendFile(path.join(__dirname, '..', 'views', 'register-device.html'));
});

router.get('/admin/user-access', (req, res) => {
    if (req.session.role !== 'SuperAdmin') return res.status(403).send('SuperAdmin access required.');
    res.sendFile(path.join(__dirname, '..', 'views', 'user-access.html'));
});

// --- User Management API ---

router.get('/api/mapping/users', requirePermission('user_view'), async (req, res) => {
    try {
        const { data: users } = await supabase
            .from('users')
            .select('id, username, role, email, department, status, failed_attempts, created_at')
            .order('id', { ascending: true });

        res.json(users || []);
    } catch (err) {
        console.error('[Users] Load error:', err);
        res.status(500).json({ error: 'Failed to load users.' });
    }
});

router.post('/api/mapping/users/create', requirePermission('user_create'), requireReAuth, async (req, res) => {
    try {
        const { data: deviceCheck } = await supabase
            .from('devices')
            .select('approved')
            .eq('user_id', req.session.userId)
            .eq('fingerprint', req.session.deviceFingerprint)
            .single();

        if (!deviceCheck?.approved) {
            return res.json({ success: false, message: 'Please register your device first.' });
        }

        const { username, password, role, email, department } = req.body;

        if (!username || !password || !role || !email) {
            return res.json({ success: false, message: 'Please fill in all fields (username, password, role, email).' });
        }

        const policyCheck = validatePassword(password);
        if (!policyCheck.valid) {
            return res.json({ success: false, message: policyCheck.errors.join(' ') });
        }

        const { data: existingUser } = await supabase
            .from('users')
            .select('id')
            .eq('username', username)
            .maybeSingle();

        if (existingUser) {
            return res.json({ success: false, message: 'This username already exists.' });
        }

        const hash = bcrypt.hashSync(password, 10);

        const { error: createError } = await supabase.from('users').insert({
            username,
            password_hash: hash,
            role,
            email: email || '',
            department: department || 'General Operations',
            status: 'active'
        });

        if (createError) return res.json({ success: false, message: createError.message });

        await logEvent(req.session.userId, 'USER_CREATED', `System identity enrolled: ${username} (Role: ${role})`, req.ip);
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

router.post('/api/mapping/users/delete', requirePermission('user_delete'), requireReAuth, async (req, res) => {
    try {
        const { data: deviceCheck } = await supabase
            .from('devices')
            .select('approved')
            .eq('user_id', req.session.userId)
            .eq('fingerprint', req.session.deviceFingerprint)
            .single();

        if (!deviceCheck?.approved) {
            return res.json({ success: false, message: 'Please register your device first.' });
        }

        const { userId: targetId } = req.body;

        if (targetId === req.session.userId) {
            return res.json({ success: false, message: 'You cannot delete your own account.' });
        }

        const { data: targetUser } = await supabase.from('users').select('username').eq('id', targetId).single();
        if (!targetUser) return res.json({ success: false, message: 'User not found.' });

        // System structural cleanup and synchronization
        await supabase.from('departments').update({ head_user_id: null }).eq('head_user_id', targetId);
        await supabase.from('departments').update({ created_by: null }).eq('created_by', targetId);
        await supabase.from('security_events').update({ resolved_by: null }).eq('resolved_by', targetId);
        await supabase.from('security_events').update({ user_id: null }).eq('user_id', targetId);
        await supabase.from('devices').update({ approved_by: null }).eq('approved_by', targetId);
        await supabase.from('ip_rules').update({ created_by: null }).eq('created_by', targetId);

        // Delete user-related data
        await supabase.from('devices').delete().eq('user_id', targetId);
        await supabase.from('otp_store').delete().eq('user_id', targetId);
        await supabase.from('risk_logs').delete().eq('user_id', targetId);
        await supabase.from('sessions_log').delete().eq('user_id', targetId);
        await supabase.from('password_history').delete().eq('user_id', targetId);
        await supabase.from('audit_log').update({ user_id: null }).eq('user_id', targetId);

        const { error: deleteError } = await supabase.from('users').delete().eq('id', targetId);
        if (deleteError) return res.json({ success: false, message: deleteError.message });

        await logEvent(req.session.userId, 'USER_DELETED', `System identity terminated: ${targetUser.username}`, req.ip);
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

router.post('/api/mapping/users/change-role', requireReAuth, async (req, res) => {
    if (req.session.role !== 'SuperAdmin') {
        return res.json({ success: false, message: 'SuperAdmin access required to change roles.' });
    }
    try {
        const { data: deviceCheck } = await supabase
            .from('devices')
            .select('approved')
            .eq('user_id', req.session.userId)
            .eq('fingerprint', req.session.deviceFingerprint)
            .single();

        if (!deviceCheck?.approved) {
            return res.json({ success: false, message: 'Please register your device first.' });
        }

        const { userId: targetId, newRole: newRole } = req.body;
        const { data: targetUser } = await supabase.from('users').select('username, role').eq('id', targetId).single();
        if (!targetUser) return res.json({ success: false, message: 'User not found.' });

        await supabase.from('users').update({ role: newRole }).eq('id', targetId);

        await logEvent(req.session.userId, 'ROLE_CHANGED', `Role changed: ${targetUser.username} (${targetUser.role} -> ${newRole})`, req.ip);
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

router.post('/api/mapping/users/edit', requirePermission('user_edit'), async (req, res) => {
    try {
        const { data: deviceCheck } = await supabase
            .from('devices')
            .select('approved')
            .eq('user_id', req.session.userId)
            .eq('fingerprint', req.session.deviceFingerprint)
            .single();

        if (!deviceCheck?.approved) {
            return res.json({ success: false, message: 'Please register your device first.' });
        }

        const { userId: targetId, username: newUsername, role: newRole, email: newEmail, phone: newPhone, department: newDept } = req.body;
        const { data: existingUser } = await supabase.from('users').select('username').eq('id', targetId).single();
        if (!existingUser) return res.json({ success: false, message: 'User not found.' });

        if (newUsername && newUsername !== existingUser.username) {
            const { data: conflictUser } = await supabase.from('users').select('id').eq('username', newUsername).maybeSingle();
            if (conflictUser && conflictUser.id !== targetId) {
                return res.json({ success: false, message: 'This username is already taken.' });
            }
        }

        const updates = {};
        if (newUsername) updates.username = newUsername;
        if (newRole) updates.role = newRole;
        if (newEmail !== undefined) updates.email = newEmail;
        if (newPhone !== undefined) updates.phone = newPhone;
        if (newDept) updates.department = newDept;

        const { error: updateError } = await supabase.from('users').update(updates).eq('id', targetId);
        if (updateError) return res.json({ success: false, message: updateError.message });

        await logEvent(req.session.userId, 'USER_EDITED', `User updated: ID ${targetId}`, req.ip);
        res.json({ success: true, message: 'User updated.' });
    } catch (err) {
        console.error('[Users] Edit error:', err);
        res.status(500).json({ success: false, message: 'Failed to update user.' });
    }
});

router.post('/api/mapping/users/suspend', requirePermission('user_suspend'), async (req, res) => {
    try {
        const { data: deviceCheck } = await supabase
            .from('devices')
            .select('approved')
            .eq('user_id', req.session.userId)
            .eq('fingerprint', req.session.deviceFingerprint)
            .single();

        if (!deviceCheck?.approved) {
            return res.json({ success: false, message: 'Please register your device first.' });
        }

        const { userId: targetId } = req.body;
        const { data: targetUser } = await supabase.from('users').select('username').eq('id', targetId).single();
        if (!targetUser) return res.json({ success: false, message: 'User not found.' });

        await supabase.from('users').update({ status: 'suspended', active_session_token: null }).eq('id', targetId);

        await logEvent(req.session.userId, 'USER_SUSPENDED', `System identity suspended: ${targetUser.username}`, req.ip);
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

router.post('/api/mapping/users/block', requirePermission('user_suspend'), async (req, res) => {
    try {
        const { data: deviceCheck } = await supabase
            .from('devices')
            .select('approved')
            .eq('user_id', req.session.userId)
            .eq('fingerprint', req.session.deviceFingerprint)
            .single();

        if (!deviceCheck?.approved) {
            return res.json({ success: false, message: 'Please register your device first.' });
        }

        const { userId: targetId } = req.body;
        const { data: targetUser } = await supabase.from('users').select('username').eq('id', targetId).single();
        if (!targetUser) return res.json({ success: false, message: 'User not found.' });

        await supabase.from('users').update({ status: 'blocked', active_session_token: null }).eq('id', targetId);

        await logEvent(req.session.userId, 'USER_BLOCKED', `System identity restricted: ${targetUser.username}`, req.ip);
        await logSecurityEvent({
            event_type: 'USER_BLOCKED',
            user_id: req.session.userId,
            username: req.session.username,
            ip: req.ip,
            details: { target_user: targetUser.username, action: 'restricted' }
        });
        res.json({ success: true, message: 'User blocked.' });
    } catch (err) {
        console.error('[Users] Block error:', err);
        res.status(500).json({ success: false, message: 'Failed to block user.' });
    }
});

router.post('/api/mapping/users/revoke-session', async (req, res) => {
    if (req.session.role !== 'SuperAdmin') {
        return res.json({ success: false, message: 'SuperAdmin access required.' });
    }
    try {
        const { data: deviceCheck } = await supabase
            .from('devices')
            .select('approved')
            .eq('user_id', req.session.userId)
            .eq('fingerprint', req.session.deviceFingerprint)
            .single();

        if (!deviceCheck?.approved) {
            return res.json({ success: false, message: 'Please register your device first.' });
        }

        const { userId: targetId } = req.body;
        const { data: targetUser } = await supabase.from('users').select('username').eq('id', targetId).single();
        if (!targetUser) return res.json({ success: false, message: 'User not found.' });

        await supabase.from('users').update({ active_session_token: null }).eq('id', targetId);

        await logEvent(req.session.userId, 'SESSION_REVOKED', `System session terminated: ${targetUser.username}`, req.ip);
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
        res.status(500).json({ success: false, message: 'Failed to delete.' });
    }
});

router.post('/api/mapping/users/reset-password', requirePermission('user_edit'), requireReAuth, async (req, res) => {
    if (req.session.role !== 'SuperAdmin') {
        return res.json({ success: false, message: 'SuperAdmin access required.' });
    }
    try {
        const { userId: targetId, newPassword: newPassword } = req.body;
        if (!targetId || !newPassword) return res.json({ success: false, message: 'User ID and new password are required.' });

        const policyCheck = validatePassword(newPassword);
        if (!policyCheck.valid) return res.json({ success: false, message: policyCheck.errors.join(' ') });

        const { data: targetUser } = await supabase.from('users').select('username').eq('id', targetId).single();
        if (!targetUser) return res.json({ success: false, message: 'User not found.' });

        const hash = bcrypt.hashSync(newPassword, 10);
        await supabase.from('users').update({
            password_hash: hash,
            active_session_token: null,
            password_changed_at: new Date().toISOString()
        }).eq('id', targetId);

        await logEvent(req.session.userId, 'PASSWORD_RESET', `System credential reset: ${targetUser.username}`, req.ip);
        await logSecurityEvent({
            event_type: 'ROLE_CHANGED',
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

router.post('/api/mapping/users/activate', requirePermission('user_approve'), async (req, res) => {
    try {
        const { data: deviceCheck } = await supabase
            .from('devices')
            .select('approved')
            .eq('user_id', req.session.userId)
            .eq('fingerprint', req.session.deviceFingerprint)
            .single();

        if (!deviceCheck?.approved) {
            return res.json({ success: false, message: 'Please register your device first.' });
        }

        const { userId: targetId } = req.body;
        const { data: targetUser } = await supabase.from('users').select('username').eq('id', targetId).single();
        if (!targetUser) return res.json({ success: false, message: 'User not found.' });

        await supabase.from('users').update({ status: 'active', failed_attempts: 0 }).eq('id', targetId);

        await logEvent(req.session.userId, 'USER_ACTIVATED', `System identity activated: ${targetUser.username}`, req.ip);
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

// --- Department Management API ---

router.get('/api/mapping/departments', async (req, res) => {
    if (req.session.role === 'HR') return res.json([]);
    try {
        const { data: departments } = await supabase.from('departments').select('*').order('name');
        if (!departments) return res.json([]);

        const { data: allUsers } = await supabase.from('users').select('id, username, department');

        const userMap = {};
        const deptCounts = {};
        (allUsers || []).forEach(function(u) {
            userMap[u.id] = u.username;
            var deptName = (u.department || '').toLowerCase();
            deptCounts[deptName] = (deptCounts[deptName] || 0) + 1;
        });

        const deptList = departments.map(dept => ({
            id: dept.id,
            name: dept.name,
            created_at: dept.created_at,
            created_by_name: dept.created_by ? (userMap[dept.created_by] || '-') : '-',
            head_name: dept.head_user_id ? (userMap[dept.head_user_id] || '-') : '-',
            total_users: deptCounts[dept.name.toLowerCase()] || 0,
            work_hours_start: dept.work_hours_start,
            work_hours_end: dept.work_hours_end,
            timezone: dept.timezone || 'UTC'
        }));

        res.json(deptList);
    } catch (err) {
        console.error('[Departments] Error:', err);
        res.json([]);
    }
});

router.post('/api/mapping/departments/create', async (req, res) => {
    if (req.session.role !== 'SuperAdmin') {
        return res.json({ success: false, message: 'SuperAdmin access required.' });
    }
    try {
        const { data: deviceCheck } = await supabase
            .from('devices')
            .select('approved')
            .eq('user_id', req.session.userId)
            .eq('fingerprint', req.session.deviceFingerprint)
            .single();

        if (!deviceCheck?.approved) {
            return res.json({ success: false, message: 'Please register your device first.' });
        }

        const deptName = (req.body.name || '').trim();
        if (!deptName) return res.json({ success: false, message: 'Department name is required.' });

        const deptData = { name: deptName, created_by: req.session.userId };
        if (req.body.head_user_id) deptData.head_user_id = parseInt(req.body.head_user_id);

        const { error: updateError } = await supabase.from('departments').insert(deptData);
        if (updateError) return res.json({ success: false, message: 'Error: ' + updateError.message });

        await logEvent(req.session.userId, 'DEPT_CREATED', `Department created: ${deptName}`, req.ip);
        res.json({ success: true, message: 'System department successfully established.' });
    } catch (err) {
        console.error('[Department Establishment] Failure:', err);
        res.status(500).json({ success: false, message: 'System structural engine failure.' });
    }
});

router.post('/api/mapping/departments/delete', async (req, res) => {
    if (req.session.role !== 'SuperAdmin') {
        return res.json({ success: false, message: 'Access denied: SuperAdmin access required to structural termination.' });
    }
    try {
        const { data: deviceCheck } = await supabase
            .from('devices')
            .select('approved')
            .eq('user_id', req.session.userId)
            .eq('fingerprint', req.session.deviceFingerprint)
            .single();

        if (!deviceCheck?.approved) {
            return res.json({ success: false, message: 'Please register your device first.' });
        }

        const { departmentId: deptId } = req.body;
        const { data: targetDepartment } = await supabase.from('departments').select('name').eq('id', deptId).single();
        if (!targetDepartment) return res.json({ success: false, message: 'Target system department not recognized within the registry.' });

        await supabase.from('departments').delete().eq('id', deptId);

        await logEvent(req.session.userId, 'DEPT_DELETED', `Department deleted: ${targetDepartment.name}`, req.ip);
        res.json({ success: true, message: 'System department successfully terminated.' });
    } catch (err) {
        console.error('[Department Termination] Failure:', err);
        res.status(500).json({ success: false, message: 'System structural engine failure.' });
    }
});

router.post('/api/mapping/departments/update-head', async (req, res) => {
    if (req.session.role !== 'SuperAdmin') {
        return res.json({ success: false, message: 'Access denied: SuperAdmin access required to leadership modification.' });
    }
    try {
        const { data: deviceCheck } = await supabase
            .from('devices')
            .select('approved')
            .eq('user_id', req.session.userId)
            .eq('fingerprint', req.session.deviceFingerprint)
            .single();

        if (!deviceCheck?.approved) {
            return res.json({ success: false, message: 'Please register your device first.' });
        }

        const { departmentId: deptId, head_user_id: userId } = req.body;
        const headUserId = userId ? parseInt(userId) : null;

        const { data: targetDepartment } = await supabase.from('departments').select('name').eq('id', deptId).single();
        if (!targetDepartment) return res.json({ success: false, message: 'Target system department not recognized within the registry.' });

        const { error: updateError } = await supabase.from('departments').update({ head_user_id: headUserId }).eq('id', deptId);
        if (updateError) return res.json({ success: false, message: updateError.message });

        await logEvent(req.session.userId, 'DEPT_HEAD_CHANGED', `System leadership transitioned: ${targetDepartment.name} head set to ${headUserId}`, req.ip);
        res.json({ success: true, message: 'System department leadership successfully transitioned.' });
    } catch (err) {
        console.error('[Leadership Transition] Failure:', err);
        res.status(500).json({ success: false, message: 'System structural engine failure.' });
    }
});

router.post('/api/mapping/departments/update-hours', requireReAuth, async (req, res) => {
    if (req.session.role !== 'SuperAdmin') {
        return res.status(403).json({ success: false, message: 'SuperAdmin access required.' });
    }
    try {
        const { deptName: deptName, startHour: startHour, endHour: endHour, timezone: tz } = req.body;
        if (!deptName || isNaN(startHour) || isNaN(endHour)) {
            return res.json({ success: false, message: 'Missing required fields: start time and end time needed.' });
        }
        
        const { error: updateError } = await supabase
            .from('departments')
            .update({ 
                work_hours_start: parseInt(startHour), 
                work_hours_end: parseInt(endHour), 
                timezone: tz || 'UTC' 
            })
            .eq('name', deptName);
            
        if (updateError) throw updateError;
        
        await logEvent(req.session.userId, 'DEPT_HOURS_UPDATED', `Working hours updated for department: ${deptName}`, req.ip);
        res.json({ success: true, message: `Working hours updated for ${deptName}` });
    } catch (err) {
        console.error('[Hours Update] Error:', err);
        res.status(500).json({ success: false, message: 'Failed to update working hours. Please try again..' });
    }
});

// --- Device Management API ---

router.get('/api/mapping/devices/pending', async (req, res) => {
    if (req.session.role === 'HR') return res.json([]);
    try {
        const pendingDevices = await getPendingDevices();
        res.json(pendingDevices);
    } catch (err) {
        console.error('[Devices] Error loading pending:', err);
        res.json([]);
    }
});

router.get('/api/mapping/devices/all', async (req, res) => {
    if (req.session.role === 'HR') return res.json([]);
    try {
        const allDevices = await getAllDevices();
        res.json(allDevices);
    } catch (err) {
        console.error('[Devices] Error loading devices:', err);
        res.json([]);
    }
});

router.post('/api/mapping/devices/approve', requirePermission('device_approve'), requireReAuth, async (req, res) => {
    if (req.session.role === 'HR') {
        return res.json({ success: false, message: 'You do not have permission.' });
    }
    try {
        const { deviceId: deviceId, trustLevel: roleLevel } = req.body;
        if (!deviceId) return res.json({ success: false, message: 'Device ID is required.' });

        const headUserId = req.session.userId;
        const assignedRole = roleLevel || 'System Managed';
        await approveDevice(deviceId, headUserId, assignedRole);

        const { data: targetUser } = await supabase.from('devices').select('user_id').eq('id', deviceId).single();
        const userId = targetUser ? targetUser.user_id : 'unidentified';

        await logEvent(headUserId, 'DEVICE_APPROVED', `Device approved: ${deviceId} (Role: ${assignedRole}) ${userId}`, req.ip);
        await logSecurityEvent({
            event_type: 'DEVICE_APPROVED',
            user_id: headUserId,
            username: req.session.username,
            ip: req.ip,
            details: { deviceId, targetUser: userId, role: assignedRole }
        });

        res.json({ success: true, message: `Device approved as ${assignedRole}` });
    } catch (err) {
        console.error('[Devices] Approve error:', err);
        res.status(500).json({ success: false, message: 'Failed to approve device. Please try again..' });
    }
});

router.post('/api/mapping/devices/reject', async (req, res) => {
    if (req.session.role === 'HR') {
        return res.json({ success: false, message: 'You do not have permission.' });
    }
    try {
        const { data: deviceCheck } = await supabase
            .from('devices')
            .select('approved')
            .eq('user_id', req.session.userId)
            .eq('fingerprint', req.session.deviceFingerprint)
            .single();

        if (!deviceCheck?.approved) {
            return res.json({ success: false, message: 'Please register your device first.' });
        }

        const { deviceId: deviceId } = req.body;
        await rejectDevice(deviceId);

        await logEvent(req.session.userId, 'DEVICE_REJECTED', `Device removed: ${deviceId}`, req.ip);
        res.json({ success: true, message: 'Device has been removed.' });
    } catch (err) {
        console.error('[Devices] Remove error:', err);
        res.status(500).json({ success: false, message: 'Failed to remove device. Please try again..' });
    }
});

// --- Permissions API ---

router.get('/api/mapping/permissions', async (req, res) => {
    if (req.session.role !== 'SuperAdmin') {
        return res.status(403).json({ success: false, message: 'SuperAdmin access required.' });
    }

    try {
        const { data: updatedUsers, error: updateError } = await supabase
            .from('users')
            .select('id, username, role, permissions')
            .order('username', { ascending: true });

        if (updateError) throw updateError;
        res.json(updatedUsers || []);
    } catch (err) {
        console.error('[Permissions] Error loading:', err);
        res.status(500).json({ success: false, message: 'Failed to load permissions..' });
    }
});

router.post('/api/mapping/permissions/update', requireReAuth, async (req, res) => {
    if (req.session.role !== 'SuperAdmin') {
        return res.status(403).json({ success: false, message: 'SuperAdmin access required.' });
    }

    try {
        const { userId: targetId, permissions: newPerms } = req.body;

        if (!targetId || !newPerms) {
            return res.json({ success: false, message: 'Missing required field: permissions.' });
        }

        const { data: targetUser } = await supabase.from('users').select('username').eq('id', targetId).single();
        if (!targetUser) return res.json({ success: false, message: 'User not found.' });

        if (!validatePermissions(newPerms)) {
            return res.json({ success: false, message: 'Cannot change SuperAdmin permissions.' });
        }

        const { error: updateError } = await supabase
            .from('users')
            .update({ permissions: newPerms })
            .eq('id', targetId);

        if (updateError) throw updateError;

        await logEvent(req.session.userId, 'PERMISSIONS_UPDATED', `Updated permissions for ${targetUser.username}`, req.ip);
        await logSecurityEvent({
            event_type: 'PERMISSIONS_UPDATED',
            user_id: req.session.userId,
            username: req.session.username,
            ip: req.ip,
            details: { target_user: targetUser.username, new_permissions: newPerms }
        });

        res.json({ success: true, message: `Permissions updated for ${targetUser.username}` });
    } catch (err) {
        console.error('[Permissions] Error:', err);
        res.status(500).json({ success: false, message: 'Failed to update permissions. Please try again..' });
    }
});

router.post('/api/mapping/permissions/bulk-update', requireReAuth, async (req, res) => {
    if (req.session.role !== 'SuperAdmin') {
        return res.status(403).json({ success: false, message: 'SuperAdmin access required.' });
    }

    try {
        const { updates: updates } = req.body;

        if (!updates || !Array.isArray(updates)) {
            return res.json({ success: false, message: 'Missing required fields for update.' });
        }

        for (const item of updates) {
            if (!item.userId || !validatePermissions(item.permissions)) {
                return res.json({ success: false, message: 'Invalid permission value.' });
            }
        }

        const results = [];
        for (const item of updates) {
            const { error: updateError } = await supabase
                .from('users')
                .update({ permissions: item.permissions })
                .eq('id', item.userId);

            results.push({ userId: item.userId, success: !updateError });
        }

        await logEvent(req.session.userId, 'PERMISSIONS_BULK_UPDATED', `Bulk permissions update for ${updates.length}, users`, req.ip);

        res.json({
            success: true,
            message: `Processed ${updates.length} permission updates.`,
            results: results
        });
    } catch (err) {
        console.error('[Bulk Update] Error:', err);
        res.status(500).json({ success: false, message: 'Failed to update permissions. Please try again..' });
    }
});

// --- Trusted Locations API ---

router.get('/api/mapping/trusted-locations/pending', async (req, res) => {
    if (req.session.role !== 'SuperAdmin' && req.session.role !== 'IT') {
        return res.status(403).json({ error: 'Access denied: Administrative credentials required.' });
    }
    try {
        const { data: pendingLocations, error: updateError } = await supabase
            .from('trusted_locations')
            .select(`
                id, label, country, ip_address, status, created_at,
                users!trusted_locations_user_id_fkey ( id, username, department )
            `)
            .eq('status', 'pending')
            .order('created_at', { ascending: false });
            
        if (updateError) throw updateError;
        res.json(pendingLocations || []);
    } catch (err) {
        console.error('[Locations] Error loading:', err);
        res.status(500).json([]);
    }
});

router.post('/api/mapping/trusted-locations/approve', requireReAuth, async (req, res) => {
    if (req.session.role !== 'SuperAdmin' && req.session.role !== 'IT') {
        return res.status(403).json({ success: false, message: 'Access denied: Administrative credentials required.' });
    }
    try {
        const { id: locationId } = req.body;
        if (!locationId) return res.json({ success: false, message: 'Missing required field: location ID.' });
        
        const { error: updateError } = await supabase
            .from('trusted_locations')
            .update({ status: 'approved', approved_by: req.session.userId })
            .eq('id', locationId);
            
        if (updateError) throw updateError;
        
        await logEvent(req.session.userId, 'LOCATION_APPROVED', `Trusted location approved: ID ${locationId}`, req.ip);
        res.json({ success: true, message: 'Location approved..' });
    } catch (err) {
        console.error('[Locations] Approve error:', err);
        res.status(500).json({ success: false, message: 'Failed to approve location. Please try again..' });
    }
});

router.post('/api/mapping/trusted-locations/reject', requireReAuth, async (req, res) => {
    if (req.session.role !== 'SuperAdmin' && req.session.role !== 'IT') {
        return res.status(403).json({ success: false, message: 'Access denied: Administrative credentials required.' });
    }
    try {
        const { id: locationId } = req.body;
        if (!locationId) return res.json({ success: false, message: 'Missing required field: location ID.' });
        
        const { error: updateError } = await supabase
            .from('trusted_locations')
            .update({ status: 'rejected', approved_by: req.session.userId })
            .eq('id', locationId);
            
        if (updateError) throw updateError;
        
        await logEvent(req.session.userId, 'LOCATION_REJECTED', `Location removed: ID ${locationId}`, req.ip);
        res.json({ success: true, message: 'Location has been removed.' });
    } catch (err) {
        console.error('[Locations] Remove error:', err);
        res.status(500).json({ success: false, message: 'Failed to remove location. Please try again..' });
    }
});

module.exports = router;
