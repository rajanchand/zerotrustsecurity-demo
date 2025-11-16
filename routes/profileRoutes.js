// routes/profileRoutes.js
// user profile: view/edit own details, change password

var express = require('express');
var bcrypt = require('bcryptjs');
var path = require('path');
var { supabase } = require('../db');
var { logEvent } = require('../services/auditService');

var router = express.Router();

// serve profile page
router.get('/profile', function (req, res) {
    res.sendFile(path.join(__dirname, '..', 'views', 'profile.html'));
});

// get own profile data
router.get('/api/profile', async function (req, res) {
    try {
        var { data: user } = await supabase
            .from('users')
            .select('id, username, name, phone, email, role, department, status, created_at')
            .eq('id', req.session.userId)
            .single();

        if (!user) return res.json({ error: 'User not found' });
        res.json(user);
    } catch (err) {
        res.status(500).json({ error: 'Failed to load profile' });
    }
});

// update own profile (name, phone, email)
router.post('/api/profile/update', async function (req, res) {
    try {
        var { name, phone, email } = req.body;

        await supabase.from('users').update({
            name: name || '',
            phone: phone || '',
            email: email || ''
        }).eq('id', req.session.userId);

        await logEvent(req.session.userId, 'PROFILE_UPDATED', 'Updated profile details', req.ip);
        res.json({ success: true, message: 'Profile updated.' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

// change own password
router.post('/api/profile/change-password', async function (req, res) {
    try {
        var { currentPassword, newPassword } = req.body;

        if (!currentPassword || !newPassword) {
            return res.json({ success: false, message: 'Both current and new password are required.' });
        }

        if (newPassword.length < 6) {
            return res.json({ success: false, message: 'New password must be at least 6 characters.' });
        }

        // verify current password
        var { data: user } = await supabase
            .from('users')
            .select('password_hash')
            .eq('id', req.session.userId)
            .single();

        if (!user) return res.json({ success: false, message: 'User not found.' });

        var match = bcrypt.compareSync(currentPassword, user.password_hash);
        if (!match) {
            return res.json({ success: false, message: 'Current password is incorrect.' });
        }

        // hash and save new password
        var newHash = bcrypt.hashSync(newPassword, 10);
        await supabase.from('users').update({ password_hash: newHash }).eq('id', req.session.userId);

        await logEvent(req.session.userId, 'PASSWORD_CHANGED', 'User changed their password', req.ip);
        res.json({ success: true, message: 'Password changed successfully.' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

// admin: get any user profile
router.get('/api/profile/:userId', async function (req, res) {
    try {
        var role = req.session.role;
        if (role !== 'SuperAdmin') {
            return res.status(403).json({ error: 'Access denied' });
        }

        var { data: user } = await supabase
            .from('users')
            .select('id, username, name, phone, email, role, department, status, created_at')
            .eq('id', req.params.userId)
            .single();

        if (!user) return res.json({ error: 'User not found' });
        res.json(user);
    } catch (err) {
        res.status(500).json({ error: 'Failed to load profile' });
    }
});

// admin: update any user profile
router.post('/api/profile/:userId/update', async function (req, res) {
    try {
        var role = req.session.role;
        if (role !== 'SuperAdmin') {
            return res.status(403).json({ success: false, message: 'Access denied' });
        }

        var { name, phone, email } = req.body;
        var targetId = parseInt(req.params.userId);

        await supabase.from('users').update({
            name: name || '',
            phone: phone || '',
            email: email || ''
        }).eq('id', targetId);

        var { data: target } = await supabase.from('users').select('username').eq('id', targetId).single();
        await logEvent(req.session.userId, 'ADMIN_PROFILE_UPDATE', 'Updated profile for: ' + (target ? target.username : targetId), req.ip);
        res.json({ success: true, message: 'Profile updated.' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

// admin: change any user password
router.post('/api/profile/:userId/change-password', async function (req, res) {
    try {
        var role = req.session.role;
        if (role !== 'SuperAdmin') {
            return res.status(403).json({ success: false, message: 'Access denied' });
        }

        var { newPassword } = req.body;
        if (!newPassword || newPassword.length < 6) {
            return res.json({ success: false, message: 'Password must be at least 6 characters.' });
        }

        var targetId = parseInt(req.params.userId);
        var newHash = bcrypt.hashSync(newPassword, 10);
        await supabase.from('users').update({ password_hash: newHash }).eq('id', targetId);

        var { data: target } = await supabase.from('users').select('username').eq('id', targetId).single();
        await logEvent(req.session.userId, 'ADMIN_PASSWORD_RESET', 'Reset password for: ' + (target ? target.username : targetId), req.ip);
        res.json({ success: true, message: 'Password changed.' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

module.exports = router;
