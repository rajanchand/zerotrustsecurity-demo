// routes/profileRoutes.js
// user profile: view/edit own details, change password
// includes: password policy enforcement, password history

var express = require('express');
var bcrypt = require('bcryptjs');
var path = require('path');
var { supabase } = require('../db');
var { logEvent } = require('../services/auditService');
var { validatePassword } = require('../middleware/passwordPolicy');

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
            .select('id, username, name, phone, email, role, department, status, password_changed_at, created_at')
            .eq('id', req.session.userId)
            .single();

        if (!user) return res.json({ error: 'User not found' });

        // add password age info
        if (user.password_changed_at) {
            var daysSinceChange = Math.floor((Date.now() - new Date(user.password_changed_at).getTime()) / (1000 * 60 * 60 * 24));
            user.passwordAgeDays = daysSinceChange;
            user.passwordExpiresSoon = daysSinceChange > 75; // warn at 75 days
            user.passwordExpired = daysSinceChange > 90;
        }

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

// change own password — with policy enforcement and password history
router.post('/api/profile/change-password', async function (req, res) {
    try {
        var { currentPassword, newPassword } = req.body;

        if (!currentPassword || !newPassword) {
            return res.json({ success: false, message: 'Both current and new password are required.' });
        }

        // PASSWORD POLICY: enforce strong passwords
        var policy = validatePassword(newPassword);
        if (!policy.valid) {
            return res.json({ success: false, message: policy.errors.join(' ') });
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

        // PASSWORD HISTORY: check against last 3 passwords
        try {
            var { data: history } = await supabase
                .from('password_history')
                .select('password_hash')
                .eq('user_id', req.session.userId)
                .order('created_at', { ascending: false })
                .limit(3);

            if (history && history.length > 0) {
                for (var i = 0; i < history.length; i++) {
                    if (bcrypt.compareSync(newPassword, history[i].password_hash)) {
                        return res.json({ success: false, message: 'Cannot reuse your last 3 passwords. Please choose a different password.' });
                    }
                }
            }
        } catch (e) {
            // password_history table may not exist yet — skip check
        }

        // also check against current password
        if (bcrypt.compareSync(newPassword, user.password_hash)) {
            return res.json({ success: false, message: 'New password must be different from current password.' });
        }

        // hash and save new password
        var newHash = bcrypt.hashSync(newPassword, 10);
        await supabase.from('users').update({
            password_hash: newHash,
            password_changed_at: new Date().toISOString()
        }).eq('id', req.session.userId);

        // save old password to history
        try {
            await supabase.from('password_history').insert({
                user_id: req.session.userId,
                password_hash: user.password_hash
            });
        } catch (e) {
            // password_history table may not exist yet
        }

        // clear password expired flag
        if (req.session.passwordExpired) {
            req.session.passwordExpired = false;
        }

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
            .select('id, username, name, phone, email, role, department, status, password_changed_at, created_at')
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

// admin: change any user password — with policy enforcement
router.post('/api/profile/:userId/change-password', async function (req, res) {
    try {
        var role = req.session.role;
        if (role !== 'SuperAdmin') {
            return res.status(403).json({ success: false, message: 'Access denied' });
        }

        var { newPassword } = req.body;

        // PASSWORD POLICY
        var policy = validatePassword(newPassword);
        if (!policy.valid) {
            return res.json({ success: false, message: policy.errors.join(' ') });
        }

        var targetId = parseInt(req.params.userId);

        // get current hash for history
        var { data: targetUser } = await supabase.from('users').select('username, password_hash').eq('id', targetId).single();

        var newHash = bcrypt.hashSync(newPassword, 10);
        await supabase.from('users').update({
            password_hash: newHash,
            password_changed_at: new Date().toISOString()
        }).eq('id', targetId);

        // save old password to history
        if (targetUser) {
            try {
                await supabase.from('password_history').insert({
                    user_id: targetId,
                    password_hash: targetUser.password_hash
                });
            } catch (e) { }
        }

        await logEvent(req.session.userId, 'ADMIN_PASSWORD_RESET', 'Reset password for: ' + (targetUser ? targetUser.username : targetId), req.ip);
        res.json({ success: true, message: 'Password changed.' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

module.exports = router;
