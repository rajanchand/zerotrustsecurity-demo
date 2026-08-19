var express = require('express');
var bcrypt = require('bcryptjs');
var path = require('path');
var { supabase } = require('../db');
var { logEvent } = require('../services/auditService');
var { validatePassword } = require('../middleware/passwordPolicy');

var router = express.Router();

// serve profile page
router.get('/profile', function(req, res) {
    res.sendFile(path.join(__dirname, '..', 'views', 'profile.html'));
});

// get current users profile
router.get('/api/profile', async function(req, res) {
    try {
        var { data: user } = await supabase
            .from('users')
            .select('id, username, name, phone, email, role, department, status, password_changed_at, created_at')
            .eq('id', req.session.userId)
            .single();

        if (!user) {
            return res.status(404).json({ error: 'User not found.' });
        }

        if (user.password_changed_at) {
            var now = Date.now();
            var lastChange = new Date(user.password_changed_at).getTime();
            var ageDays = Math.floor((now - lastChange) / (1000 * 60 * 60 * 24));

            user.credentialAgeDays = ageDays;
            user.credentialRotationRequested = ageDays > 75;
            user.credentialRotationMandated = ageDays > 90;
        }

        res.json(user);
    } catch (err) {
        console.error('Profile load error:', err);
        res.status(500).json({ error: 'Failed to load profile.' });
    }
});

// update profile info
router.post('/api/profile/update', async function(req, res) {
    try {
        var name = req.body.name || '';
        var phone = req.body.phone || '';
        var email = req.body.email || '';

        await supabase.from('users').update({ name: name, phone: phone, email: email }).eq('id', req.session.userId);

        await logEvent(req.session.userId, 'PROFILE_UPDATED', 'Profile updated', req.ip);
        res.json({ success: true, message: 'Profile updated.' });
    } catch (err) {
        console.error('Profile update error:', err);
        res.status(500).json({ success: false, message: 'Failed to update profile.' });
    }
});

// change password (support both endpoint aliases)
async function handleChangePassword(req, res) {
    try {
        var currentPassword = req.body.currentPassword;
        var newPassword = req.body.newPassword;

        if (!currentPassword || !newPassword) {
            return res.status(400).json({ success: false, message: 'Please fill in all fields.' });
        }

        var policyCheck = validatePassword(newPassword);
        if (!policyCheck.valid) {
            return res.status(400).json({ success: false, message: policyCheck.errors.join(' ') });
        }

        var { data: user } = await supabase
            .from('users')
            .select('password_hash')
            .eq('id', req.session.userId)
            .single();

        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }

        var isCurrentCorrect = await bcrypt.compare(currentPassword, user.password_hash);
        if (!isCurrentCorrect) {
            return res.status(401).json({ success: false, message: 'Current password is wrong.' });
        }

        // check against recent passwords
        try {
            var { data: oldPasswords } = await supabase
                .from('password_history')
                .select('password_hash')
                .eq('user_id', req.session.userId)
                .order('created_at', { ascending: false })
                .limit(3);

            if (oldPasswords && oldPasswords.length) {
                for (var i = 0; i < oldPasswords.length; i++) {
                    if (await bcrypt.compare(newPassword, oldPasswords[i].password_hash)) {
                        return res.status(400).json({ success: false, message: 'This password was used recently. Please choose a different one.' });
                    }
                }
            }
        } catch (err) {
            // password history check is optional
        }

        if (await bcrypt.compare(newPassword, user.password_hash)) {
            return res.status(400).json({ success: false, message: 'New password must be different from current password.' });
        }

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
        } catch (err) {
            // saving to history is optional
        }

        if (req.session.passwordExpired) req.session.passwordExpired = false;

        await logEvent(req.session.userId, 'PASSWORD_CHANGED', 'Password changed', req.ip);
        res.json({ success: true, message: 'Password changed.' });
    } catch (err) {
        console.error('Password change error:', err);
        res.status(500).json({ success: false, message: 'Failed to change password.' });
    }
}

router.post('/api/profile/change-password', handleChangePassword);
router.post('/api/profile/update-password', handleChangePassword);

// get another users profile (admin only)
router.get('/api/profile/:userId', async function(req, res) {
    if (req.session.role !== 'SuperAdmin') {
        return res.status(403).json({ error: 'Admin access required.' });
    }

    try {
        var targetId = req.params.userId;
        var { data: user } = await supabase
            .from('users')
            .select('id, username, name, phone, email, role, department, status, password_changed_at, created_at')
            .eq('id', targetId)
            .single();

        if (!user) {
            return res.status(404).json({ error: 'User not found.' });
        }
        res.json(user);
    } catch (err) {
        res.status(500).json({ error: 'Failed to load user details.' });
    }
});

// admin update another users profile
router.post('/api/profile/:userId/update', async function(req, res) {
    if (req.session.role !== 'SuperAdmin') {
        return res.status(403).json({ success: false, message: 'Admin access required.' });
    }

    try {
        var name = req.body.name || '';
        var phone = req.body.phone || '';
        var email = req.body.email || '';
        var targetId = parseInt(req.params.userId);

        await supabase.from('users').update({ name: name, phone: phone, email: email }).eq('id', targetId);

        var { data: targetUser } = await supabase.from('users').select('username').eq('id', targetId).single();
        await logEvent(req.session.userId, 'ADMIN_PROFILE_UPDATED', 'Updated profile for ' + ((targetUser && targetUser.username) || targetId), req.ip);
        res.json({ success: true, message: 'User profile updated.' });
    } catch (err) {
        console.error('Admin profile update error:', err);
        res.status(500).json({ success: false, message: 'Failed to update user.' });
    }
});

// admin reset another users password
router.post('/api/profile/:userId/change-password', async function(req, res) {
    if (req.session.role !== 'SuperAdmin') {
        return res.status(403).json({ success: false, message: 'Admin access required.' });
    }

    try {
        var newPassword = req.body.newPassword;
        var policyCheck = validatePassword(newPassword);
        if (!policyCheck.valid) {
            return res.status(400).json({ success: false, message: policyCheck.errors.join(' ') });
        }

        var targetId = parseInt(req.params.userId);
        var { data: targetUser } = await supabase.from('users').select('username, password_hash').eq('id', targetId).single();

        var newHash = bcrypt.hashSync(newPassword, 10);
        await supabase.from('users').update({
            password_hash: newHash,
            password_changed_at: new Date().toISOString()
        }).eq('id', targetId);

        if (targetUser) {
            try {
                await supabase.from('password_history').insert({
                    user_id: targetId,
                    password_hash: targetUser.password_hash
                });
            } catch (err) {
                // password history is optional
            }
        }

        await logEvent(req.session.userId, 'ADMIN_PASSWORD_RESET', 'Admin reset password for ' + ((targetUser && targetUser.username) || targetId), req.ip);
        res.json({ success: true, message: 'Password reset done.' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Failed to reset password.' });
    }
});

// request to save current location as trusted
router.post('/api/profile/trusted-locations/request', async function(req, res) {
    try {
        var userId = req.session.userId;
        var userIP = req.session.loginIP;
        var userCountry = req.session.loginCountry;

        if (!userId) {
            return res.status(401).json({ success: false, message: 'Please log in first.' });
        }

        var label = req.body.label || 'Home';
        var ip = userIP || req.ip;
        var country = userCountry || 'Unknown';

        var { data: existing } = await supabase
            .from('trusted_locations')
            .select('id, status')
            .eq('user_id', userId)
            .eq('ip_address', ip)
            .maybeSingle();

        if (existing) {
            if (existing.status === 'approved') {
                return res.json({ success: false, message: 'This location is already saved as trusted.' });
            }
            if (existing.status === 'pending') {
                return res.json({ success: false, message: 'This location is already waiting for approval.' });
            }
        }

        var { error } = await supabase.from('trusted_locations').insert({
            user_id: userId,
            label: label,
            country: country,
            ip_address: ip,
            status: 'pending'
        });

        if (error) throw error;

        await logEvent(userId, 'LOCATION_REQUEST', 'Location saved: ' + ip, ip);
        res.json({ success: true, message: 'Location saved. Waiting for admin approval.' });
    } catch (err) {
        console.error('Location save error:', err);
        res.status(500).json({ success: false, message: 'Failed to save location.' });
    }
});

// end all sessions for the current user
router.post('/api/profile/end-sessions', async function(req, res) {
    try {
        var { error } = await supabase
            .from('sessions_log')
            .update({ active: false })
            .eq('user_id', req.session.userId);

        if (error) throw error;

        await logEvent(req.session.userId, 'USER_ENDED_SESSIONS', 'User ended all their active sessions', req.ip);

        req.session.destroy();

        res.json({ success: true, message: 'All your sessions have been ended. You will be logged out.' });
    } catch (err) {
        console.error('[Profile] End sessions error:', err);
        res.status(500).json({ success: false, message: 'Could not end sessions.' });
    }
});

module.exports = router;
