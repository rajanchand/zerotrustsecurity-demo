const express = require('express');
const bcrypt = require('bcryptjs');
const path = require('path');
const { supabase } = require('../db');
const { logEvent } = require('../services/auditService');
const { validatePassword } = require('../middleware/passwordPolicy');

const router = express.Router();

router.get('/profile', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'views', 'profile.html'));
});

router.get('/api/profile', async (req, res) => {
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

router.post('/api/profile/update', async (req, res) => {
    try {
        var { name = '', phone = '', email = '' } = req.body;

        await supabase.from('users').update({ name, phone, email }).eq('id', req.session.userId);

        await logEvent(req.session.userId, 'PROFILE_SYNCHRONIZED', 'Profile updated', req.ip);
        res.json({ success: true, message: 'Profile updated.' });
    } catch (err) {
        console.error('Profile update error:', err);
        res.status(500).json({ success: false, message: 'Failed to update profile.' });
    }
});

router.post('/api/profile/change-password', async (req, res) => {
    try {
        var { currentPassword, newPassword } = req.body;

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

        try {
            var { data: oldPasswords } = await supabase
                .from('password_history')
                .select('password_hash')
                .eq('user_id', req.session.userId)
                .order('created_at', { ascending: false })
                .limit(3);

            if (oldPasswords?.length) {
                for (var old of oldPasswords) {
                    if (await bcrypt.compare(newPassword, old.password_hash)) {
                        return res.status(400).json({ success: false, message: 'This password was used recently. Please choose a different one.' });
                    }
                }
            }
        } catch (err) {
            // Password history check is optional
        }

        if (await bcrypt.compare(newPassword, user.password_hash)) {
            return res.status(400).json({ success: false, message: 'New password must be different from current password.' });
        }

        var newHash = bcrypt.hashSync(newPassword, 10);
        await supabase.from('users').update({
            password_hash: newHash,
            password_changed_at: new Date().toISOString()
        }).eq('id', req.session.userId);

        try {
            await supabase.from('password_history').insert({
                user_id: req.session.userId,
                password_hash: user.password_hash
            });
        } catch (err) {
            // Saving old password to history is optional
        }

        if (req.session.passwordExpired) req.session.passwordExpired = false;

        await logEvent(req.session.userId, 'CREDENTIAL_ROTATED', 'Password changed', req.ip);
        res.json({ success: true, message: 'Password changed.' });
    } catch (err) {
        console.error('Password change error:', err);
        res.status(500).json({ success: false, message: 'Failed to change password.' });
    }
});

router.get('/api/profile/:userId', async (req, res) => {
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

router.post('/api/profile/:userId/update', async (req, res) => {
    if (req.session.role !== 'SuperAdmin') {
        return res.status(403).json({ success: false, message: 'Admin access required.' });
    }

    try {
        var { name = '', phone = '', email = '' } = req.body;
        var targetId = parseInt(req.params.userId);

        await supabase.from('users').update({ name, phone, email }).eq('id', targetId);

        var { data: targetUser } = await supabase.from('users').select('username').eq('id', targetId).single();
        await logEvent(req.session.userId, 'ADMIN_IDENTITY_SYNCHRONIZED', 'Updated profile for ' + (targetUser?.username || targetId), req.ip);
        res.json({ success: true, message: 'User profile updated.' });
    } catch (err) {
        console.error('Admin profile update error:', err);
        res.status(500).json({ success: false, message: 'Failed to update user.' });
    }
});

router.post('/api/profile/:userId/change-password', async (req, res) => {
    if (req.session.role !== 'SuperAdmin') {
        return res.status(403).json({ success: false, message: 'Admin access required.' });
    }

    try {
        var { newPassword } = req.body;
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
                // Password history is optional
            }
        }

        await logEvent(req.session.userId, 'ADMIN_CREDENTIAL_ROTATED', 'Admin reset password for ' + (targetUser?.username || targetId), req.ip);
        res.json({ success: true, message: 'Password reset done.' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Failed to reset password.' });
    }
});

router.post('/api/profile/trusted-locations/request', async (req, res) => {
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

        await logEvent(userId, 'LOCATION_AUTHORIZATION_REQUESTED', 'Location saved: ' + ip, ip);
        res.json({ success: true, message: 'Location saved. Waiting for admin approval.' });
    } catch (err) {
        console.error('Location save error:', err);
        res.status(500).json({ success: false, message: 'Failed to save location.' });
    }
});

module.exports = router;
