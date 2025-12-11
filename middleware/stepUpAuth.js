// middleware/stepUpAuth.js
// re-authentication for sensitive operations (step-up auth)

const bcrypt = require('bcryptjs');
const { supabase } = require('../db');
const { logEvent } = require('../services/auditService');

const REAUTH_WINDOW = 5 * 60 * 1000; // 5 minutes

function requireReAuth(req, res, next) {
    if (!req.session || !req.session.userId) {
        return res.status(401).json({ success: false, message: 'Not authenticated.' });
    }

    var lastReAuth = req.session.lastReAuth || 0;
    var now = Date.now();

    if (now - lastReAuth > REAUTH_WINDOW) {
        return res.status(403).json({
            success: false,
            requireReAuth: true,
            message: 'This action requires re-authentication. Please confirm your password.'
        });
    }

    next();
}

// POST /api/verify-reauth — verify password for step-up
async function handleReAuth(req, res) {
    try {
        var password = req.body.password || '';

        if (!password) {
            return res.json({ success: false, message: 'Password is required.' });
        }

        var { data: user } = await supabase
            .from('users')
            .select('password_hash')
            .eq('id', req.session.userId)
            .single();

        if (!user) {
            return res.json({ success: false, message: 'User not found.' });
        }

        var match = bcrypt.compareSync(password, user.password_hash);
        if (!match) {
            await logEvent(req.session.userId, 'REAUTH_FAILED', 'Step-up re-authentication failed', req.ip);
            return res.json({ success: false, message: 'Incorrect password.' });
        }

        req.session.lastReAuth = Date.now();
        await logEvent(req.session.userId, 'REAUTH_SUCCESS', 'Step-up re-authentication successful', req.ip);

        req.session.save(function (err) {
            if (err) console.error('Session save error:', err);
            res.json({ success: true, message: 'Re-authenticated successfully.' });
        });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
}

module.exports = { requireReAuth, handleReAuth };
