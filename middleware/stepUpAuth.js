var bcrypt = require('bcryptjs');
var { supabase } = require('../db');
var { logEvent } = require('../services/auditService');

// re-auth window lasts 5 minutes
var REAUTH_WINDOW = 5 * 60 * 1000;

// check if user recently confirmed their password
// if they did it within 5 mins let them through, otherwise ask again
function requireReAuth(req, res, next) {
    if (!req.session?.userId) {
        return res.status(401).json({ success: false, message: 'Please log in.' });
    }

    var lastVerified = req.session.lastReAuth || 0;
    var timeSince = Date.now() - lastVerified;

    if (timeSince < REAUTH_WINDOW) {
        return next();
    }

    return res.status(401).json({
        success: false,
        requireReAuth: true,
        message: 'Please confirm your password to continue.'
    });
}

// handle the password confirmation
async function handleReAuth(req, res) {
    try {
        var password = req.body.password || '';

        if (!password) {
            return res.status(400).json({ success: false, message: 'Password is required to confirm this action.' });
        }

        var { data: user } = await supabase
            .from('users')
            .select('password_hash')
            .eq('id', req.session.userId)
            .single();

        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }

        var isCorrect = await bcrypt.compare(password, user.password_hash);
        if (!isCorrect) {
            await logEvent(req.session.userId, 'STEP_UP_VERIFICATION_FAILED', 'Wrong password during confirmation', req.ip);
            return res.status(401).json({ success: false, message: 'Wrong password.' });
        }

        req.session.lastReAuth = Date.now();
        await logEvent(req.session.userId, 'STEP_UP_VERIFICATION_SUCCESSFUL', 'Password confirmed', req.ip);

        req.session.save(function(err) {
            if (err) console.error('Session save error:', err);
            res.json({ success: true, message: 'Confirmed.' });
        });
    } catch (err) {
        console.error('Verification error:', err);
        res.status(500).json({ success: false, message: 'Verification failed. Try again.' });
    }
}

module.exports = { requireReAuth: requireReAuth, handleReAuth: handleReAuth };
