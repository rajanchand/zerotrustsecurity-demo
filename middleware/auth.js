// middleware/auth.js
// checks if the user is logged in and session is valid

var { logSecurityEvent } = require('../services/monitorService');

function requireLogin(req, res, next) {
    // allow login and static routes
    if (req.path === '/login' || req.path === '/logout' || req.path.startsWith('/css') || req.path.startsWith('/js')) {
        return next();
    }

    if (!req.session || !req.session.userId) {
        return res.redirect('/login');
    }

    // check session timeout (15 minutes of inactivity)
    var now = Date.now();
    var lastActive = req.session.lastActive || now;
    var timeout = 15 * 60 * 1000;

    if (now - lastActive > timeout) {
        var uid  = req.session.userId;
        var uname = req.session.username || 'unknown';
        req.session.destroy(function () {
            logSecurityEvent({
                event_type: 'FORCE_LOGOUT',
                user_id: uid,
                username: uname,
                ip: req.ip,
                details: { reason: 'Session timeout (15 min inactivity)', path: req.path }
            }).catch(function(){});
            res.redirect('/login?msg=session_expired');
        });
        return;
    }

    // update last active
    req.session.lastActive = now;

    // check if OTP verified (except on OTP page itself)
    if (req.path !== '/otp' && req.path !== '/verify-otp' && !req.session.otpVerified) {
        return res.redirect('/otp');
    }

    next();
}

module.exports = { requireLogin };

