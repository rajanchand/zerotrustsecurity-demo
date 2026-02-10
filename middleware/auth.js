// middleware/auth.js
// authentication guard with session-device binding, concurrent session control,
// password expiry check, and continuous risk assessment

var { logSecurityEvent } = require('../services/monitorService');
var { supabase } = require('../db');

// paths that don't require authentication
var PUBLIC_PATHS = ['/login', '/logout', '/css', '/js', '/api/csrf-token'];

// how often to re-validate session token against DB (ms)
var SESSION_CHECK_INTERVAL = 10 * 1000; // 10 seconds for real-time revocation kill switch

async function requireLogin(req, res, next) {
    // allow login, logout, and static routes
    if (PUBLIC_PATHS.some(function (p) { return req.path === p || req.path.startsWith(p + '/'); })) {
        return next();
    }

    if (!req.session || !req.session.userId) {
        return res.redirect('/login');
    }

    // TIME-BASED CONTINUOUS ACCESS CONTROL (Using UTC to avoid VPS timezone issues)
    var currentHour = new Date().getUTCHours();
    var ALLOW_START = 0;   // Allow all hours (adjust as needed, e.g. 6-22 for 6AM-10PM UTC)
    var ALLOW_END = 24;

    if (currentHour < ALLOW_START || currentHour >= ALLOW_END) {
        if (req.session) {
            req.session.destroy(function() {
                res.redirect('/login?msg=off_hours');
            });
        } else {
            res.redirect('/login?msg=off_hours');
        }
        return;
    }

    // CONDITIONAL ACCESS: Block high-risk sessions
    if (req.session.highRisk && req.path !== '/security-block' && req.path !== '/logout') {
        return res.redirect('/security-block');
    }

    // SESSION TIMEOUT: 15 minutes inactivity
    var now = Date.now();
    var lastActive = req.session.lastActive || now;
    var timeout = 15 * 60 * 1000;

    if (now - lastActive > timeout) {
        var uid = req.session.userId;
        var uname = req.session.username || 'unknown';
        req.session.destroy(function () {
            logSecurityEvent({
                event_type: 'FORCE_LOGOUT',
                user_id: uid,
                username: uname,
                ip: req.ip,
                details: { reason: 'Session timeout (15 min inactivity)', path: req.path }
            }).catch(function () { });
            res.redirect('/login?msg=session_expired');
        });
        return;
    }

    // update last active
    req.session.lastActive = now;

    // SESSION-DEVICE BINDING: detect session hijacking
    var clientFingerprint = req.headers['x-device-fingerprint'];
    if (clientFingerprint && req.session.deviceFingerprint && clientFingerprint !== req.session.deviceFingerprint) {
        var hijackUid = req.session.userId;
        var hijackUname = req.session.username || 'unknown';
        logSecurityEvent({
            event_type: 'SESSION_HIJACK_ATTEMPT',
            user_id: hijackUid,
            username: hijackUname,
            ip: req.ip,
            details: {
                reason: 'Device fingerprint mismatch mid-session',
                expected: req.session.deviceFingerprint,
                received: clientFingerprint
            }
        }).catch(function () { });
        req.session.destroy(function () {
            res.redirect('/login?msg=session_invalid');
        });
        return;
    }

    // CONCURRENT SESSION CONTROL & KILL SWITCH: check token and status periodically
    var lastSessionCheck = req.session.lastSessionCheck || 0;
    if (now - lastSessionCheck > SESSION_CHECK_INTERVAL && req.session.sessionToken) {
        req.session.lastSessionCheck = now;
        try {
            // synchronous database check for kill switch
            var { data: result } = await supabase
                .from('users')
                .select('status, active_session_token, password_changed_at')
                .eq('id', req.session.userId)
                .single();

            if (result) {
                // 1. KILL SWITCH: Blocked or Suspended Accounts
                if (result.status !== 'active') {
                    await logSecurityEvent({
                        event_type: 'FORCE_LOGOUT',
                        user_id: req.session.userId,
                        username: req.session.username || 'unknown',
                        ip: req.ip,
                        details: { reason: 'Kill switch triggered. Account status changed to: ' + result.status }
                    }).catch(function () { });
                    
                    return req.session.destroy(function () {
                        res.redirect('/login?msg=account_blocked');
                    });
                }

                // 2. CONCURRENT LOGIN REVOCATION: Newer login detected elsewhere
                if (result.active_session_token && result.active_session_token !== req.session.sessionToken) {
                    await logSecurityEvent({
                        event_type: 'FORCE_LOGOUT',
                        user_id: req.session.userId,
                        username: req.session.username || 'unknown',
                        ip: req.ip,
                        details: { reason: 'Concurrent login detected — session invalidated by newer login' }
                    }).catch(function () { });
                    
                    return req.session.destroy(function () {
                        res.redirect('/login?msg=session_invalid');
                    });
                }

                // 3. PASSWORD EXPIRY: check if password older than 90 days
                if (result.password_changed_at) {
                    var changedAt = new Date(result.password_changed_at).getTime();
                    var ninetyDays = 90 * 24 * 60 * 60 * 1000;
                    if (Date.now() - changedAt > ninetyDays) {
                        req.session.passwordExpired = true;
                    }
                }
            }
        } catch (err) {
            // Ignore DB timeouts to avoid locking out verified users if Supabase has a blip
        }
    }

    // PASSWORD EXPIRY: redirect to profile if password expired (except profile and API routes)
    if (req.session.passwordExpired && req.path !== '/profile' && !req.path.startsWith('/api/profile') && req.path !== '/logout') {
        if (req.path.startsWith('/api/')) {
            return res.status(403).json({ success: false, passwordExpired: true, message: 'Your password has expired. Please change it in your profile.' });
        }
        return res.redirect('/profile?msg=password_expired');
    }

    // OTP check (except on OTP page itself)
    if (req.path !== '/otp' && req.path !== '/verify-otp' && !req.session.otpVerified) {
        return res.redirect('/otp');
    }

    next();
}

module.exports = { requireLogin };
