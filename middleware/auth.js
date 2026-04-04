// middleware/auth.js
// authentication guard with session-device binding, concurrent session control,
// password expiry check, and continuous risk assessment

var { logSecurityEvent } = require('../services/monitorService');
var { supabase } = require('../db');

// paths that don't need authentication
var PUBLIC_PATHS = [
    '/login', '/logout', '/otp', '/verify-otp', 
    '/api/login', '/api/verify-otp', '/api/session',
    '/css', '/js', '/api/csrf-token'
];

// how often to re-validate the session token against the database (ms)
// this drives the real-time account kill-switch and concurrent session revocation
var SESSION_CHECK_INTERVAL = 10 * 1000; // 10 seconds

async function requireLogin(req, res, next) {

    // let public routes through without any checks
    if (PUBLIC_PATHS.some(function (p) {
        return req.path === p || req.path.startsWith(p + '/');
    })) {
        return next();
    }

    if (!req.session || !req.session.userId) {
        return res.redirect('/login');
    }

    // ── TIME-BASED CONTINUOUS ACCESS CONTROL (UTC) ──
    var currentHour = new Date().getUTCHours();
    var ALLOW_START = 0;
    var ALLOW_END = 24; // allow all hours — change to e.g. 6/22 for restricted window

    if (currentHour < ALLOW_START || currentHour >= ALLOW_END) {
        if (req.session) {
            req.session.destroy(function () {
                res.redirect('/login?msg=off_hours');
            });
        } else {
            res.redirect('/login?msg=off_hours');
        }
        return;
    }

    // ── HIGH-RISK SESSION BLOCK ──
    if (req.session.highRisk && req.path !== '/security-block' && req.path !== '/logout') {
        return res.redirect('/security-block');
    }

    // ── SESSION INACTIVITY TIMEOUT (15 minutes) ──
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
                details: { reason: 'Session timeout — 15 min inactivity', path: req.path }
            }).catch(function () { });
            res.redirect('/login?msg=session_expired');
        });
        return;
    }

    req.session.lastActive = now;

    // ── SESSION-DEVICE BINDING (detect potential session hijacking) ──
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

    // ── CONCURRENT SESSION CONTROL & KILL SWITCH (periodic DB check) ──
    var lastSessionCheck = req.session.lastSessionCheck || 0;
    if (now - lastSessionCheck > SESSION_CHECK_INTERVAL && req.session.sessionToken) {
        req.session.lastSessionCheck = now;
        try {
            var { data: result } = await supabase
                .from('users')
                .select('status, role, permissions, active_session_token, password_changed_at')
                .eq('id', req.session.userId)
                .single();

            if (result) {
                // 1. KILL SWITCH — account was blocked or suspended by an admin
                // SuperAdmin bypass: prevent total system lockout (they must be able to login to fix it)
                if (result.status !== 'active' && result.role !== 'SuperAdmin') {
                    await logSecurityEvent({
                        event_type: 'FORCE_LOGOUT',
                        user_id: req.session.userId,
                        username: req.session.username || 'unknown',
                        ip: req.ip,
                        details: { reason: 'Kill switch triggered — account status changed to: ' + result.status }
                    }).catch(function () { });
                    return req.session.destroy(function () {
                        res.redirect('/login?msg=account_blocked');
                    });
                }

                // 2. REAL-TIME ROLE & PERMISSION SYNC ──
                // If an admin changed the user's role or granular permissions, 
                // update the session immediately without requiring a logout.
                if (result.role !== req.session.role) {
                    console.log(`[AUTH] Syncing role for ${req.session.username}: ${req.session.role} -> ${result.role}`);
                    req.session.role = result.role;
                }
                
                var currentPermsStr = JSON.stringify(req.session.permissions || {});
                var dbPermsStr = JSON.stringify(result.permissions || {});
                if (currentPermsStr !== dbPermsStr) {
                    console.log(`[AUTH] Syncing permissions for ${req.session.username}`);
                    req.session.permissions = result.permissions || {};
                }

                // 3. CONCURRENT LOGIN REVOCATION — a newer login was made elsewhere
                if (
                    result.active_session_token &&
                    result.active_session_token !== req.session.sessionToken
                ) {
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

                // 4. PASSWORD EXPIRY — flag if password older than 90 days
                if (result.password_changed_at) {
                    var changedAt = new Date(result.password_changed_at).getTime();
                    var ninetyDays = 90 * 24 * 60 * 60 * 1000;
                    if (Date.now() - changedAt > ninetyDays) {
                        req.session.passwordExpired = true;
                    }
                }
            }
        } catch (err) {
            // ignore DB timeouts — don't lock out users over a transient Supabase blip
        }
    }

    // ── PASSWORD EXPIRY REDIRECT ──
    // Allow the profile page and ALL /api/profile/* calls (so the user can
    // actually change their password), plus logout. Block everything else.
    if (
        req.session.passwordExpired &&
        req.path !== '/profile' &&
        !req.path.startsWith('/api/profile') &&
        req.path !== '/logout'
    ) {
        if (req.path.startsWith('/api/')) {
            return res.status(403).json({
                success: false,
                passwordExpired: true,
                message: 'Your password has expired. Please update it in your profile.'
            });
        }
        return res.redirect('/profile?msg=password_expired');
    }

    // ── OTP GATE — redirect to OTP page if not yet verified ──
    if (req.path !== '/otp' && req.path !== '/verify-otp' && !req.session.otpVerified) {
        return res.redirect('/otp');
    }

    next();
}

module.exports = { requireLogin };
