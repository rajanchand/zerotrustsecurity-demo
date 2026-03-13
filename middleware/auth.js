var { logSecurityEvent } = require('../services/monitorService');
var { supabase } = require('../db');
var { generateOTP } = require('../services/otpService');

// Pages that don't need login
var PUBLIC_PATHS = [
    '/login', '/logout', '/otp', '/verify-otp',
    '/api/login', '/api/verify-otp', '/api/session',
    '/css', '/js', '/api/csrf-token'
];

// How often to check the database for user status changes (10 seconds)
var SESSION_CHECK_INTERVAL = 10 * 1000;

/**
 * Main login check middleware.
 * Makes sure the user is logged in and their session is still valid.
 */
async function requireLogin(req, res, next) {

    // Skip login check for public pages
    if (PUBLIC_PATHS.some(function(p) { return req.path === p || req.path.startsWith(p + '/'); })) {
        return next();
    }

    // Not logged in? Go to login page
    if (!req.session || !req.session.userId) {
        return res.redirect('/login');
    }

    // Check working hours (0-24 means always open)
    var currentHour = new Date().getUTCHours();
    var START_HOUR = 0;
    var END_HOUR = 24;

    if (currentHour < START_HOUR || currentHour >= END_HOUR) {
        if (req.session) {
            req.session.destroy(function() { res.redirect('/login?msg=off_hours'); });
        } else {
            res.redirect('/login?msg=off_hours');
        }
        return;
    }

    // High risk users go to security block page
    if (req.session.highRisk && req.path !== '/security-block' && req.path !== '/logout') {
        return res.redirect('/security-block');
    }

    // Check for inactivity (15 minutes)
    var now = Date.now();
    var lastActive = req.session.lastActive || now;
    var TIMEOUT = 15 * 60 * 1000;

    if (now - lastActive > TIMEOUT) {
        var userId = req.session.userId;
        var username = req.session.username || 'unknown';
        req.session.destroy(function() {
            logSecurityEvent({
                event_type: 'FORCE_LOGOUT',
                user_id: userId,
                username: username,
                ip: req.ip,
                req: req,
                details: { reason: 'Inactive for too long' }
            }).catch(function() {});
            res.redirect('/login?msg=session_expired');
        });
        return;
    }

    req.session.lastActive = now;

    // Check if user needs to re-verify (IP changed or off-hours)
    if (req.session.otpVerified) {
        var needsReVerify = false;
        var reason = '';

        // IP address changed since last OTP
        var rawIP = req.headers['cf-connecting-ip'] || req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || req.ip || '127.0.0.1';
        var currentIP = rawIP.split(',')[0].trim().replace('::ffff:', '');

        if (req.session.mfaVerifiedIp && currentIP !== req.session.mfaVerifiedIp) {
            needsReVerify = true;
            reason = 'IP address changed';
        }

        // Off-hours access
        var { isOffHours } = require('../services/policyService');
        var offHours = isOffHours(new Date(), req.session.timezoneOffset || 0);

        if (offHours && !req.session.mfaVerifiedOffHours) {
            needsReVerify = true;
            reason = 'Off-hours access';
        }

        if (needsReVerify) {
            logSecurityEvent({
                event_type: 'STEP_UP_CHALLENGE',
                user_id: req.session.userId,
                username: req.session.username || 'unknown',
                ip: req.ip,
                req: req,
                details: { reason: reason, path: req.originalUrl }
            }).catch(function() {});

            req.session.otpVerified = false;
            req.session.returnTo = req.originalUrl;

            await generateOTP(req.session.userId);
            return req.session.save(function() {
                res.redirect('/otp');
            });
        }
    }

    // Check device fingerprint matches
    var deviceFP = req.headers['x-device-fingerprint'];
    if (deviceFP && req.session.deviceFingerprint && deviceFP !== req.session.deviceFingerprint) {
        logSecurityEvent({
            event_type: 'SESSION_HIJACK_ATTEMPT',
            user_id: req.session.userId,
            username: req.session.username || 'unknown',
            ip: req.ip,
            req: req,
            details: {
                reason: 'Device fingerprint changed',
                expected: req.session.deviceFingerprint,
                received: deviceFP
            }
        }).catch(function() {});
        req.session.destroy(function() {
            res.redirect('/login?msg=session_invalid');
        });
        return;
    }

    // Periodically check database for account status changes
    var lastCheck = req.session.lastSessionCheck || 0;
    if (now - lastCheck > SESSION_CHECK_INTERVAL && req.session.sessionToken) {
        req.session.lastSessionCheck = now;
        try {
            var { data: user } = await supabase
                .from('users')
                .select('status, role, permissions, active_session_token, password_changed_at')
                .eq('id', req.session.userId)
                .single();

            if (user) {
                // Account blocked or suspended
                if (user.status !== 'active' && user.role !== 'SuperAdmin') {
                    await logSecurityEvent({
                        event_type: 'FORCE_LOGOUT',
                        user_id: req.session.userId,
                        username: req.session.username || 'unknown',
                        ip: req.ip,
                        req: req,
                        details: { reason: 'Account status: ' + user.status }
                    }).catch(function() {});
                    return req.session.destroy(function() {
                        res.redirect('/login?msg=account_blocked');
                    });
                }

                // Sync role if changed by admin
                if (user.role !== req.session.role) {
                    req.session.role = user.role;
                }

                // Sync permissions if changed
                var currentPerms = JSON.stringify(req.session.permissions || {});
                var dbPerms = JSON.stringify(user.permissions || {});
                if (currentPerms !== dbPerms) {
                    req.session.permissions = user.permissions || {};
                }

                // Logged in from another device - kick this session
                if (user.active_session_token && user.active_session_token !== req.session.sessionToken) {
                    await logSecurityEvent({
                        event_type: 'FORCE_LOGOUT',
                        user_id: req.session.userId,
                        username: req.session.username || 'unknown',
                        ip: req.ip,
                        req: req,
                        details: { reason: 'Logged in from another device' }
                    }).catch(function() {});

                    return req.session.destroy(function() {
                        res.redirect('/login?msg=session_invalid');
                    });
                }

                // Password expired (90 days)
                if (user.password_changed_at) {
                    var lastChanged = new Date(user.password_changed_at).getTime();
                    var ninetyDays = 90 * 24 * 60 * 60 * 1000;
                    if (Date.now() - lastChanged > ninetyDays) {
                        req.session.passwordExpired = true;
                    }
                }
            }
        } catch (err) {
            // Database check failed - not critical, skip
        }
    }

    // Force password change if expired
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
                message: 'Your password has expired. Please change it in your profile.'
            });
        }
        return res.redirect('/profile?msg=password_expired');
    }

    // Must complete OTP before accessing other pages
    if (req.path !== '/otp' && req.path !== '/verify-otp' && !req.session.otpVerified) {
        return res.redirect('/otp');
    }

    next();
}

module.exports = { requireLogin: requireLogin };
