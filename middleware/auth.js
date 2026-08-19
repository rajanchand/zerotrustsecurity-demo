var { logSecurityEvent } = require('../services/monitorService');
var { supabase } = require('../db');
var { generateOTP } = require('../services/otpService');
var { getClientIP } = require('../services/ipService');

// pages that dont need login
var PUBLIC_PATHS = [
    '/login', '/logout', '/otp', '/verify-otp',
    '/api/login', '/api/verify-otp', '/api/session',
    '/css', '/js', '/api/csrf-token', '/favicon.ico', '/manifest.json', '/apple-touch-icon.png'
];

// check user status from db every 10 seconds
var SESSION_CHECK_INTERVAL = 10 * 1000;

// main login check, runs on every request
async function requireLogin(req, res, next) {

    // skip check for public pages
    if (PUBLIC_PATHS.some(function(p) { return req.path === p || req.path.startsWith(p + '/'); })) {
        return next();
    }

    // not logged in, send to login
    if (!req.session || !req.session.userId) {
        return res.redirect('/login');
    }





    // high risk users go to security block page
    if (req.session.highRisk && req.path !== '/security-block' && req.path !== '/logout') {
        return res.redirect('/security-block');
    }

    // timeout after 15 mins of no activity
    var now = Date.now();
    var lastActive = req.session.lastActive || now;
    var TIMEOUT = 15 * 60 * 1000;

    if (now - lastActive > TIMEOUT) {
        var userId = req.session.userId;
        var username = req.session.username || 'unknown';
        var userIP = getClientIP(req);
        
        logSecurityEvent({
            event_type: 'FORCE_LOGOUT',
            user_id: userId,
            username: username,
            ip: userIP,
            req: req,
            details: { reason: 'Inactive for too long' }
        }).catch(function() {});

        res.clearCookie('connect.sid');
        return req.session.destroy(function(err) {
            if (err) console.error('[Session] Failed to destroy expired session:', err);
            res.redirect('/login?msg=session_expired');
        });
    }

    req.session.lastActive = now;

    // if user already verified otp, check if they need to reverify
    if (req.session.otpVerified) {
        var needsReVerify = false;
        var reason = '';

        // get client ip
        var currentIP = getClientIP(req);

        // ip changed since last otp verification
        if (req.session.mfaVerifiedIp && currentIP !== req.session.mfaVerifiedIp) {
            needsReVerify = true;
            reason = 'IP address changed';
        }

        // check if currently off hours
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

            var otpCode = await generateOTP(req.session.userId);
            req.session.currentOtp = otpCode;
            return req.session.save(function() {
                res.redirect('/otp');
            });
        }
    }

    // device fingerprint check
    // Only check on POST/PUT/DELETE requests where JS can attach custom headers.
    // Browsers do NOT send custom headers on page navigations (GET), so checking
    // on GET would kill the session every time the user navigates to a new page.
    // Also skip for OTP paths since the user is still in the authentication flow.
    var isModifyingRequest = !['GET', 'HEAD', 'OPTIONS'].includes(req.method);
    var isOtpPath = req.path === '/otp' || req.path === '/api/verify-otp';
    var deviceFP = req.headers['x-device-fingerprint'];
    var expectedFP = req.session.deviceFingerprint;
    
    // If the session is bound to a fingerprint, but the request does not provide one,
    // or if the provided fingerprint does not match, flag it as a hijacking attempt.
    if (isModifyingRequest && !isOtpPath && expectedFP && (!deviceFP || deviceFP !== expectedFP)) {
        logSecurityEvent({
            event_type: 'SESSION_HIJACK_ATTEMPT',
            user_id: req.session.userId,
            username: req.session.username || 'unknown',
            ip: getClientIP(req),
            req: req,
            details: {
                reason: !deviceFP ? 'Missing device fingerprint header' : 'Device fingerprint mismatch',
                expected: expectedFP,
                received: deviceFP || 'none'
            }
        }).catch(function() {});

        res.clearCookie('connect.sid');
        return req.session.destroy(function(err) {
            if (err) console.error('[Session] Fail to destroy on hijack attempt:', err);
            if (req.path.startsWith('/api/')) {
                return res.status(401).json({ success: false, sessionInvalid: true, message: 'Your session was ended. Please sign in again.' });
            }
            res.redirect('/login?msg=session_invalid');
        });
    }

    // periodically check db for account status changes
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
                // account blocked or suspended
                if (user.status !== 'active' && user.role !== 'SuperAdmin') {
                    logSecurityEvent({
                        event_type: 'FORCE_LOGOUT',
                        user_id: req.session.userId,
                        username: req.session.username || 'unknown',
                        ip: getClientIP(req),
                        req: req,
                        details: { reason: 'Account status: ' + user.status }
                    }).catch(function() {});

                    res.clearCookie('connect.sid');
                    return req.session.destroy(function(err) {
                        if (err) console.error('[Session] Fail to destroy blocked user session:', err);
                        res.redirect('/login?msg=account_blocked');
                    });
                }

                // sync role if admin changed it
                if (user.role !== req.session.role) {
                    req.session.role = user.role;
                }

                // sync permissions if changed
                var currentPerms = JSON.stringify(req.session.permissions || {});
                var dbPerms = JSON.stringify(user.permissions || {});
                if (currentPerms !== dbPerms) {
                    req.session.permissions = user.permissions || {};
                }

                // kick session if user logged in from another device
                if (user.active_session_token && user.active_session_token !== req.session.sessionToken) {
                    logSecurityEvent({
                        event_type: 'FORCE_LOGOUT',
                        user_id: req.session.userId,
                        username: req.session.username || 'unknown',
                        ip: getClientIP(req),
                        req: req,
                        details: { reason: 'Logged in from another device' }
                    }).catch(function() {});

                    res.clearCookie('connect.sid');
                    return req.session.destroy(function(err) {
                        if (err) console.error('[Session] Fail to destroy concurrent session:', err);
                        res.redirect('/login?msg=session_invalid');
                    });
                }

                // password expired after 90 days
                if (user.password_changed_at) {
                    var lastChanged = new Date(user.password_changed_at).getTime();
                    var ninetyDays = 90 * 24 * 60 * 60 * 1000;
                    if (Date.now() - lastChanged > ninetyDays) {
                        req.session.passwordExpired = true;
                    }
                }
            }
        } catch (err) {
            // db check failed, not critical so just skip
        }
    }

    // force password change if expired
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

    // must finish otp before accessing other pages
    if (req.path !== '/otp' && req.path !== '/verify-otp' && !req.session.otpVerified) {
        return res.redirect('/otp');
    }

    next();
}

module.exports = { requireLogin: requireLogin };
