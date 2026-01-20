// routes/authRoutes.js
// handles login, OTP, logout, and device approval check
// includes: IP blocklist enforcement, rate limiting, concurrent session control

var express = require('express');
var bcrypt = require('bcryptjs');
var crypto = require('crypto');
var UAParser = require('ua-parser-js');
var { supabase } = require('../db');
var { generateOTP, verifyOTP } = require('../services/otpService');
var { sendLoginAlertEmail } = require('../services/emailService');
var { calculateRisk } = require('../services/riskEngine');
var { registerDevice, findDevice } = require('../services/deviceService');
var { getCountryFromIP, getGeoFromIP, isVPNConnection, checkImpossibleTravel } = require('../services/geoService');
var { logEvent } = require('../services/auditService');
var { logSecurityEvent } = require('../services/monitorService');
var { generateCSRFToken } = require('../middleware/csrf');
var { loginLimiter, otpLimiter } = require('../middleware/rateLimiter');

var router = express.Router();

// show login page
router.get('/login', function (req, res) {
    var msg = req.query.msg || '';
    res.sendFile('login.html', { root: 'views' });
});

// process login form — with rate limiting and IP blocklist
router.post('/login', loginLimiter, async function (req, res) {
    try {
        var username = (req.body.username || '').trim();
        var password = req.body.password || '';
        var fingerprint = req.body.fingerprint || 'unknown';

        if (!username || !password) {
            return res.json({ success: false, message: 'Please enter username and password.' });
        }

        // get real visitor IP
        var rawIp = req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || req.ip || '127.0.0.1';
        var ip = rawIp.split(',')[0].trim().replace('::ffff:', '');

        // IP BLOCKLIST ENFORCEMENT: check ip_rules table
        try {
            // TIME-BASED ACCESS CONTROL (Allow 6:00 AM - 10:00 PM Server Time)
            var currentHour = new Date().getHours();
            var ALLOW_START = 6;
            var ALLOW_END = 22;

            if (currentHour < ALLOW_START || currentHour >= ALLOW_END) {
                return res.json({ 
                    success: false, 
                    message: 'Access denied: Remote work access restricted during off-hours (10:00 PM to 6:00 AM).' 
                });
            }
            var { data: ipRule } = await supabase
                .from('ip_rules')
                .select('action, reason')
                .eq('ip_address', ip)
                .eq('action', 'block')
                .single();

            if (ipRule) {
                await logSecurityEvent({
                    event_type: 'IP_BLOCKED',
                    username: username,
                    ip: ip,
                    details: { reason: ipRule.reason || 'IP is in block list', action: 'login_rejected' }
                });
                return res.json({ success: false, message: 'Access denied from your IP address.' });
            }
        } catch (e) {
            // no blocking rule found — continue
        }

        // find user in database
        var { data: user } = await supabase
            .from('users')
            .select('*')
            .eq('username', username)
            .single();

        if (!user) {
            logSecurityEvent({ event_type: 'LOGIN_FAILED', username: username, ip: ip, details: { reason: 'User not found' } }).catch(function () { });
            return res.json({ success: false, message: 'Invalid username or password.' });
        }

        // check if user is blocked or suspended
        if (user.status === 'blocked') {
            await logEvent(user.id, 'LOGIN_BLOCKED', 'Blocked user tried to login', req.ip);
            return res.json({ success: false, message: 'Your account has been blocked. Contact your administrator.' });
        }

        if (user.status === 'suspended') {
            await logEvent(user.id, 'LOGIN_SUSPENDED', 'Suspended user tried to login', req.ip);
            return res.json({ success: false, message: 'Your account has been suspended. Contact your administrator.' });
        }

        // check if account is locked (5 failed attempts)
        if (user.failed_attempts >= 5 && user.role !== 'SuperAdmin') {
            await logEvent(user.id, 'LOGIN_LOCKED', 'Locked account login attempt', req.ip);
            return res.json({ success: false, message: 'Account locked after 5 failed attempts. Contact your administrator.' });
        }

        // verify password
        var passwordMatch = bcrypt.compareSync(password, user.password_hash);
        if (!passwordMatch) {
            var newAttempts = (user.failed_attempts || 0) + 1;
            await supabase.from('users').update({
                failed_attempts: newAttempts,
                last_failed_at: new Date().toISOString()
            }).eq('id', user.id);

            await logEvent(user.id, 'LOGIN_FAILED', 'Wrong password (attempt ' + newAttempts + ')', req.ip);
            await logSecurityEvent({
                event_type: 'LOGIN_FAILED',
                user_id: user.id,
                username: user.username,
                ip: ip,
                risk_score: newAttempts * 10,
                details: { reason: 'Wrong password', attempt: newAttempts, role: user.role }
            });
            return res.json({ success: false, message: 'Invalid username or password.' });
        }

        // password is correct, gather device and geo info
        var parser = new UAParser(req.headers['user-agent']);
        var browserInfo = parser.getBrowser();
        var osInfo = parser.getOS();

        // get real location from IP
        var geo = await getGeoFromIP(ip);
        var country = geo.country || 'Unknown';
        var vpn = isVPNConnection(ip) || geo.isProxy;

        // register or find device
        var deviceResult = await registerDevice(user.id, {
            fingerprint: fingerprint,
            browser: (browserInfo.name || 'Unknown') + ' ' + (browserInfo.version || ''),
            os: (osInfo.name || 'Unknown') + ' ' + (osInfo.version || ''),
            ip: ip,
            country: country
        });

        // check if device is approved
        var autoApproveRoles = ['SuperAdmin'];
        var needsApproval = autoApproveRoles.indexOf(user.role) === -1;

        if (deviceResult.isNew && needsApproval) {
            await logEvent(user.id, 'DEVICE_NEW', 'New device registered, pending approval', ip);
            await logSecurityEvent({
                event_type: 'DEVICE_NEW',
                user_id: user.id,
                username: user.username,
                ip: ip,
                location: country,
                device_id: deviceResult.device ? deviceResult.device.id : null,
                details: { browser: req.headers['user-agent'], needs_approval: true, role: user.role }
            });
            return res.json({
                success: false,
                message: 'New device detected. Your device must be approved by an administrator before you can login.',
                devicePending: true
            });
        }

        if (deviceResult.isNew && !needsApproval) {
            var { approveDevice } = require('../services/deviceService');
            await approveDevice(deviceResult.device.id, user.id);
            await logEvent(user.id, 'DEVICE_AUTO_APPROVED', 'Device auto-approved for ' + user.role, ip);
            await logSecurityEvent({
                event_type: 'DEVICE_NEW',
                user_id: user.id,
                username: user.username,
                ip: ip,
                location: country,
                device_id: deviceResult.device ? deviceResult.device.id : null,
                details: { browser: req.headers['user-agent'], auto_approved: true, role: user.role }
            });
        }

        if (!deviceResult.device.approved && needsApproval) {
            await logEvent(user.id, 'DEVICE_PENDING', 'Login blocked - device not approved', ip);
            return res.json({
                success: false,
                message: 'Your device is pending approval. Please contact your administrator.',
                devicePending: true
            });
        }

        // REMOTE WORK: Working Hours  Check
        // Typically, remote workers log in between 6 AM and 10 PM.
        // For the demo, we use the server time (or we could use the timezone offset from fingerprint)
        var currentHour = new Date().getHours();
        var isUnusualHours = currentHour >= 22 || currentHour < 6; // 10 PM to 6 AM

        // REMOTE WORK: Geo-Fencing Check per Department
        var hasGeoFenceViolation = false;
        var allowedCountriesStr = null;

        if (user.department) {
            try {
                var { data: deptInfo } = await supabase
                    .from('departments')
                    .select('allowed_countries')
                    .eq('name', user.department)
                    .single();

                if (deptInfo && deptInfo.allowed_countries) {
                    allowedCountriesStr = deptInfo.allowed_countries;
                    var allowedList = deptInfo.allowed_countries.split(',').map(function (c) { return c.trim().toLowerCase(); });

                    if (allowedList.length > 0 && !allowedList.includes(country.toLowerCase())) {
                        hasGeoFenceViolation = true;

                        await logEvent(user.id, 'GEO_FENCE_VIOLATION', 'Login blocked from ' + country + ' (Department geo-fence)', ip);
                        await logSecurityEvent({
                            event_type: 'GEO_FENCE_VIOLATION',
                            user_id: user.id,
                            username: user.username,
                            ip: ip,
                            location: country,
                            risk_score: 100,
                            details: { reason: 'Country not in department allowed list', allowed: allowedCountriesStr, role: user.role }
                        });

                        // Block outright
                        return res.json({ success: false, message: 'Access denied. Logins from ' + country + ' are not permitted for your department.' });
                    }
                }
            } catch (e) {
                // Ignore if departments table doesn't have the column yet
            }
        }

        // check for location anomaly
        var isNewCountry = false;
        var isImpossibleTravel = false;

        var { data: recentLogins } = await supabase
            .from('sessions_log')
            .select('country, login_at')
            .eq('user_id', user.id)
            .order('login_at', { ascending: false })
            .limit(10);

        if (recentLogins && recentLogins.length > 0) {
            isNewCountry = !recentLogins.some(function (log) { return log.country === country; });

            var lastLogin = recentLogins[0];
            var timeDiffMinutes = (new Date() - new Date(lastLogin.login_at)) / (1000 * 60);
            isImpossibleTravel = checkImpossibleTravel(country, lastLogin.country, timeDiffMinutes);

            if (isNewCountry || isImpossibleTravel) {
                var anomalyReason = isImpossibleTravel ? 'Impossible travel detected' : 'Unrecognized login location';

                await logEvent(user.id, 'LOCATION_ANOMALY', anomalyReason + ' from ' + country, ip);
                await logSecurityEvent({
                    event_type: 'LOCATION_ANOMALY',
                    user_id: user.id,
                    username: user.username,
                    ip: ip,
                    location: country,
                    risk_score: 100,
                    details: { reason: anomalyReason, previous_location: lastLogin.country, role: user.role }
                });
            }
        }

        // calculate risk score
        var risk = await calculateRisk({
            userId: user.id,
            isNewDevice: deviceResult.isNew,
            isNewCountry: isNewCountry,
            failedAttempts: user.failed_attempts || 0,
            isVPN: vpn,
            isAdminUnknownIP: false,
            role: user.role,
            isUnusualHours: isUnusualHours
        });

        // emit VPN detection event
        if (vpn) {
            await logSecurityEvent({
                event_type: 'VPN_DETECTED',
                user_id: user.id,
                username: user.username,
                ip: ip,
                location: country,
                risk_score: risk.score,
                details: { role: user.role, risk_level: risk.level }
            });
        }

        // reset failed attempts
        await supabase.from('users').update({ failed_attempts: 0 }).eq('id', user.id);

        // CONCURRENT SESSION CONTROL: generate unique session token
        var sessionToken = crypto.randomUUID();
        await supabase.from('users').update({ active_session_token: sessionToken }).eq('id', user.id);

        // save to session (common for both paths)
        req.session.userId = user.id;
        req.session.username = user.username;
        req.session.role = user.role;
        req.session.department = user.department;
        req.session.riskScore = risk.score;
        req.session.riskLevel = risk.level;
        req.session.riskFactors = risk.factors;
        req.session.loginIP = ip;
        req.session.loginCountry = country;
        req.session.lastActive = Date.now();
        req.session.deviceFingerprint = fingerprint;
        req.session.sessionToken = sessionToken;

        // log the session
        await supabase.from('sessions_log').insert({
            user_id: user.id,
            ip: ip,
            user_agent: req.headers['user-agent'],
            browser: browserInfo.name || 'Unknown',
            os: osInfo.name || 'Unknown',
            device_fingerprint: fingerprint,
            country: country,
            risk_score: risk.score
        });

        // ADAPTIVE MFA (Risk-Based Authentication)
        if (risk.score === 0) {
            // Context is identical to normal pattern — Risk is 0. Bypass OTP.
            req.session.otpVerified = true;
            var csrfToken = generateCSRFToken(req);

            await logEvent(user.id, 'LOGIN_SUCCESS', 'Logged in (Adaptive MFA: OTP Bypassed). Risk: Low (0)', ip);
            await logSecurityEvent({
                event_type: 'LOGIN_SUCCESS',
                user_id: user.id,
                username: user.username,
                ip: ip,
                location: country,
                risk_score: 0,
                details: { risk_level: 'Low', role: user.role, adaptive_mfa: 'bypassed', department: user.department }
            });

            sendLoginAlertEmail(user.username, ip, country).catch(function (err) { });

            return res.json({
                success: true,
                risk: { score: 0, level: 'Low' },
                redirect: '/dashboard',
                csrfToken: csrfToken
            });
        }

        // Context has changed or introduced risk (Score > 0) — REQUIRE OTP
        req.session.otpVerified = false;
        var otpCode = await generateOTP(user.id);

        await logEvent(user.id, 'LOGIN_PASSWORD_OK', 'Password verified, OTP required. Risk: ' + risk.level + ' (' + risk.score + ')', ip);
        await logSecurityEvent({
            event_type: 'OTP_SENT',
            user_id: user.id,
            username: user.username,
            ip: ip,
            location: country,
            risk_score: risk.score,
            details: { risk_level: risk.level, risk_factors: risk.factors, role: user.role }
        });

        return res.json({
            success: true,
            risk: { score: risk.score, level: risk.level },
            redirect: '/otp'
        });

    } catch (err) {
        console.error('Login error:', err);
        return res.json({ success: false, message: 'Server error. Please try again.' });
    }
});

// show OTP page
router.get('/otp', function (req, res) {
    if (!req.session.userId) return res.redirect('/login');
    res.sendFile('otp.html', { root: 'views' });
});

// verify OTP — with rate limiting
router.post('/verify-otp', otpLimiter, async function (req, res) {
    try {
        var code = (req.body.code || '').trim();
        
        // Cache session variables upfront to prevent race conditions if session is destroyed asynchronously
        if (!req.session || !req.session.userId) {
            return res.json({ success: false, message: 'Session expired. Please login again.' });
        }

        var userId = req.session.userId;
        var username = req.session.username || 'unknown';
        var riskScore = req.session.riskScore || 0;
        var riskLevel = req.session.riskLevel || 'Low';
        var role = req.session.role || 'User';
        var department = req.session.department || '';
        var loginIP = req.session.loginIP || req.ip;
        var loginCountry = req.session.loginCountry || 'Unknown';

        var result = await verifyOTP(userId, code);

        if (!result.valid) {
            await logEvent(userId, 'OTP_FAILED', result.reason, req.ip);
            await logSecurityEvent({
                event_type: 'OTP_FAILED',
                user_id: userId,
                username: username,
                ip: req.ip,
                risk_score: riskScore,
                details: { reason: result.reason }
            });
            return res.json({ success: false, message: result.reason });
        }

        // Check if session was asynchronously destroyed by requireLogin
        if (!req.session) {
            return res.json({ success: false, message: 'Session invalidated during verification due to concurrent login. Please login again.' });
        }

        // OTP verified — mark session as fully authenticated
        req.session.otpVerified = true;
        req.session.lastActive = Date.now();

        // generate CSRF token for this session
        var csrfToken = generateCSRFToken(req);

        await logEvent(userId, 'LOGIN_SUCCESS', 'Logged in. Risk: ' + riskLevel + ' (' + riskScore + ')', req.ip);
        await logSecurityEvent({
            event_type: 'LOGIN_SUCCESS',
            user_id: userId,
            username: username,
            ip: loginIP,
            location: loginCountry,
            risk_score: riskScore,
            details: { risk_level: riskLevel, role: role, department: department }
        });
        
        await logSecurityEvent({
            event_type: 'OTP_SUCCESS',
            user_id: userId,
            username: username,
            ip: req.ip,
            risk_score: riskScore,
            details: { role: role }
        });

        // Send login alert email
        sendLoginAlertEmail(username, loginIP, loginCountry).catch(function (err) { console.error('Failed to send alert email', err); });

        req.session.save(function (err) {
            if (err) console.error('Session save error:', err);
            return res.json({ success: true, redirect: '/dashboard', csrfToken: csrfToken });
        });

    } catch (err) {
        console.error('OTP error:', err);
        return res.json({ success: false, message: 'Server error. Please try again.' });
    }
});

// session info API
router.get('/api/session', function (req, res) {
    if (!req.session.userId || !req.session.otpVerified) {
        return res.json({ loggedIn: false });
    }
    res.json({
        loggedIn: true,
        user: {
            id: req.session.userId,
            username: req.session.username,
            role: req.session.role,
            department: req.session.department
        },
        risk: {
            score: req.session.riskScore,
            level: req.session.riskLevel
        },
        security: {
            sessionToken: req.session.sessionToken ? 'active' : 'none',
            deviceBound: !!req.session.deviceFingerprint,
            passwordExpired: !!req.session.passwordExpired
        }
    });
});

// logout
router.get('/logout', async function (req, res) {
    try {
        if (req.session && req.session.userId) {
            const userId = req.session.userId;
            // clear active session token on logout
            await supabase.from('users').update({ active_session_token: null }).eq('id', userId).catch(function () { });
            await logEvent(userId, 'LOGOUT', 'User logged out', req.ip).catch(function () { });
        }
        
        res.clearCookie('connect.sid');

        if (req.session) {
            req.session.destroy(function () {
                res.redirect('/login');
            });
        } else {
            res.redirect('/login');
        }
    } catch (err) {
        console.error('Logout exception:', err);
        res.redirect('/login');
    }
});

module.exports = router;
