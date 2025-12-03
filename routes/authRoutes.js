// routes/authRoutes.js
// handles login, OTP, logout, and device approval check

var express = require('express');
var bcrypt = require('bcryptjs');
var UAParser = require('ua-parser-js');
var { supabase } = require('../db');
var { generateOTP, verifyOTP, sendLoginAlertEmail } = require('../services/otpService'); // Note: Actually needs to come from emailService
var { sendLoginAlertEmail } = require('../services/emailService');
var { calculateRisk } = require('../services/riskEngine');
var { registerDevice, findDevice } = require('../services/deviceService');
var { getCountryFromIP, getGeoFromIP, isVPNConnection, checkImpossibleTravel } = require('../services/geoService');
var { logEvent } = require('../services/auditService');
var { logSecurityEvent } = require('../services/monitorService');

var router = express.Router();

// show login page
router.get('/login', function (req, res) {
    var msg = req.query.msg || '';
    res.sendFile('login.html', { root: 'views' });
});

// process login form
router.post('/login', async function (req, res) {
    try {
        var username = (req.body.username || '').trim();
        var password = req.body.password || '';
        var fingerprint = req.body.fingerprint || 'unknown';

        if (!username || !password) {
            return res.json({ success: false, message: 'Please enter username and password.' });
        }

        // find user in database
        var { data: user } = await supabase
            .from('users')
            .select('*')
            .eq('username', username)
            .single();

        if (!user) {
            // unknown user — log generic failed attempt
            logSecurityEvent({ event_type: 'LOGIN_FAILED', username: username, ip: ip || req.ip, details: { reason: 'User not found' } }).catch(function () { });
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
        if (user.failed_attempts >= 5) {
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
                ip: req.ip,
                risk_score: newAttempts * 10,
                details: { reason: 'Wrong password', attempt: newAttempts, role: user.role }
            });
            return res.json({ success: false, message: 'Invalid username or password.' });
        }

        // password is correct, gather device and geo info
        var parser = new UAParser(req.headers['user-agent']);
        var browserInfo = parser.getBrowser();
        var osInfo = parser.getOS();

        // get real visitor IP (X-Forwarded-For from Nginx, strip ::ffff: prefix)
        var rawIp = req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || req.ip || '127.0.0.1';
        var ip = rawIp.split(',')[0].trim().replace('::ffff:', '');

        // get real location from IP (async, uses ip-api.com on VPS)
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
        // SuperAdmin devices are auto-approved so they can always login
        var autoApproveRoles = ['SuperAdmin'];
        var needsApproval = autoApproveRoles.indexOf(user.role) === -1;

        if (deviceResult.isNew && needsApproval) {
            // new device for regular user, needs admin approval
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
            // auto-approve for SuperAdmin
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

        // check for location anomaly
        var isNewCountry = false;
        var isImpossibleTravel = false;
        
        // get recent successful logins for this user to compare location
        var { data: recentLogins } = await supabase
            .from('sessions_log')
            .select('country, login_at')
            .eq('user_id', user.id)
            .order('login_at', { ascending: false })
            .limit(10);
            
        if (recentLogins && recentLogins.length > 0) {
            // check if the country has ever been seen before
            isNewCountry = !recentLogins.some(function(log) { return log.country === country; });
            
            // check impossible travel against the very last successful login
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
                
                // Do not permanently suspend the device or hard-block the login here.
                // The dynamic Risk Engine will evaluate this anomaly and Conditional Access
                // will block the session later if the risk score crosses the threshold.
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
            role: user.role
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

        // generate OTP
        var otpCode = await generateOTP(user.id);

        // save to session (not fully logged in until OTP verified)
        req.session.userId = user.id;
        req.session.username = user.username;
        req.session.role = user.role;
        req.session.department = user.department;
        req.session.otpVerified = false;
        req.session.riskScore = risk.score;
        req.session.riskLevel = risk.level;
        req.session.riskFactors = risk.factors;
        req.session.loginIP = ip;
        req.session.loginCountry = country;
        req.session.lastActive = Date.now();
        req.session.deviceFingerprint = fingerprint;

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

        await logEvent(user.id, 'LOGIN_PASSWORD_OK', 'Password verified, OTP sent. Risk: ' + risk.level + ' (' + risk.score + ')', ip);
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
            otpCode: otpCode,
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

// verify OTP
router.post('/verify-otp', async function (req, res) {
    try {
        var code = (req.body.code || '').trim();
        var userId = req.session.userId;

        if (!userId) {
            return res.json({ success: false, message: 'Session expired. Please login again.' });
        }

        var result = await verifyOTP(userId, code);

        if (!result.valid) {
            await logEvent(userId, 'OTP_FAILED', result.reason, req.ip);
            await logSecurityEvent({
                event_type: 'OTP_FAILED',
                user_id: userId,
                username: req.session.username || 'unknown',
                ip: req.ip,
                risk_score: req.session.riskScore || 0,
                details: { reason: result.reason }
            });
            return res.json({ success: false, message: result.reason });
        }

        // OTP verified — mark session as fully authenticated
        req.session.otpVerified = true;
        req.session.lastActive = Date.now();

        await logEvent(userId, 'LOGIN_SUCCESS', 'Logged in. Risk: ' + req.session.riskLevel + ' (' + req.session.riskScore + ')', req.ip);
        await logSecurityEvent({
            event_type: 'LOGIN_SUCCESS',
            user_id: userId,
            username: req.session.username || 'unknown',
            ip: req.session.loginIP || req.ip,
            location: req.session.loginCountry || '',
            risk_score: req.session.riskScore || 0,
            details: { risk_level: req.session.riskLevel, role: req.session.role, department: req.session.department }
        });
        await logSecurityEvent({
            event_type: 'OTP_SUCCESS',
            user_id: userId,
            username: req.session.username || 'unknown',
            ip: req.ip,
            risk_score: req.session.riskScore || 0,
            details: { role: req.session.role }
        });

        // Send login alert email
        sendLoginAlertEmail(
            req.session.username || 'unknown', 
            req.session.loginIP || req.ip, 
            req.session.loginCountry || 'Unknown'
        ).catch(err => console.error('Failed to send alert email', err));

        // save session to store BEFORE responding so the cookie is valid
        // when the browser immediately navigates to /dashboard
        req.session.save(function (err) {
            if (err) console.error('Session save error:', err);
            return res.json({ success: true, redirect: '/dashboard' });
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
        }
    });
});

// logout
router.get('/logout', async function (req, res) {
    if (req.session.userId) {
        await logEvent(req.session.userId, 'LOGOUT', 'User logged out', req.ip);
    }
    req.session.destroy(function () {
        res.redirect('/login');
    });
});

module.exports = router;
