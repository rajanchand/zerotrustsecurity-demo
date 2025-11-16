// routes/authRoutes.js
// handles login, OTP, logout, and device approval check

var express = require('express');
var bcrypt = require('bcryptjs');
var UAParser = require('ua-parser-js');
var { supabase } = require('../db');
var { generateOTP, verifyOTP } = require('../services/otpService');
var { calculateRisk } = require('../services/riskEngine');
var { registerDevice, findDevice } = require('../services/deviceService');
var { getCountryFromIP, getGeoFromIP, isVPNConnection } = require('../services/geoService');
var { logEvent } = require('../services/auditService');

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
        }

        if (!deviceResult.device.approved && needsApproval) {
            await logEvent(user.id, 'DEVICE_PENDING', 'Login blocked - device not approved', ip);
            return res.json({
                success: false,
                message: 'Your device is pending approval. Please contact your administrator.',
                devicePending: true
            });
        }

        // calculate risk score
        var risk = await calculateRisk({
            userId: user.id,
            isNewDevice: false,
            isNewCountry: false,
            failedAttempts: user.failed_attempts || 0,
            isVPN: vpn,
            isAdminUnknownIP: false,
            role: user.role
        });

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
            return res.json({ success: false, message: result.reason });
        }

        // OTP verified, fully logged in
        req.session.otpVerified = true;
        req.session.lastActive = Date.now();

        await logEvent(userId, 'LOGIN_SUCCESS', 'Logged in. Risk: ' + req.session.riskLevel + ' (' + req.session.riskScore + ')', req.ip);

        return res.json({ success: true, redirect: '/dashboard' });

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
