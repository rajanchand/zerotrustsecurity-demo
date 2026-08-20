var express = require('express');
var bcrypt = require('bcryptjs');
var crypto = require('crypto');
var UAParser = require('ua-parser-js');

var { supabase } = require('../db');
var { generateOTP, verifyOTP } = require('../services/otpService');
var { sendLoginAlertEmail, sendAnomalyAlertEmail } = require('../services/emailService');
var { calculateRisk } = require('../services/riskEngine');
var { registerDevice, approveDevice } = require('../services/deviceService');
var { getGeoFromIP, isVPNConnection, checkImpossibleTravel } = require('../services/geoService');
var { logEvent } = require('../services/auditService');
var { logSecurityEvent } = require('../services/monitorService');
var { generateCSRFToken } = require('../middleware/csrf');
var { loginLimiter, otpLimiter } = require('../middleware/rateLimiter');
var metrics = require('../services/metricservice');
var { sendSlackAlert } = require('../services/slackService');
var { classifyNetwork } = require('../services/networkTrustService');
var { isOffHours } = require('../services/policyService');

var router = express.Router();

// All devices require explicit approval in a Zero Trust model

// get the real client ip, centralized in ipService
var { getClientIP } = require('../services/ipService');

// show login page
router.get('/login', loginLimiter, function(req, res) {
    res.sendFile('login.html', { root: 'views' });
});

// handle login form submission
router.post('/api/login', loginLimiter, async function(req, res) {
    try {
        var username = (req.body.username || '').trim();
        var password = req.body.password || '';
        var fingerprint = req.body.fingerprint || 'unknown-device';

        if (!username || !password) {
            return res.json({ success: false, message: 'Username and password are required.' });
        }

        var clientIP = getClientIP(req);

        // check if this ip is blocked
        try {
            var { data: networkRule } = await supabase
                .from('ip_rules')
                .select('action, reason')
                .eq('ip_address', clientIP)
                .eq('action', 'block')
                .single();

            if (networkRule) {
                await logSecurityEvent({
                    event_type: 'IP_BLOCKED',
                    username: username,
                    ip: clientIP,
                    req: req,
                    details: { reason: networkRule.reason || 'Blocked IP', action: 'authentication_rejection' }
                });
                return res.json({ success: false, message: 'Access denied from this IP address.' });
            }
        } catch (err) {
            // no block rule found, thats fine
        }

        // look up the user
        var { data: user } = await supabase
            .from('users')
            .select('*')
            .eq('username', username)
            .single();

        if (!user) {
            logSecurityEvent({
                event_type: 'LOGIN_FAILED',
                username: username,
                ip: clientIP,
                req: req,
                details: { reason: 'User not found' }
            }).catch(function() {});
            return res.json({ success: false, message: 'Wrong username or password.' });
        }

        // blocked accounts cant log in (except superadmin)
        if (user.status === 'blocked' && user.role !== 'SuperAdmin') {
            await logEvent(user.id, 'LOGIN_BLOCKED', 'Blocked user tried to log in', clientIP, req.correlationId);
            return res.json({ success: false, message: 'Your account is blocked. Please contact admin.' });
        }

        if (user.status === 'suspended' && user.role !== 'SuperAdmin') {
            await logEvent(user.id, 'LOGIN_SUSPENDED', 'Suspended user tried to log in', clientIP);
            return res.json({ success: false, message: 'Your account is suspended. Please contact admin.' });
        }

        // lockout after 5 failed attempts for 30 mins
        if (user.failed_attempts >= 5 && user.role !== 'SuperAdmin') {
            var lockoutTime = 30 * 60 * 1000;
            var lastFail = user.last_failed_at ? new Date(user.last_failed_at).getTime() : 0;
            if (Date.now() - lastFail < lockoutTime) {
                await logEvent(user.id, 'LOGIN_LOCKED', 'Locked user tried to log in', clientIP);
                return res.json({ success: false, message: 'Too many failed attempts. Try again in 30 minutes.' });
            }
            await supabase.from('users').update({ failed_attempts: 0 }).eq('id', user.id);
            user.failed_attempts = 0;
        }

        // check password
        var passwordOk = await bcrypt.compare(password, user.password_hash);
        if (!passwordOk) {
            var failCount = (user.failed_attempts || 0) + 1;
            await supabase.from('users').update({
                failed_attempts: failCount,
                last_failed_at: new Date().toISOString()
            }).eq('id', user.id);

            await logEvent(user.id, 'LOGIN_FAILED', 'Failed login attempt: ' + failCount, clientIP);
            metrics.loginTotal.inc({ outcome: 'failed' });
            await logSecurityEvent({
                event_type: 'LOGIN_FAILED',
                user_id: user.id,
                username: user.username,
                ip: clientIP,
                risk_score: failCount * 10,
                details: { reason: 'Wrong password', attempt_count: failCount, role: user.role }
            });
            return res.json({ success: false, message: 'Wrong username or password.' });
        }

        // parse browser and os info
        var userAgentParser = new UAParser(req.headers['user-agent']);
        var browserInfo = userAgentParser.getBrowser();
        var osInfo = userAgentParser.getOS();
        var geoData = await getGeoFromIP(clientIP);
        var country = geoData.country || 'Distributed Region';
        var isVPN = isVPNConnection(clientIP) || geoData.isProxy;

        // register the device
        var deviceResult = await registerDevice(user.id, {
            fingerprint: fingerprint,
            browser: (browserInfo.name || 'Unknown') + ' ' + (browserInfo.version || ''),
            os: (osInfo.name || 'Unknown') + ' ' + (osInfo.version || ''),
            ip: clientIP,
            country: country
        });

        // SuperAdmin auto-approval: automatically approve the device in the database
        if (user.role === 'SuperAdmin' && (!deviceResult.device || !deviceResult.device.approved)) {
            await supabase.from('devices').update({ approved: true, trust_level: 'Managed', approved_by: user.id }).eq('user_id', user.id);
            if (deviceResult.device) {
                deviceResult.device.approved = true;
                deviceResult.device.trust_level = 'Managed';
            }
        }

        var needsApproval = user.role !== 'SuperAdmin'; // Zero Trust: All devices require approval (except SuperAdmin)

        // new device needs admin approval
        if (deviceResult.isNew && needsApproval) {
            await logEvent(user.id, 'DEVICE_NEW', 'New device found, waiting for approval', clientIP);
            await logSecurityEvent({
                event_type: 'DEVICE_NEW',
                user_id: user.id,
                username: user.username,
                ip: clientIP,
                location: country,
                device_id: deviceResult.device ? deviceResult.device.id : null,
                details: { agent: req.headers['user-agent'], awaiting_approval: true, role: user.role }
            });
            sendAnomalyAlertEmail(user.username, clientIP, country, 'New device detected').catch(function() {});
            return res.json({
                success: false,
                message: 'New device detected. Waiting for admin approval.',
                devicePending: true
            });
        }


        // existing device still waiting for approval
        if (!deviceResult.isNew && needsApproval && !deviceResult.device.approved) {
            await logEvent(user.id, 'DEVICE_PENDING', 'Login blocked: device not approved', clientIP);
            return res.json({
                success: false,
                message: 'Your device is still waiting for approval.',
                devicePending: true
            });
        }

        // check if login is outside working hours
        var isOffHoursLogin = isOffHours(new Date());

        // check department-specific rules
        if (user.department) {
            try {
                var { data: departmentContext } = await supabase
                    .from('departments')
                    .select('allowed_countries, work_hours_start, work_hours_end, timezone')
                    .eq('name', user.department)
                    .single();

                if (departmentContext) {
                    // department-specific working hours
                    if (departmentContext.work_hours_start !== undefined && departmentContext.work_hours_end !== undefined) {
                        var deptTimezone = departmentContext.timezone || 'UTC';
                        var timeFormatter = new Intl.DateTimeFormat('en-US', { timeZone: deptTimezone, hour: 'numeric', hour12: false });
                        var departmentalHour = parseInt(timeFormatter.format(new Date()), 10);
                        isOffHoursLogin = departmentalHour < departmentContext.work_hours_start || departmentalHour >= departmentContext.work_hours_end;
                    }

                    // geo-fencing: only allow login from certain countries (SuperAdmin always allowed)
                    if (departmentContext.allowed_countries && user.role !== 'SuperAdmin') {
                        var allowedCountries = departmentContext.allowed_countries.split(',').map(function(c) { return c.trim().toLowerCase(); });
                        if (allowedCountries.length > 0 && !allowedCountries.includes(country.toLowerCase())) {
                            await logEvent(user.id, 'GEO_FENCE_VIOLATION', 'Country not allowed: ' + country, clientIP);
                            await logSecurityEvent({
                                event_type: 'GEO_FENCE_VIOLATION',
                                user_id: user.id, username: user.username, ip: clientIP, location: country, risk_score: 100,
                                req: req,
                                details: { reason: 'Country not allowed', authorized: departmentContext.allowed_countries, role: user.role }
                            });
                            return res.json({ success: false, message: 'Access denied from this country.' });
                        }
                    }
                }
            } catch (err) { }
        }

        // check login history for suspicious patterns
        var isKnownCountry = true;
        var impossibleTravel = false;

        var { data: recentSessions } = await supabase
            .from('sessions_log')
            .select('country, login_at')
            .eq('user_id', user.id)
            .order('login_at', { ascending: false })
            .limit(10);

        if (recentSessions && recentSessions.length > 0) {
            isKnownCountry = recentSessions.some(function(auth) { return auth.country === country; });

            var lastSession = recentSessions[0];
            var minutesSinceLast = (new Date() - new Date(lastSession.login_at)) / (1000 * 60);
            impossibleTravel = checkImpossibleTravel(country, lastSession.country, minutesSinceLast);

            if (!isKnownCountry || impossibleTravel) {
                var reason = impossibleTravel ? 'Login from different country too quickly' : 'New login location';

                await logEvent(user.id, 'LOCATION_ALERT', reason + ': ' + country, clientIP);
                await logSecurityEvent({
                    event_type: 'LOCATION_ALERT',
                    user_id: user.id,
                    username: user.username,
                    ip: clientIP,
                    location: country,
                    risk_score: 100,
                    details: { reason: reason, previous_country: lastSession.country, role: user.role }
                });
                sendAnomalyAlertEmail(user.username, clientIP, country, reason).catch(function() {});
            }
        }

        // classify the network trust level
        var networkTrust = await classifyNetwork(user.id, clientIP, country, isVPN);

        // calculate overall risk score
        var riskResult = await calculateRisk({
            userId: user.id,
            username: user.username,
            ip: clientIP,
            country: country,
            location: country,
            isNewDevice: deviceResult.isNew,
            isNewCountry: !isKnownCountry,
            failedAttempts: user.failed_attempts || 0,
            isVPN: isVPN,
            isAdminUnknownIP: false,
            role: user.role,
            isUnusualHours: isOffHoursLogin,
            networkTrustModifier: networkTrust.riskModifier
        });

        // log vpn usage
        if (isVPN) {
            await logSecurityEvent({
                event_type: 'VPN_DETECTED',
                user_id: user.id,
                username: user.username,
                ip: clientIP,
                location: country,
                risk_score: riskResult.score,
                details: { role: user.role, classification: riskResult.level }
            });
            metrics.vpnDetected.inc();

            if (!isKnownCountry || impossibleTravel) {
                var previousCountry = (recentSessions && recentSessions.length > 0) ? recentSessions[0].country : 'Unknown';
                sendSlackAlert({
                    type: 'VPN_ALERT',
                    username: user.username,
                    role: user.role,
                    ip: clientIP,
                    country: country,
                    riskScore: riskResult.score,
                    riskLevel: riskResult.level,
                    previousCountry: previousCountry,
                    device: (browserInfo.name || 'Unknown') + ' ' + (browserInfo.version || '') + ' on ' + (osInfo.name || 'Unknown') + ' ' + (osInfo.version || ''),
                    loginReasons: '[VPN] [Country change: ' + previousCountry + ' -> ' + country + ']',
                    reason: 'VPN from new country: ' + previousCountry + ' -> ' + country
                }).catch(function() {});
            }
        }

        // country change or impossible travel without VPN
        if (!isVPN && (!isKnownCountry || impossibleTravel)) {
            var prevCountry = (recentSessions && recentSessions.length > 0) ? recentSessions[0].country : 'Unknown';
            sendSlackAlert({
                type: 'COUNTRY_CHANGE',
                username: user.username,
                role: user.role,
                ip: clientIP,
                country: country,
                riskScore: riskResult.score,
                riskLevel: riskResult.level,
                device: (browserInfo.name || 'Unknown') + ' ' + (browserInfo.version || '') + ' on ' + (osInfo.name || 'Unknown') + ' ' + (osInfo.version || ''),
                loginReasons: '[Country change: ' + prevCountry + ' → ' + country + ']' +
                    (impossibleTravel ? ' [Impossible travel]' : ''),
                reason: 'Suspicious country change: ' + prevCountry + ' → ' + country
            }).catch(function() {});
        }

        // alert on any high-risk login
        if (riskResult.level === 'High') {
            sendSlackAlert({
                type: 'HIGH_RISK',
                username: user.username,
                role: user.role,
                ip: clientIP,
                country: country,
                riskScore: riskResult.score,
                riskLevel: riskResult.level,
                device: (browserInfo.name || 'Unknown') + ' ' + (browserInfo.version || '') + ' on ' + (osInfo.name || 'Unknown') + ' ' + (osInfo.version || ''),
                loginReasons: riskResult.factors.map(function(f) { return f.factor; }).join(', '),
                reason: 'High risk login detected (score: ' + riskResult.score + ')'
            }).catch(function() {});
        }

        // auto-block if risk is too high (except superadmin)
        if (riskResult.score >= 100 && user.role !== 'SuperAdmin') {
            await supabase.from('users').update({ status: 'blocked' }).eq('id', user.id);
            await logEvent(user.id, 'AUTO_BLOCK', 'Auto-blocked: risk score too high: ' + riskResult.score, clientIP);
            await logSecurityEvent({
                event_type: 'LOGIN_BLOCKED',
                user_id: user.id, username: user.username, ip: clientIP, location: country, risk_score: riskResult.score,
                details: { reason: 'Auto-blocked (high risk)', role: user.role }
            });
            return res.json({ success: false, message: 'Your account has been blocked due to high risk. Contact admin.' });
        }

        // password was correct, reset fail counter
        await supabase.from('users').update({ failed_attempts: 0 }).eq('id', user.id);

        // create a session token so we can track concurrent logins
        var logicSessionToken = crypto.randomUUID();
        await supabase.from('users').update({ active_session_token: logicSessionToken }).eq('id', user.id);

        // store everything in the session
        await new Promise(function(resolve, reject) {
            req.session.regenerate(function(err) {
                if (err) reject(err);
                else resolve();
            });
        });

        req.session.userId = user.id;
        req.session.username = user.username;
        req.session.role = user.role;
        req.session.department = user.department;
        req.session.permissions = user.permissions || {};
        req.session.riskScore = riskResult.score;
        req.session.riskLevel = riskResult.level;
        req.session.riskFactors = riskResult.factors;
        req.session.loginIP = clientIP;
        req.session.loginCountry = country;
        req.session.lastActive = Date.now();
        req.session.deviceFingerprint = fingerprint;
        req.session.sessionToken = logicSessionToken;
        req.session.vpn = isVPN;
        req.session.isUnusualHours = isOffHoursLogin;
        req.session.networkTrust = networkTrust;

        var deviceLabel = ((browserInfo.name || 'Unknown') + ' ' + (browserInfo.version || '') + ' on ' + (osInfo.name || 'Unknown') + ' ' + (osInfo.version || '')).trim();
        req.session.deviceLabel = deviceLabel;

        // build login context flags
        var flags = [];
        flags.push(networkTrust.label);
        if (isVPN && networkTrust.tier !== 'ANONYMIZED') flags.push('[VPN]');
        if (isOffHoursLogin) flags.push('[Off-hours]');
        if (deviceResult.isNew) flags.push('[New device]');
        if (!isKnownCountry) flags.push('[New country]');
        if (impossibleTravel) flags.push('[Impossible travel]');
        if (flags.length <= 1) flags.push('[Normal]');

        var loginFlags = flags.join(' · ');
        req.session.loginReasons = loginFlags;

        // save session to the sessions_log table
        var sessionRecord = {
            user_id: user.id,
            ip: clientIP,
            user_agent: req.headers['user-agent'],
            browser: browserInfo.name || 'Unknown',
            os: osInfo.name || 'Unknown',
            device_fingerprint: fingerprint,
            country: country,
            risk_score: riskResult.score,
            vpn: !!isVPN
        };

        try {
            await supabase.from('sessions_log').insert(sessionRecord);
        } catch (err) {
            delete sessionRecord.vpn;
            await supabase.from('sessions_log').insert(sessionRecord);
        }

        // otp is always required, no bypass
        req.session.otpVerified = false;
        req.session.offHoursLogin = isOffHoursLogin;
        var otpCode = await generateOTP(user.id);
        req.session.currentOtp = otpCode;
        metrics.otpSent.inc();

        await logEvent(user.id, 'LOGIN_PASSWORD_OK', 'Password OK, OTP required (Risk: ' + riskResult.level + ')', clientIP);
        await logSecurityEvent({
            event_type: 'OTP_SENT',
            user_id: user.id,
            username: user.username,
            ip: clientIP,
            location: country,
            risk_score: riskResult.score,
            details: { factors: riskResult.factors, role: user.role, vpn: isVPN, off_hours: isOffHoursLogin }
        });

        // extra logging and alerts for off-hours logins
        if (isOffHoursLogin) {
            await logSecurityEvent({
                event_type: 'RISK_SCORE_CHANGED',
                user_id: user.id,
                username: user.username,
                ip: clientIP,
                location: country,
                risk_score: riskResult.score,
                details: { reason: 'Off-hours login', role: user.role }
            });

            sendSlackAlert({
                type: 'OFF_HOURS_ALERT',
                username: user.username,
                role: user.role,
                ip: clientIP,
                country: country,
                riskScore: riskResult.score,
                riskLevel: riskResult.level,
                device: deviceLabel,
                loginReasons: loginFlags,
                reason: 'Off-hours login'
            }).catch(function() {});
        }

        return req.session.save(function(err) {
            if (err) console.error('[Auth] Session save error:', err);
            return res.json({
                success: true,
                risk: { score: riskResult.score, level: riskResult.level, factors: riskResult.factors },
                offHours: isOffHoursLogin,
                vpn: isVPN,
                redirect: '/otp'
            });
        });

    } catch (err) {
        console.error('[Auth] Error:', err);
        return res.json({ success: false, message: 'Something went wrong. Try again.' });
    }
});

// show otp page
router.get('/otp', otpLimiter, function(req, res) {
    if (!req.session.userId) return res.redirect('/login');
    res.sendFile('otp.html', { root: 'views' });
});

// verify otp code
router.post('/api/verify-otp', otpLimiter, async function(req, res) {
    try {
        var otpCode = String(req.body.code || req.body.otp || '').trim();

        if (!req.session || !req.session.userId) {
            return res.json({ success: false, message: 'Session expired. Please log in again.' });
        }

        var userId = req.session.userId;
        var username = req.session.username || 'unidentified';
        var riskScore = req.session.riskScore || 0;
        var riskLevel = req.session.riskLevel || 'Low';
        var role = req.session.role || 'Standard';
        var loginIP = req.session.loginIP;
        var loginCountry = req.session.loginCountry;

        var verificationResult = await verifyOTP(userId, otpCode);

        if (!verificationResult.valid) {
            await logEvent(userId, 'OTP_FAILED', verificationResult.reason, getClientIP(req));
            await logSecurityEvent({
                event_type: 'OTP_FAILED',
                user_id: userId,
                username: username,
                ip: getClientIP(req),
                risk_score: riskScore,
                details: { failure_reason: verificationResult.reason }
            });
            return res.json({ success: false, message: verificationResult.reason });
        }

        req.session.otpVerified = true;
        req.session.lastActive = Date.now();
        req.session.lastReAuth = Date.now();

        var clientIP = getClientIP(req);

        req.session.mfaVerifiedIp = clientIP;
        req.session.mfaVerifiedOffHours = isOffHours(new Date());

        var csrfToken = generateCSRFToken(req);

        await logEvent(userId, 'LOGIN_SUCCESS', 'OTP verified. Risk: ' + riskLevel, clientIP);
        metrics.loginTotal.inc({ outcome: 'success' });
        metrics.riskScore.set({ user: username }, riskScore || 0);

        await logSecurityEvent({
            event_type: 'LOGIN_SUCCESS',
            user_id: userId,
            username: username,
            ip: loginIP,
            location: loginCountry,
            risk_score: riskScore,
            details: { role: role, status: 'Verified' }
        });

        await logSecurityEvent({
            event_type: 'OTP_SUCCESS',
            user_id: userId,
            username: username,
            ip: clientIP,
            risk_score: riskScore
        });

        sendLoginAlertEmail(username, loginIP || clientIP, loginCountry || 'Unknown').catch(function() {});

        // send slack alert
        try {
            var { data: prevSessions } = await supabase
                .from('sessions_log')
                .select('id')
                .eq('user_id', userId)
                .limit(2);

            var isFirstLogin = !prevSessions || prevSessions.length <= 1;
            sendSlackAlert({
                type: isFirstLogin ? 'FIRST_LOGIN' : 'LOGIN',
                username: username,
                role: role,
                ip: loginIP || clientIP,
                country: loginCountry || 'Unknown',
                riskScore: riskScore,
                riskLevel: riskLevel,
                device: req.session.deviceLabel || 'Unknown device',
                loginReasons: req.session.loginReasons || 'Standard'
            }).catch(function() {});
        } catch (err) {
            sendSlackAlert({ type: 'LOGIN', username: username, role: role, ip: loginIP || clientIP, country: loginCountry || 'Unknown', riskScore: riskScore, riskLevel: riskLevel, device: req.session.deviceLabel || 'Unknown device' }).catch(function() {});
        }

        var redirectTo = req.session.returnTo || '/dashboard';
        delete req.session.returnTo;

        req.session.save(function() {
            return res.json({ success: true, redirect: redirectTo, csrfToken: csrfToken });
        });

    } catch (err) {
        console.error('[Auth] OTP verify error:', err);
        return res.json({ success: false, message: 'Something went wrong. Try again.' });
    }
});

// get current session info
router.get('/api/session', function(req, res) {
    if (!req.session.userId) {
        return res.json({ loggedIn: false });
    }
    res.json({
        loggedIn: !!req.session.otpVerified,
        otpCode: req.session.otpVerified ? undefined : req.session.currentOtp,
        user: {
            id: req.session.userId,
            username: req.session.username,
            role: req.session.role,
            department: req.session.department,
            riskScore: req.session.riskScore || 0,
            riskLevel: req.session.riskLevel || 'Low'
        },
        risk: {
            score: req.session.riskScore || 0,
            level: req.session.riskLevel || 'Low',
            factors: req.session.riskFactors || []
        },
        offHoursLogin: !!req.session.offHoursLogin,
        vpn: !!req.session.vpn,
        loginIP: req.session.loginIP || '',
        loginCountry: req.session.loginCountry || '',
        isUnusualHours: !!req.session.isUnusualHours,
        security: {
            sessionToken: req.session.sessionToken ? 'active' : 'none',
            deviceBound: !!req.session.deviceFingerprint,
            passwordExpired: !!req.session.passwordExpired
        }
    });
});

// logout
router.get('/logout', async function(req, res) {
    try {
        if (req.session && req.session.userId) {
            var userId = req.session.userId;
            var clientIP = getClientIP(req);

            try { await supabase.from('users').update({ active_session_token: null }).eq('id', userId); } catch (err) { }
            try { await logEvent(userId, 'LOGOUT', 'User logged out', clientIP); } catch (err) { }
            try {
                var { data: previousSession } = await supabase
                    .from('sessions_log')
                    .select('id')
                    .eq('user_id', userId)
                    .order('login_at', { ascending: false })
                    .limit(1)
                    .single();

                if (previousSession) {
                    await supabase.from('sessions_log')
                        .update({ logout_at: new Date().toISOString() })
                        .eq('id', previousSession.id);
                }
            } catch (err) { }
        }

        res.clearCookie('connect.sid');

        if (req.session) {
            req.session.destroy(function() {
                res.redirect('/login');
            });
        } else {
            res.redirect('/login');
        }
    } catch (err) {
        console.error('[Logout] Error:', err);
        res.redirect('/login');
    }
});

module.exports = router;
