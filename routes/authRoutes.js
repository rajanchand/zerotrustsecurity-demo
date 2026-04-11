const express = require('express');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const UAParser = require('ua-parser-js');

const { supabase } = require('../db');
const { generateOTP, verifyOTP } = require('../services/otpService');
const { sendLoginAlertEmail, sendAnomalyAlertEmail } = require('../services/emailService');
const { calculateRisk } = require('../services/riskEngine');
const { registerDevice, approveDevice } = require('../services/deviceService');
const { getGeoFromIP, isVPNConnection, checkImpossibleTravel } = require('../services/geoService');
const { logEvent } = require('../services/auditService');
const { logSecurityEvent } = require('../services/monitorService');
const { generateCSRFToken } = require('../middleware/csrf');
const { loginLimiter, otpLimiter } = require('../middleware/rateLimiter');
const metrics = require('../services/metricservice');
const { sendSlackAlert } = require('../services/slackService');
const { classifyNetwork } = require('../services/networkTrustService');
const { isOffHours } = require('../services/policyService');

const router = express.Router();

const PRIVILEGED_AUTO_APPROVAL_ROLES = ['SuperAdmin', 'IT'];

const getClientIP = (req) => {
    const ipHeader = req.headers['cf-connecting-ip'] || req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || req.ip || '127.0.0.1';
    return ipHeader.split(',')[0].trim().replace('::ffff:', '');
};

router.get('/login', loginLimiter, (req, res) => {
    res.sendFile('login.html', { root: 'views' });
});

router.post('/api/login', loginLimiter, async (req, res) => {
    try {
        const username = (req.body.username || '').trim();
        const password = req.body.password || '';
        const fingerprint = req.body.fingerprint || 'unknown-device';

        if (!username || !password) {
            return res.json({ success: false, message: 'Username and password are required.' });
        }

        const clientIP = getClientIP(req);

        // Check if login is outside working hours
        if (isOffHours(new Date())) {
            // Optional: Log attempt during restricted hours
        }

        try {
            const { data: networkRule } = await supabase
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
            // No restrictive rule found
        }

        const { data: user } = await supabase
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
            }).catch(() => {});
            return res.json({ success: false, message: 'Wrong username or password.' });
        }

        if (user.status === 'blocked' && user.role !== 'SuperAdmin') {
            await logEvent(user.id, 'LOGIN_BLOCKED', 'Blocked user tried to log in', clientIP, req.correlationId);
            return res.json({ success: false, message: 'Your account is blocked. Please contact admin.' });
        }

        if (user.status === 'suspended' && user.role !== 'SuperAdmin') {
            await logEvent(user.id, 'LOGIN_SUSPENDED', 'Suspended user tried to log in', clientIP);
            return res.json({ success: false, message: 'Your account is suspended. Please contact admin.' });
        }

        if (user.failed_attempts >= 5 && user.role !== 'SuperAdmin') {
            const lockoutTime = 30 * 60 * 1000; 
            const lastFail = user.last_failed_at ? new Date(user.last_failed_at).getTime() : 0;
            if (Date.now() - lastFail < lockoutTime) {
                await logEvent(user.id, 'LOGIN_LOCKED', 'Locked user tried to log in', clientIP);
                return res.json({ success: false, message: 'Too many failed attempts. Try again in 30 minutes.' });
            }
            await supabase.from('users').update({ failed_attempts: 0 }).eq('id', user.id);
            user.failed_attempts = 0;
        }

        const passwordOk = await bcrypt.compare(password, user.password_hash);
        if (!passwordOk) {
            const failCount = (user.failed_attempts || 0) + 1;
            await supabase.from('users').update({
                failed_attempts: failCount,
                last_failed_at: new Date().toISOString()
            }).eq('id', user.id);

            await logEvent(user.id, 'LOGIN_FAILED', `Failed login attempt: ${failCount}`, clientIP);
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

        const userAgentParser = new UAParser(req.headers['user-agent']);
        const browserInfo = userAgentParser.getBrowser();
        const osInfo = userAgentParser.getOS();
        const geoData = await getGeoFromIP(clientIP);
        const country = geoData.country || 'Distributed Region';
        const isVPN = isVPNConnection(clientIP) || geoData.isProxy;

        const deviceResult = await registerDevice(user.id, {
            fingerprint: fingerprint,
            browser: `${browserInfo.name || 'Unknown'} ${browserInfo.version || ''}`,
            os: `${osInfo.name || 'Unknown'} ${osInfo.version || ''}`,
            ip: clientIP,
            country: country
        });

        const needsApproval = !PRIVILEGED_AUTO_APPROVAL_ROLES.includes(user.role);

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
            sendAnomalyAlertEmail(user.username, clientIP, country, 'New device detected').catch(() => {});
            return res.json({
                success: false,
                message: 'New device detected. Waiting for admin approval.',
                devicePending: true
            });
        }

        if (deviceResult.isNew && !needsApproval) {
            await approveDevice(deviceResult.device.id, user.id);
            await logEvent(user.id, 'DEVICE_AUTO_APPROVED', `Device auto-approved for ${user.role}`, clientIP);
            await logSecurityEvent({
                event_type: 'DEVICE_NEW',
                user_id: user.id,
                username: user.username,
                ip: clientIP,
                location: country,
                device_id: deviceResult.device ? deviceResult.device.id : null,
                details: { agent: req.headers['user-agent'], auto_authorized: true, role: user.role }
            });
            sendAnomalyAlertEmail(user.username, clientIP, country, 'Device auto-approved').catch(() => {});
        }

        if (!deviceResult.isNew && needsApproval && !deviceResult.device.approved) {
            await logEvent(user.id, 'DEVICE_PENDING', 'Login blocked: device not approved', clientIP);
            return res.json({
                success: false,
                message: 'Your device is still waiting for approval.',
                devicePending: true
            });
        }

        let isOffHoursLogin = isOffHours(new Date()); 

        if (user.department) {
            try {
                const { data: departmentContext } = await supabase
                    .from('departments')
                    .select('allowed_countries, work_hours_start, work_hours_end, timezone')
                    .eq('name', user.department)
                    .single();

                if (departmentContext) {
                    if (departmentContext.work_hours_start !== undefined && departmentContext.work_hours_end !== undefined) {
                        const deptTimezone = departmentContext.timezone || 'UTC';
                        const timeFormatter = new Intl.DateTimeFormat('en-US', { timeZone: deptTimezone, hour: 'numeric', hour12: false });
                        const departmentalHour = parseInt(timeFormatter.format(new Date()), 10);
                        isOffHoursLogin = departmentalHour < departmentContext.work_hours_start || departmentalHour >= departmentContext.work_hours_end;
                    }

                    if (departmentContext.allowed_countries) {
                        const allowedCountries = departmentContext.allowed_countries.split(',').map(c => locale.trim().toLowerCase());
                        if (allowedCountries.length > 0 && !allowedCountries.includes(country.toLowerCase())) {
                            await logEvent(user.id, 'GEO_FENCE_VIOLATION', `Country not allowed: ${country}`, clientIP);
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

        let isKnownCountry = true;
        let impossibleTravel = false;

        const { data: recentSessions } = await supabase
            .from('sessions_log')
            .select('country, login_at')
            .eq('user_id', user.id)
            .order('login_at', { ascending: false })
            .limit(10);

        if (recentSessions?.length > 0) {
            isKnownCountry = recentSessions.some(auth => auth.country === country);

            const lastSession = recentSessions[0];
            const minutesSinceLast = (new Date() - new Date(lastSession.login_at)) / (1000 * 60);
            impossibleTravel = checkImpossibleTravel(country, lastSession.country, minutesSinceLast);

            if (!isKnownCountry || impossibleTravel) {
                const reason = impossibleTravel ? 'Login from different country too quickly' : 'New login location';

                await logEvent(user.id, 'LOCATION_ALERT', `${reason}: ${country}`, clientIP);
                await logSecurityEvent({
                    event_type: 'LOCATION_ALERT',
                    user_id: user.id,
                    username: user.username,
                    ip: clientIP,
                    location: country,
                    risk_score: 100,
                    details: { reason: reason, previous_country: lastSession.country, role: user.role }
                });
                sendAnomalyAlertEmail(user.username, clientIP, country, reason).catch(() => {});
            }
        }

        const networkTrust = await classifyNetwork(user.id, clientIP, country, isVPN);

        const riskResult = await calculateRisk({
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
                const previousCountry = (recentSessions?.length > 0) ? recentSessions[0].country : 'Unknown';
                sendSlackAlert({
                    type: 'VPN_ALERT',
                    username: user.username,
                    role: user.role,
                    ip: clientIP,
                    country: country,
                    riskScore: riskResult.score,
                    riskLevel: riskResult.level,
                    previousCountry: previousCountry,
                    device: `${browserInfo.name || 'Unknown'} ${browserInfo.version || ''} on ${osInfo.name || 'Unknown'} ${osInfo.version || ''}`,
                    loginReasons: `[VPN] [Country change: ${previousCountry} -> ${country}]`,
                    reason: `VPN from new country: ${previousCountry} -> ${country}`
                }).catch(() => {});
            }
        }

        if (riskResult.score >= 100 && user.role !== 'SuperAdmin') {
            await supabase.from('users').update({ status: 'blocked' }).eq('id', user.id);
            await logEvent(user.id, 'AUTO_BLOCK', `Auto-blocked: risk score too high: ${riskResult.score}`, clientIP);
            await logSecurityEvent({
                event_type: 'LOGIN_BLOCKED',
                user_id: user.id, username: user.username, ip: clientIP, location: country, risk_score: riskResult.score,
                details: { reason: 'Auto-blocked (high risk)', role: user.role }
            });
            return res.json({ success: false, message: 'Your account has been blocked due to high risk. Contact admin.' });
        }

        await supabase.from('users').update({ failed_attempts: 0 }).eq('id', user.id);

        const logicSessionToken = crypto.randomUUID();
        await supabase.from('users').update({ active_session_token: logicSessionToken }).eq('id', user.id);

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

        const deviceLabel = `${browserInfo.name || 'Unknown'} ${browserInfo.version || ''} on ${osInfo.name || 'Unknown'} ${osInfo.version || ''}`.trim();
        req.session.deviceLabel = deviceLabel;

        let flags = [];
        flags.push(networkTrust.label);
        if (isVPN && networkTrust.tier !== 'ANONYMIZED') flags.push('[VPN]');
        if (isOffHoursLogin) flags.push('[Off-hours]');
        if (deviceResult.isNew) flags.push('[New device]');
        if (!isKnownCountry) flags.push('[New country]');
        if (impossibleTravel) flags.push('[Impossible travel]');
        if (flags.length <= 1) flags.push('[Normal]');
        
        const loginFlags = flags.join(' · ');
        req.session.loginReasons = loginFlags;

        const sessionRecord = {
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

        // OTP is always required — no bypass


        req.session.otpVerified = false;
        req.session.offHoursLogin = isOffHoursLogin;
        await generateOTP(user.id);
        metrics.otpSent.inc();

        await logEvent(user.id, 'LOGIN_PASSWORD_OK', `Password OK, OTP required (Classification: ${riskResult.level})`, clientIP);
        await logSecurityEvent({
            event_type: 'OTP_SENT',
            user_id: user.id,
            username: user.username,
            ip: clientIP,
            location: country,
            risk_score: riskResult.score,
            details: { factors: riskResult.factors, role: user.role, vpn: isVPN, off_hours: isOffHoursLogin }
        });

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
            }).catch(() => {});
        }

        return req.session.save(() => {
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

router.get('/otp', otpLimiter, (req, res) => {
    if (!req.session.userId) return res.redirect('/login');
    res.sendFile('otp.html', { root: 'views' });
});

router.post('/api/verify-otp', otpLimiter, async (req, res) => {
    try {
        const otpCode = (req.body.code || '').trim();

        if (!req.session || !req.session.userId) {
            return res.json({ success: false, message: 'Session expired. Please log in again.' });
        }

        const { userId: userId, username = 'unidentified', riskScore = 0, riskLevel = 'Low', role = 'Standard', loginIP, loginCountry } = req.session;

        const verificationResult = await verifyOTP(userId, otpCode);

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
        
        const clientIP = getClientIP(req);

        req.session.mfaVerifiedIp = clientIP;
        req.session.mfaVerifiedOffHours = isOffHours(new Date());

        const csrfToken = generateCSRFToken(req);

        await logEvent(userId, 'LOGIN_SUCCESS', `OTP verified. Risk Classification: ${riskLevel}`, clientIP);
        metrics.loginTotal.inc({ outcome: 'success' });
        metrics.riskScore.set({ user: username }, riskScore || 0);
        
        await logSecurityEvent({
            event_type: 'LOGIN_SUCCESS',
            user_id: userId,
            username: username,
            ip: loginIP,
            location: loginCountry,
            risk_score: riskScore,
            details: { role, status: 'Verified' }
        });

        await logSecurityEvent({
            event_type: 'OTP_SUCCESS',
            user_id: userId,
            username: username,
            ip: clientIP,
            risk_score: riskScore
        });

        sendLoginAlertEmail(username, loginIP || clientIP, loginCountry || 'Unknown').catch(() => {});

        try {
            const { data: prevSessions } = await supabase
                .from('sessions_log')
                .select('id')
                .eq('user_id', userId)
                .limit(2);
            
            const isFirstLogin = !prevSessions || prevSessions.length <= 1;
            sendSlackAlert({
                type: isFirstLogin ? 'FIRST_LOGIN' : 'LOGIN',
                username,
                role,
                ip: loginIP || clientIP,
                country: loginCountry || 'Unknown',
                riskScore,
                riskLevel,
                device: req.session.deviceLabel || 'Unknown device',
                loginReasons: req.session.loginReasons || 'Standard'
            }).catch(() => {});
        } catch (err) {
            sendSlackAlert({ type: 'LOGIN', username, role, ip: loginIP || clientIP, country: loginCountry || 'Unknown', riskScore, riskLevel, device: req.session.deviceLabel || 'Unknown device' }).catch(() => {});
        }

        const redirectTo = req.session.returnTo || '/dashboard';
        delete req.session.returnTo;
        
        req.session.save(() => {
            return res.json({ success: true, redirect: redirectTo, csrfToken: csrfToken });
        });

    } catch (err) {
        console.error('[Auth] OTP verify error:', err);
        return res.json({ success: false, message: 'Something went wrong. Try again.' });
    }
});

router.get('/api/session', (req, res) => {
    if (!req.session.userId || !req.session.otpVerified) {
        return res.json({ loggedIn: false });
    }
    res.json({
        loggedIn: true,
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

router.get('/logout', async (req, res) => {
    try {
        if (req.session?.userId) {
            const userId = req.session.userId;
            const clientIP = getClientIP(req);

            try { await supabase.from('users').update({ active_session_token: null }).eq('id', userId); } catch (err) { }
            try { await logEvent(userId, 'LOGOUT', 'User logged out', clientIP); } catch (err) { }
            try {
                const { data: previousSession } = await supabase
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
            req.session.destroy(() => {
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


