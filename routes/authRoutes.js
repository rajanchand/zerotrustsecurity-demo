// routes/authRoutes.js
// handles login, OTP verification, logout, and device approval checks
// includes IP blocklist enforcement, rate limiting, and concurrent session control

var express  = require('express');
var bcrypt   = require('bcryptjs');
var crypto   = require('crypto');
var UAParser = require('ua-parser-js');

var { supabase }                                          = require('../db');
var { generateOTP, verifyOTP }                               = require('../services/otpService');
var { sendLoginAlertEmail, sendAnomalyAlertEmail }        = require('../services/emailService');
var { calculateRisk }                                     = require('../services/riskEngine');
var { registerDevice, approveDevice }                     = require('../services/deviceService');
var { getGeoFromIP, isVPNConnection, checkImpossibleTravel } = require('../services/geoService');
var { logEvent }                                          = require('../services/auditService');
var { logSecurityEvent }                                  = require('../services/monitorService');
var { generateCSRFToken }                                 = require('../middleware/csrf');
var { loginLimiter, otpLimiter }                          = require('../middleware/rateLimiter');
var metrics                                               = require('../services/metricservice');

var router = express.Router();

// roles that get their devices auto-approved on first login
var AUTO_APPROVE_ROLES = ['SuperAdmin', 'IT'];

// ────────────────────────────────────────────────────────────────
// GET /login  — serve the login page
// ────────────────────────────────────────────────────────────────
router.get('/login', function (req, res) {
    res.sendFile('login.html', { root: 'views' });
});

// ────────────────────────────────────────────────────────────────
// POST /api/login  — authenticate user (rate-limited)
// ────────────────────────────────────────────────────────────────
router.post('/api/login', loginLimiter, async function (req, res) {
    try {
        var username    = (req.body.username || '').trim();
        var password    = req.body.password  || '';
        var fingerprint = req.body.fingerprint || 'unknown';

        if (!username || !password) {
            return res.json({ success: false, message: 'Please enter your username and password.' });
        }

        // resolve real client IP (handles proxies / VPS setups)
        var rawIp = req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || req.ip || '127.0.0.1';
        var ip    = rawIp.split(',')[0].trim().replace('::ffff:', '');

        // ── TIME-BASED ACCESS CONTROL (UTC to avoid VPS timezone drift) ──
        var currentHour = new Date().getUTCHours();
        var ALLOW_START = 0;  // midnight UTC
        var ALLOW_END   = 24; // all hours allowed — adjust if needed (e.g. 6-22)

        if (currentHour < ALLOW_START || currentHour >= ALLOW_END) {
            return res.json({
                success: false,
                message: 'Access denied: Remote work access is restricted during off-hours.'
            });
        }

        // ── IP BLOCKLIST CHECK ──
        try {
            var { data: ipRule } = await supabase
                .from('ip_rules')
                .select('action, reason')
                .eq('ip_address', ip)
                .eq('action', 'block')
                .single();

            if (ipRule) {
                await logSecurityEvent({
                    event_type: 'IP_BLOCKED',
                    username:   username,
                    ip:         ip,
                    details:    { reason: ipRule.reason || 'IP is on the block list', action: 'login_rejected' }
                });
                return res.json({ success: false, message: 'Access denied from your IP address.' });
            }
        } catch (e) {
            // no blocking rule found — continue
        }

        // ── FIND USER ──
        var { data: user } = await supabase
            .from('users')
            .select('*')
            .eq('username', username)
            .single();

        if (!user) {
            logSecurityEvent({
                event_type: 'LOGIN_FAILED',
                username:   username,
                ip:         ip,
                details:    { reason: 'User not found' }
            }).catch(function () {});
            return res.json({ success: false, message: 'Invalid username or password.' });
        }

        // ── ACCOUNT STATUS CHECKS ──
        if (user.status === 'blocked' && user.role !== 'SuperAdmin') {
            await logEvent(user.id, 'LOGIN_BLOCKED', 'Blocked user tried to login', req.ip);
            return res.json({ success: false, message: 'Your account has been blocked. Contact your administrator.' });
        }

        if (user.status === 'suspended' && user.role !== 'SuperAdmin') {
            await logEvent(user.id, 'LOGIN_SUSPENDED', 'Suspended user tried to login', req.ip);
            return res.json({ success: false, message: 'Your account has been suspended. Contact your administrator.' });
        }

        // lock out non-admin accounts after 5 consecutive failures
        if (user.failed_attempts >= 5 && user.role !== 'SuperAdmin') {
            await logEvent(user.id, 'LOGIN_LOCKED', 'Locked account login attempt', req.ip);
            return res.json({ success: false, message: 'Account locked after 5 failed attempts. Contact your administrator.' });
        }

        // ── PASSWORD VERIFICATION ──
        var passwordMatch = bcrypt.compareSync(password, user.password_hash);
        if (!passwordMatch) {
            var newAttempts = (user.failed_attempts || 0) + 1;
            await supabase.from('users').update({
                failed_attempts: newAttempts,
                last_failed_at:  new Date().toISOString()
            }).eq('id', user.id);

            await logEvent(user.id, 'LOGIN_FAILED', 'Wrong password (attempt ' + newAttempts + ')', req.ip);
            metrics.loginTotal.inc({ result: 'failed' });
            await logSecurityEvent({
                event_type: 'LOGIN_FAILED',
                user_id:    user.id,
                username:   user.username,
                ip:         ip,
                risk_score: newAttempts * 10,
                details:    { reason: 'Wrong password', attempt: newAttempts, role: user.role }
            });
            return res.json({ success: false, message: 'Invalid username or password.' });
        }

        // ── DEVICE & GEO INFO ──
        var parser      = new UAParser(req.headers['user-agent']);
        var browserInfo = parser.getBrowser();
        var osInfo      = parser.getOS();

        var geo     = await getGeoFromIP(ip);
        var country = geo.country || 'Unknown';
        var vpn     = isVPNConnection(ip) || geo.isProxy;

        // ── DEVICE REGISTRATION ──
        var deviceResult  = await registerDevice(user.id, {
            fingerprint: fingerprint,
            browser:     (browserInfo.name || 'Unknown') + ' ' + (browserInfo.version || ''),
            os:          (osInfo.name || 'Unknown') + ' ' + (osInfo.version || ''),
            ip:          ip,
            country:     country
        });

        var needsApproval = AUTO_APPROVE_ROLES.indexOf(user.role) === -1;

        if (deviceResult.isNew && needsApproval) {
            // brand-new device for a non-privileged role — requires admin approval
            await logEvent(user.id, 'DEVICE_NEW', 'New device registered, pending approval', ip);
            await logSecurityEvent({
                event_type: 'DEVICE_NEW',
                user_id:    user.id,
                username:   user.username,
                ip:         ip,
                location:   country,
                device_id:  deviceResult.device ? deviceResult.device.id : null,
                details:    { browser: req.headers['user-agent'], needs_approval: true, role: user.role }
            });
            sendAnomalyAlertEmail(user.username, ip, country, 'New device detected (needs approval)').catch(function () {});
            return res.json({
                success: false,
                message: 'New device detected. Your device must be approved by an administrator before you can log in.',
                devicePending: true
            });
        }

        if (deviceResult.isNew && !needsApproval) {
            // auto-approve privileged roles (SuperAdmin / IT) on first login
            await approveDevice(deviceResult.device.id, user.id);
            await logEvent(user.id, 'DEVICE_AUTO_APPROVED', 'Device auto-approved for ' + user.role, ip);
            await logSecurityEvent({
                event_type: 'DEVICE_NEW',
                user_id:    user.id,
                username:   user.username,
                ip:         ip,
                location:   country,
                device_id:  deviceResult.device ? deviceResult.device.id : null,
                details:    { browser: req.headers['user-agent'], auto_approved: true, role: user.role }
            });
            sendAnomalyAlertEmail(user.username, ip, country, 'New device registered (auto-approved)').catch(function () {});
        }

        // re-check device approval status in case the device existed but is unapproved
        if (!deviceResult.isNew && needsApproval && !deviceResult.device.approved) {
            await logEvent(user.id, 'DEVICE_PENDING', 'Login blocked — device not yet approved', ip);
            return res.json({
                success: false,
                message: 'Your device is pending approval. Please contact your administrator.',
                devicePending: true
            });
        }

        // ── WORKING HOURS CHECK (local server time) ──
        var localHour      = new Date().getHours();
        var isUnusualHours = localHour >= 18 || localHour < 9;

        // ── GEO-FENCING CHECK PER DEPARTMENT ──
        if (user.department) {
            try {
                var { data: deptInfo } = await supabase
                    .from('departments')
                    .select('allowed_countries')
                    .eq('name', user.department)
                    .single();

                if (deptInfo && deptInfo.allowed_countries) {
                    var allowedList = deptInfo.allowed_countries
                        .split(',')
                        .map(function (c) { return c.trim().toLowerCase(); });

                    if (allowedList.length > 0 && !allowedList.includes(country.toLowerCase())) {
                        await logEvent(user.id, 'GEO_FENCE_VIOLATION', 'Login blocked from ' + country + ' (department geo-fence)', ip);
                        await logSecurityEvent({
                            event_type: 'GEO_FENCE_VIOLATION',
                            user_id:    user.id,
                            username:   user.username,
                            ip:         ip,
                            location:   country,
                            risk_score: 100,
                            details:    {
                                reason:  'Country not in department allowed list',
                                allowed: deptInfo.allowed_countries,
                                role:    user.role
                            }
                        });
                        return res.json({
                            success: false,
                            message: 'Access denied. Logins from ' + country + ' are not permitted for your department.'
                        });
                    }
                }
            } catch (e) {
                // ignore if departments table doesn't have the column yet
            }
        }

        // ── LOCATION ANOMALY DETECTION ──
        var isNewCountry      = false;
        var isImpossibleTravel = false;

        var { data: recentLogins } = await supabase
            .from('sessions_log')
            .select('country, login_at')
            .eq('user_id', user.id)
            .order('login_at', { ascending: false })
            .limit(10);

        if (recentLogins && recentLogins.length > 0) {
            isNewCountry = !recentLogins.some(function (log) { return log.country === country; });

            var lastLogin       = recentLogins[0];
            var timeDiffMinutes = (new Date() - new Date(lastLogin.login_at)) / (1000 * 60);
            isImpossibleTravel  = checkImpossibleTravel(country, lastLogin.country, timeDiffMinutes);

            if (isNewCountry || isImpossibleTravel) {
                var anomalyReason = isImpossibleTravel
                    ? 'Impossible travel detected'
                    : 'Unrecognised login location';

                await logEvent(user.id, 'LOCATION_ANOMALY', anomalyReason + ' from ' + country, ip);
                await logSecurityEvent({
                    event_type: 'LOCATION_ANOMALY',
                    user_id:    user.id,
                    username:   user.username,
                    ip:         ip,
                    location:   country,
                    risk_score: 100,
                    details:    { reason: anomalyReason, previous_location: lastLogin.country, role: user.role }
                });
                sendAnomalyAlertEmail(user.username, ip, country, anomalyReason).catch(function () {});
            }
        }

        // ── RISK SCORE CALCULATION ──
        var risk = await calculateRisk({
            userId:           user.id,
            username:         user.username,
            ip:               ip,
            country:          country,
            location:         country,
            isNewDevice:      deviceResult.isNew,
            isNewCountry:     isNewCountry,
            failedAttempts:   user.failed_attempts || 0,
            isVPN:            vpn,
            isAdminUnknownIP: false,
            role:             user.role,
            isUnusualHours:   isUnusualHours
        });

        if (vpn) {
            await logSecurityEvent({
                event_type: 'VPN_DETECTED',
                user_id:    user.id,
                username:   user.username,
                ip:         ip,
                location:   country,
                risk_score: risk.score,
                details:    { role: user.role, risk_level: risk.level }
            });
            metrics.vpnDetected.inc();
        }

        // ── AUTO-BLOCK AT CRITICAL RISK (100+) ──
        if (risk.score >= 100 && user.role !== 'SuperAdmin') {
            await supabase.from('users').update({ status: 'blocked' }).eq('id', user.id);
            await logEvent(user.id, 'AUTO_BLOCK', 'Account auto-blocked due to critical risk score (' + risk.score + ')', ip);
            await logSecurityEvent({
                event_type: 'LOGIN_BLOCKED',
                user_id: user.id, username: user.username, ip: ip, location: country, risk_score: risk.score,
                details: { reason: 'Automatic block triggered by risk engine (100+)', role: user.role }
            });
            return res.json({ success: false, message: 'Account automatically blocked due to critical risk score (' + risk.score + '). Please contact an Administrator.' });
        }

        // reset failed-login counter on success
        await supabase.from('users').update({ failed_attempts: 0 }).eq('id', user.id);

        // ── SESSION SETUP ──
        // generate a unique token for concurrent-session control
        var sessionToken = crypto.randomUUID();

        // write the token to DB *before* setting it on the session so the
        // auth middleware will always find a matching token when it checks
        var tokenUpdateRes = await supabase.from('users').update({ active_session_token: sessionToken }).eq('id', user.id);
        if (tokenUpdateRes.error) {
            console.error('Failed to update active_session_token in DB:', tokenUpdateRes.error);
        }

        req.session.userId          = user.id;
        req.session.username        = user.username;
        req.session.role            = user.role;
        req.session.department      = user.department;
        req.session.permissions     = user.permissions || {}; // Store granular permissions
        req.session.riskScore       = risk.score;
        req.session.riskLevel       = risk.level;
        req.session.riskFactors     = risk.factors;
        req.session.loginIP         = ip;
        req.session.loginCountry    = country;
        req.session.lastActive      = Date.now();
        req.session.deviceFingerprint = fingerprint;
        req.session.sessionToken    = sessionToken;
        req.session.vpn             = vpn;
        req.session.isUnusualHours  = isUnusualHours;

        // log the session to sessions_log (vpn field added if column exists)
        var sessionRecord = {
            user_id:            user.id,
            ip:                 ip,
            user_agent:         req.headers['user-agent'],
            browser:            browserInfo.name  || 'Unknown',
            os:                 osInfo.name        || 'Unknown',
            device_fingerprint: fingerprint,
            country:            country,
            risk_score:         risk.score,
            vpn:                vpn ? true : false
        };

        var sessionInsert = await supabase.from('sessions_log').insert(sessionRecord);
        if (sessionInsert.error && sessionInsert.error.code === '42703') {
            // vpn column doesn't exist yet — insert without it
            delete sessionRecord.vpn;
            await supabase.from('sessions_log').insert(sessionRecord);
        }

        // ── ADAPTIVE MFA (risk-based) ──
        if (risk.score === 0) {
            // identical context to normal pattern — bypass OTP
            req.session.otpVerified = true;
            var csrfToken = generateCSRFToken(req);

            await logEvent(user.id, 'LOGIN_SUCCESS', 'Logged in (Adaptive MFA: OTP bypassed). Risk: Low (0)', ip);
            metrics.loginTotal.inc({ result: 'success' });
            metrics.riskScore.set({ username: user.username }, 0);
            await logSecurityEvent({
                event_type: 'LOGIN_SUCCESS',
                user_id:    user.id,
                username:   user.username,
                ip:         ip,
                location:   country,
                risk_score: 0,
                details:    { risk_level: 'Low', role: user.role, adaptive_mfa: 'bypassed', department: user.department }
            });

            sendLoginAlertEmail(user.username, ip, country).catch(function () {});

            // save session before responding so the token is always in sync
            return req.session.save(function (saveErr) {
                if (saveErr) console.error('Session save error (login bypass):', saveErr);
                return res.json({
                    success:   true,
                    risk:      { score: 0, level: 'Low' },
                    redirect:  '/dashboard',
                    csrfToken: csrfToken
                });
            });
        }

        // risk > 0 — require OTP before granting access
        req.session.otpVerified    = false;
        req.session.offHoursLogin  = isUnusualHours;   // tell OTP page to show the warning
        await generateOTP(user.id);
        metrics.otpSent.inc();

        await logEvent(user.id, 'LOGIN_PASSWORD_OK', 'Password verified, OTP required. Risk: ' + risk.level + ' (' + risk.score + ')', ip);
        await logSecurityEvent({
            event_type: 'OTP_SENT',
            user_id:    user.id,
            username:   user.username,
            ip:         ip,
            location:   country,
            risk_score: risk.score,
            details:    { risk_level: risk.level, risk_factors: risk.factors, role: user.role, vpn: vpn, off_hours: isUnusualHours }
        });

        // if off-hours, log it as a separate event so monitoring shows it
        if (isUnusualHours) {
            await logSecurityEvent({
                event_type: 'RISK_SCORE_CHANGED',
                user_id:    user.id,
                username:   user.username,
                ip:         ip,
                location:   country,
                risk_score: risk.score,
                details:    { reason: 'Off-hours login', time_utc: new Date().toUTCString(), role: user.role }
            });
        }

        // save session so the session token is committed before the OTP page loads
        return req.session.save(function (saveErr) {
            if (saveErr) console.error('Session save error (otp redirect):', saveErr);
            return res.json({
                success:   true,
                risk:      { score: risk.score, level: risk.level, factors: risk.factors },
                offHours:  isUnusualHours,
                vpn:       vpn,
                redirect:  '/otp'
            });
        });

    } catch (err) {
        console.error('Login error:', err);
        return res.json({ success: false, message: 'Server error. Please try again.' });
    }
});

// ────────────────────────────────────────────────────────────────
// GET /otp  — serve the OTP verification page
// ────────────────────────────────────────────────────────────────
router.get('/otp', function (req, res) {
    if (!req.session.userId) return res.redirect('/login');
    res.sendFile('otp.html', { root: 'views' });
});

// ────────────────────────────────────────────────────────────────
// POST /api/verify-otp  — check the one-time password (rate-limited)
// ────────────────────────────────────────────────────────────────
router.post('/api/verify-otp', otpLimiter, async function (req, res) {
    try {
        var code = (req.body.code || '').trim();

        if (!req.session || !req.session.userId) {
            return res.json({ success: false, message: 'Session expired. Please log in again.' });
        }

        // cache session values up front to avoid race conditions
        var userId       = req.session.userId;
        var username     = req.session.username     || 'unknown';
        var riskScore    = req.session.riskScore    || 0;
        var riskLevel    = req.session.riskLevel    || 'Low';
        var role         = req.session.role         || 'User';
        var department   = req.session.department   || '';
        var loginIP      = req.session.loginIP      || req.ip;
        var loginCountry = req.session.loginCountry || 'Unknown';

        var result = await verifyOTP(userId, code);

        if (!result.valid) {
            await logEvent(userId, 'OTP_FAILED', result.reason, req.ip);
            await logSecurityEvent({
                event_type: 'OTP_FAILED',
                user_id:    userId,
                username:   username,
                ip:         req.ip,
                risk_score: riskScore,
                details:    { reason: result.reason }
            });
            return res.json({ success: false, message: result.reason });
        }

        if (!req.session) {
            return res.json({ success: false, message: 'Session was invalidated during verification. Please log in again.' });
        }

        req.session.otpVerified = true;
        req.session.lastActive  = Date.now();

        var csrfToken = generateCSRFToken(req);

        await logEvent(userId, 'LOGIN_SUCCESS', 'Logged in. Risk: ' + riskLevel + ' (' + riskScore + ')', req.ip);
        metrics.loginTotal.inc({ result: 'success' });
        metrics.riskScore.set({ username: req.session.username || 'unknown' }, riskScore || 0);
        await logSecurityEvent({
            event_type: 'LOGIN_SUCCESS',
            user_id:    userId,
            username:   username,
            ip:         loginIP,
            location:   loginCountry,
            risk_score: riskScore,
            details:    { risk_level: riskLevel, role: role, department: department }
        });

        await logSecurityEvent({
            event_type: 'OTP_SUCCESS',
            user_id:    userId,
            username:   username,
            ip:         req.ip,
            risk_score: riskScore,
            details:    { role: role }
        });

        sendLoginAlertEmail(username, loginIP, loginCountry).catch(function (err) {
            console.error('Failed to send login alert email:', err);
        });

        req.session.save(function (err) {
            if (err) console.error('Session save error (otp verify):', err);
            return res.json({ success: true, redirect: '/dashboard', csrfToken: csrfToken });
        });

    } catch (err) {
        console.error('OTP verification error:', err);
        return res.json({ success: false, message: 'Server error. Please try again.' });
    }
});

// ────────────────────────────────────────────────────────────────
// GET /api/session  — return current session info to the frontend
// ────────────────────────────────────────────────────────────────
router.get('/api/session', function (req, res) {
    if (!req.session.userId || !req.session.otpVerified) {
        return res.json({ loggedIn: false });
    }
    res.json({
        loggedIn: true,
        user: {
            id:         req.session.userId,
            userId:     req.session.userId,
            username:   req.session.username,
            email:      req.session.email || '',
            role:       req.session.role,
            department: req.session.department,
            riskScore:  req.session.riskScore  || 0,
            riskLevel:  req.session.riskLevel  || 'Low'
        },
        risk: {
            score:   req.session.riskScore  || 0,
            level:   req.session.riskLevel  || 'Low',
            factors: req.session.riskFactors || []
        },
        offHoursLogin:  !!req.session.offHoursLogin,
        vpn:            !!req.session.vpn,
        loginIP:        req.session.loginIP      || '',
        loginCountry:   req.session.loginCountry || '',
        isUnusualHours: !!req.session.isUnusualHours,
        security: {
            sessionToken:    req.session.sessionToken ? 'active' : 'none',
            deviceBound:     !!req.session.deviceFingerprint,
            passwordExpired: !!req.session.passwordExpired
        }
    });
});

// ────────────────────────────────────────────────────────────────
// GET /logout  — destroy session and redirect to login
// ────────────────────────────────────────────────────────────────
router.get('/logout', async function (req, res) {
    try {
        if (req.session && req.session.userId) {
            var userId = req.session.userId;
            var ip     = req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || req.ip || '127.0.0.1';
            
            // 1. Clear session token in DB
            try { await supabase.from('users').update({ active_session_token: null }).eq('id', userId); } catch (e) {}
            
            // 2. Audit logout event
            try { await logEvent(userId, 'LOGOUT', 'User logged out', ip); } catch (e) {}
            
            // 3. Update sessions_log with logout_at
            try {
                // Find the most recent active session for this user to mark as ended
                var { data: lastSession } = await supabase
                    .from('sessions_log')
                    .select('id')
                    .eq('user_id', userId)
                    .order('login_at', { ascending: false })
                    .limit(1)
                    .single();
                
                if (lastSession) {
                    await supabase.from('sessions_log')
                        .update({ logout_at: new Date().toISOString() })
                        .eq('id', lastSession.id);
                }
            } catch (e) {
                // logout_at column might not exist yet
            }
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
        console.error('Logout error:', err);
        res.redirect('/login');
    }
});
module.exports = router;
