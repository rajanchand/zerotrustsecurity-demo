var express = require('express');
var path = require('path');
var { supabase } = require('../db');
var { getRiskHistory } = require('../services/riskEngine');
var { getUserAuditLog } = require('../services/auditService');
var { getDeviceHealth } = require('../services/deviceService');
var { logSecurityEvent } = require('../services/monitorService');
var { classifyNetwork } = require('../services/networkTrustService');
var { isOffHours } = require('../services/policyService');

var router = express.Router();

// dashboard card configs for each role
var DASHBOARD_CONFIG = {
    SuperAdmin: {
        title: 'Admin Dashboard',
        description: 'Manage users, devices, and system security.',
        cards: [
            { icon: 'U', title: 'Users', description: 'Manage users and permissions', link: '/mapping' },
            { icon: 'R', title: 'Risk Score', description: 'View security risk scores', link: '/risk' },
            { icon: 'A', title: 'Activity Log', description: 'View all system events', link: '/mapping' },
            { icon: 'D', title: 'Devices', description: 'Register and manage devices', link: '/register-device' },
            { icon: 'P', title: 'System Health', description: 'Check system security status', link: '#security-posture' }
        ]
    },
    HR: {
        title: 'HR Portal',
        description: 'Manage staff records.',
        cards: [
            { icon: 'E', title: 'Staff List', description: 'View all staff members', link: '#' },
            { icon: 'L', title: 'Leave Manager', description: 'Manage staff leave', link: '#' },
            { icon: 'R', title: 'Reports', description: 'HR reports', link: '#' }
        ]
    },
    Finance: {
        title: 'Finance Portal',
        description: 'Manage billing and reports.',
        cards: [
            { icon: 'B', title: 'Budget', description: 'Track spending', link: '#' },
            { icon: 'I', title: 'Invoices', description: 'Manage payments', link: '#' },
            { icon: 'F', title: 'Reports', description: 'Financial reports', link: '#' }
        ]
    },
    IT: {
        title: 'IT Portal',
        description: 'Manage servers and support.',
        cards: [
            { icon: 'S', title: 'Server Status', description: 'Check server health', link: '#' },
            { icon: 'T', title: 'Tickets', description: 'View support tickets', link: '#' },
            { icon: 'N', title: 'Network Rules', description: 'Manage IP rules', link: '/network' }
        ]
    },
    CustomerSupport: {
        title: 'Support Portal',
        description: 'Handle customer requests.',
        cards: [
            { icon: 'T', title: 'Tickets', description: 'View open tickets', link: '#' },
            { icon: 'K', title: 'Knowledge Base', description: 'Help articles', link: '#' },
            { icon: 'F', title: 'Feedback', description: 'Customer feedback', link: '#' }
        ]
    }
};

// serve dashboard page
router.get('/dashboard', function(req, res) {
    res.sendFile(path.join(__dirname, '..', 'views', 'dashboard.html'));
});

// serve portal page
router.get('/portal', function(req, res) {
    res.sendFile(path.join(__dirname, '..', 'views', 'portal.html'));
});

// get dashboard data for the current user
router.get('/api/dashboard-data', async function(req, res) {
    try {
        var role = req.session.role;
        var userId = req.session.userId;
        var username = req.session.username;
        var department = req.session.department;
        var riskScore = req.session.riskScore;
        var riskLevel = req.session.riskLevel;
        var isUnusualHours = req.session.isUnusualHours;
        var loginCountry = req.session.loginCountry;
        var loginIP = req.session.loginIP;

        var dashConfig = DASHBOARD_CONFIG[role] || DASHBOARD_CONFIG.HR;

        var securityCard = { icon: 'S', title: 'Personal Security', description: 'Your security status', link: '/risk' };
        var cards = dashConfig.cards.concat([securityCard]);

        var { count: sessionCount } = await supabase
            .from('sessions_log')
            .select('*', { count: 'exact', head: true })
            .eq('user_id', userId);

        var { data: lastSession } = await supabase
            .from('sessions_log')
            .select('country, device_fingerprint, ip')
            .eq('user_id', userId)
            .order('login_at', { ascending: false })
            .limit(1)
            .single();

        var isNewDevice = false;
        if (lastSession) {
            var { count: deviceCount } = await supabase
                .from('devices')
                .select('*', { count: 'exact', head: true })
                .eq('user_id', userId)
                .eq('fingerprint', lastSession.device_fingerprint);
            isNewDevice = deviceCount === 0;
        }

        res.json({
            user: { username: username, role: role, department: department },
            dashboard: {
                title: dashConfig.title,
                description: dashConfig.description,
                cards: cards
            },
            security: {
                riskScore: riskScore || 0,
                riskLevel: riskLevel || 'Low',
                sessionCount: sessionCount || 0,
                loginContext: {
                    country: (lastSession && lastSession.country) || loginCountry || 'Unknown',
                    ip: (lastSession && lastSession.ip) || loginIP || 'Unknown',
                    isNewDevice: isNewDevice
                },
                isUnusualHours: isUnusualHours || false
            }
        });
    } catch (err) {
        console.error('[Dashboard] Load error:', err);
        res.status(500).json({ error: 'Dashboard data unavailable.' });
    }
});

// recent activity for the logged in user
router.get('/api/activity', async function(req, res) {
    try {
        var logs = await getUserAuditLog(req.session.userId, 20);
        res.json(logs);
    } catch (err) {
        res.json([]);
    }
});

// serve risk page
router.get('/risk', function(req, res) {
    res.sendFile(path.join(__dirname, '..', 'views', 'risk.html'));
});

// get risk data for the current user
router.get('/api/risk-data', async function(req, res) {
    try {
        var history = await getRiskHistory(req.session.userId, 20);
        res.json({
            currentScore: req.session.riskScore || 0,
            currentLevel: req.session.riskLevel || 'Low',
            factors: req.session.riskFactors || [],
            history: history
        });
    } catch (err) {
        res.json({ currentScore: 0, currentLevel: 'Low', factors: [], history: [] });
    }
});

// admin stats for the superadmin dashboard
router.get('/api/admin-stats', async function(req, res) {
    if (req.session.role !== 'SuperAdmin') {
        return res.status(403).json({ error: 'SuperAdmin access required.' });
    }

    var { data: deviceCheck } = await supabase
        .from('devices')
        .select('approved')
        .eq('user_id', req.session.userId)
        .eq('fingerprint', req.session.deviceFingerprint)
        .single();

    if (!deviceCheck || !deviceCheck.approved) {
        return res.status(403).json({ error: 'Please register your device first.' });
    }

    try {
        var results = await Promise.all([
            supabase.from('users').select('*', { count: 'exact', head: true }),
            supabase.from('users').select('*', { count: 'exact', head: true }).eq('status', 'active'),
            supabase.from('users').select('*', { count: 'exact', head: true }).eq('status', 'blocked'),
            supabase.from('devices').select('*', { count: 'exact', head: true }).eq('approved', false),
            supabase.from('sessions_log').select('*', { count: 'exact', head: true })
        ]);

        var totalUsers = results[0].count;
        var activeUsers = results[1].count;
        var blockedUsers = results[2].count;
        var pendingDevices = results[3].count;
        var totalSessions = results[4].count;

        var since24h = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();

        var activityResults = await Promise.all([
            supabase.from('audit_log').select('*', { count: 'exact', head: true }).gte('created_at', since24h),
            supabase.from('audit_log').select('*', { count: 'exact', head: true }).eq('action', 'LOGIN_FAILED').gte('created_at', since24h),
            supabase.from('audit_log').select('id, user_id, action, detail, ip, created_at').order('created_at', { ascending: false }).limit(10)
        ]);

        var events24h = activityResults[0].count;
        var fails24h = activityResults[1].count;
        var recentEvents = activityResults[2].data;

        var { data: rolesData } = await supabase.from('users').select('role');
        var roleBreakdown = {};
        (rolesData || []).forEach(function(u) { roleBreakdown[u.role] = (roleBreakdown[u.role] || 0) + 1; });

        res.json({
            users: { total: totalUsers || 0, active: activeUsers || 0, blocked: blockedUsers || 0 },
            devices: { pendingApproval: pendingDevices || 0 },
            activity: {
                events24h: events24h || 0,
                loginFails24h: fails24h || 0,
                totalSessions: totalSessions || 0,
                mfaRate: totalSessions > 0 ? (Math.round((totalSessions / (totalSessions + fails24h)) * 1000) / 10) : 99.8,
                health: 'OK'
            },
            roleBreakdown: roleBreakdown,
            recentEvents: recentEvents || []
        });
    } catch (err) {
        console.error('[Dashboard] Stats error:', err);
        res.status(500).json({ error: 'Failed to load stats.' });
    }
});

// emergency lockdown - ends all non-admin sessions
router.post('/api/system/emergency-lockdown', async function(req, res) {
    if (req.session.role !== 'SuperAdmin') {
        return res.status(403).json({ success: false, message: 'SuperAdmin access required for this action.' });
    }

    try {
        var { error: dbError } = await supabase
            .from('users')
            .update({ active_session_token: null })
            .neq('role', 'SuperAdmin');

        if (dbError) throw dbError;

        await logSecurityEvent({
            event_type: 'FORCE_LOGOUT',
            user_id: req.session.userId,
            username: req.session.username,
            ip: req.ip,
            details: { action_taken: 'ALL_SESSIONS_ENDED' }
        });

        res.json({ success: true, message: 'All sessions ended.' });
    } catch (err) {
        console.error('[Dashboard] Lockdown error:', err);
        res.status(500).json({ success: false, message: 'Failed to end sessions.' });
    }
});

// serve remote analytics page
router.get('/admin/remote-analytics', function(req, res) {
    if (req.session.role !== 'SuperAdmin' && req.session.role !== 'IT') {
        return res.status(403).send('Admin access required.');
    }
    res.sendFile(path.join(__dirname, '..', 'views', 'remote-analytics.html'));
});

// remote analytics data
router.get('/api/admin/remote-analytics', async function(req, res) {
    if (req.session.role !== 'SuperAdmin' && req.session.role !== 'IT') {
        return res.status(403).json({ error: 'Admin access required.' });
    }

    try {
        var since24h = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();

        var { data: sessions } = await supabase
            .from('sessions_log')
            .select('id, user_id, ip, browser, os, country, risk_score, device_fingerprint, login_at, vpn')
            .gte('login_at', since24h)
            .order('login_at', { ascending: false });

        sessions = sessions || [];

        var { data: users } = await supabase.from('users').select('id, username, role');
        var userMap = {};
        (users || []).forEach(function(u) { userMap[u.id] = u; });

        var { count: vpnCount } = await supabase
            .from('security_events')
            .select('*', { count: 'exact', head: true })
            .eq('event_type', 'VPN_DETECTED')
            .gte('created_at', since24h);

        // find off-hours logins
        var offHoursEvents = [];
        var offHoursUsers = {};

        sessions.forEach(function(session) {
            if (isOffHours(new Date(session.login_at))) {
                var identityContext = userMap[session.user_id] || {};
                var offHoursEntry = {
                    id: session.id,
                    user_id: session.user_id,
                    ip: session.ip,
                    browser: session.browser,
                    os: session.os,
                    country: session.country,
                    risk_score: session.risk_score,
                    device_fingerprint: session.device_fingerprint,
                    login_at: session.login_at,
                    vpn: session.vpn,
                    username: identityContext.username || 'Unknown',
                    details: { role: identityContext.role || 'Personnel' },
                    created_at: session.login_at
                };
                offHoursEvents.push(offHoursEntry);
                if (!offHoursUsers[session.user_id]) offHoursUsers[session.user_id] = offHoursEntry;
            }
        });

        var totalSessions = sessions.length;
        var vpnPercent = totalSessions > 0 ? Math.round((vpnCount || 0) / totalSessions * 100) : 0;

        // average risk score
        var avgRisk = 0;
        if (totalSessions > 0) {
            var sumRisk = sessions.reduce(function(acc, s) { return acc + (s.risk_score || 0); }, 0);
            avgRisk = Math.round(sumRisk / totalSessions);
        }

        // unique countries and devices
        var uniqueCountries = {};
        var uniqueDevices = {};
        sessions.forEach(function(s) {
            if (s.country) uniqueCountries[s.country] = true;
            if (s.device_fingerprint) uniqueDevices[s.device_fingerprint] = true;
        });

        // hourly breakdown
        var hourlyCounts = Array(24).fill(0);
        sessions.forEach(function(s) {
            var observationHour = new Date(s.login_at).getUTCHours();
            hourlyCounts[observationHour]++;
        });
        var hourlyBreakdown = hourlyCounts.map(function(count, hour) { return { hour: hour, count: count }; });

        // top countries
        var countryCounts = {};
        sessions.forEach(function(s) {
            var region = s.country || 'Unknown';
            countryCounts[region] = (countryCounts[region] || 0) + 1;
        });

        var topCountries = Object.keys(countryCounts)
            .map(function(k) { return { country: k, count: countryCounts[k] }; })
            .sort(function(a, b) { return b.count - a.count; })
            .slice(0, 10);

        // network trust classification
        var networkBreakdown = { office: 0, secure_remote: 0, untrusted: 0, anonymized: 0 };
        for (var i = 0; i < sessions.length; i++) {
            var s = sessions[i];
            try {
                var trustRole = await classifyNetwork(s.user_id, s.ip, s.country, false);
                if (trustRole.tier === 'INSTITUTIONAL') {
                    networkBreakdown.office++;
                    s.networkLabel = 'Office Network';
                } else if (trustRole.tier === 'SECURE_REMOTE') {
                    networkBreakdown.secure_remote++;
                    s.networkLabel = 'Trusted: ' + (trustRole.label || 'Home/Remote');
                } else if (trustRole.tier === 'ANONYMIZED') {
                    networkBreakdown.anonymized++;
                    s.networkLabel = 'VPN/Proxy';
                } else {
                    networkBreakdown.untrusted++;
                    s.networkLabel = 'Unknown Network';
                }
            } catch (err) {
                networkBreakdown.untrusted++;
                s.networkLabel = 'Unknown Network';
            }
        }

        networkBreakdown.anonymized += (vpnCount || 0);
        if (networkBreakdown.anonymized > 0 && networkBreakdown.untrusted >= networkBreakdown.anonymized) {
            networkBreakdown.untrusted -= networkBreakdown.anonymized;
        }

        // build the recent sessions list
        var recentList = sessions.slice(0, 25).map(function(s) {
            var identity = userMap[s.user_id] || {};
            return {
                username: identity.username || 'Unidentified',
                role: identity.role || 'Personnel',
                browser: s.browser || 'Unknown',
                os: s.os || 'Unknown',
                ip: s.ip || 'Unknown',
                country: s.country || 'Unknown',
                risk_score: s.risk_score || 0,
                networkLabel: s.networkLabel || 'Unknown Network',
                login_at: s.login_at
            };
        });

        res.json({
            kpis: {
                totalSessions24h: totalSessions,
                vpnPercentage: vpnPercent,
                offHoursLogins: offHoursEvents.length,
                uniqueOffHoursUsers: Object.keys(offHoursUsers).length,
                avgRiskScore: avgRisk,
                uniqueCountries: Object.keys(uniqueCountries).length,
                uniqueDevices: Object.keys(uniqueDevices).length
            },
            hourlyBreakdown: hourlyBreakdown,
            topLocations: topCountries,
            networkTrust: networkBreakdown,
            recentSessions: recentList,
            offHoursEvents: offHoursEvents,
            offHoursCount: offHoursEvents.length,
            uniqueOffHoursCount: Object.keys(offHoursUsers).length,
            uniqueOffHoursUsers: Object.values(offHoursUsers)
        });
    } catch (err) {
        console.error('[Analytics] Error:', err);
        res.status(500).json({ error: 'Failed to load analytics.' });
    }
});

module.exports = router;
