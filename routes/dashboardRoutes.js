const express = require('express');
const path = require('path');
const { supabase } = require('../db');
const { getRiskHistory } = require('../services/riskEngine');
const { getUserAuditLog } = require('../services/auditService');
const { getDeviceHealth } = require('../services/deviceService');
const { logSecurityEvent } = require('../services/monitorService');
const { classifyNetwork } = require('../services/networkTrustService');
const { isOffHours } = require('../services/policyService');

const router = express.Router();

const DASHBOARD_CONFIG = {
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

router.get('/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'views', 'dashboard.html'));
});

router.get('/portal', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'views', 'portal.html'));
});

router.get('/api/dashboard-data', async (req, res) => {
    try {
        const { role, userId: userId, username, department, riskScore, riskLevel, isUnusualHours, loginCountry, loginIP } = req.session;
        const dashConfig = DASHBOARD_CONFIG[role] || DASHBOARD_CONFIG.HR;

        const securityCard = { icon: 'S', title: 'Personal Security', description: 'Your security status', link: '/risk' };
        const cards = [...dashConfig.cards, securityCard];

        const { count: sessionCount } = await supabase
            .from('sessions_log')
            .select('*', { count: 'exact', head: true })
            .eq('user_id', userId);

        const { data: lastSession } = await supabase
            .from('sessions_log')
            .select('country, device_fingerprint, ip')
            .eq('user_id', userId)
            .order('login_at', { ascending: false })
            .limit(1)
            .single();

        let isNewDevice = false;
        if (lastSession) {
            const { count: deviceCount } = await supabase
                .from('devices')
                .select('*', { count: 'exact', head: true })
                .eq('user_id', userId)
                .eq('fingerprint', lastSession.device_fingerprint);
            isNewDevice = deviceCount === 0;
        }

        res.json({
            user: { username, role, department },
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
                    country: lastSession?.country || loginCountry || 'Unknown',
                    ip: lastSession?.ip || loginIP || 'Unknown',
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

router.get('/api/activity', async (req, res) => {
    try {
        const logs = await getUserAuditLog(req.session.userId, 20);
        res.json(logs);
    } catch (err) {
        res.json([]);
    }
});

router.get('/risk', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'views', 'risk.html'));
});

router.get('/api/risk-data', async (req, res) => {
    try {
        const history = await getRiskHistory(req.session.userId, 20);
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

router.get('/api/admin-stats', async (req, res) => {
    if (req.session.role !== 'SuperAdmin') {
        return res.status(403).json({ error: 'SuperAdmin access required.' });
    }

    const { data: deviceCheck } = await supabase
        .from('devices')
        .select('approved')
        .eq('user_id', req.session.userId)
        .eq('fingerprint', req.session.deviceFingerprint)
        .single();

    if (!deviceCheck?.approved) {
        return res.status(403).json({ error: 'Please register your device first.' });
    }

    try {
        const [
            { count: totalUsers },
            { count: activeUsers },
            { count: blockedUsers },
            { count: pendingDevices },
            { count: totalSessions }
        ] = await Promise.all([
            supabase.from('users').select('*', { count: 'exact', head: true }),
            supabase.from('users').select('*', { count: 'exact', head: true }).eq('status', 'active'),
            supabase.from('users').select('*', { count: 'exact', head: true }).eq('status', 'blocked'),
            supabase.from('devices').select('*', { count: 'exact', head: true }).eq('approved', false),
            supabase.from('sessions_log').select('*', { count: 'exact', head: true })
        ]);

        const since24h = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();

        const [
            { count: events24h },
            { count: fails24h },
            { data: recentEvents }
        ] = await Promise.all([
            supabase.from('audit_log').select('*', { count: 'exact', head: true }).gte('created_at', since24h),
            supabase.from('audit_log').select('*', { count: 'exact', head: true }).eq('action', 'LOGIN_FAILED').gte('created_at', since24h),
            supabase.from('audit_log').select('id, user_id, action, detail, ip, created_at').order('created_at', { ascending: false }).limit(10)
        ]);

        const { data: rolesData } = await supabase.from('users').select('role');
        const roleBreakdown = {};
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

router.post('/api/system/emergency-lockdown', async (req, res) => {
    if (req.session.role !== 'SuperAdmin') {
        return res.status(403).json({ success: false, message: 'SuperAdmin access required for this action.' });
    }
    
    try {
        const { error: dbError } = await supabase
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

router.get('/admin/remote-analytics', (req, res) => {
    if (req.session.role !== 'SuperAdmin' && req.session.role !== 'IT') {
        return res.status(403).send('Admin access required.');
    }
    res.sendFile(path.join(__dirname, '..', 'views', 'remote-analytics.html'));
});

router.get('/api/admin/remote-analytics', async (req, res) => {
    if (req.session.role !== 'SuperAdmin' && req.session.role !== 'IT') {
        return res.status(403).json({ error: 'Admin access required.' });
    }
    
    try {
        const since24h = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();

        let { data: sessions } = await supabase
            .from('sessions_log')
            .select('id, user_id, ip, browser, os, country, risk_score, device_fingerprint, login_at, vpn')
            .gte('login_at', since24h)
            .order('login_at', { ascending: false });
        
        sessions = sessions || [];

        const { data: users } = await supabase.from('users').select('id, username, role');
        const userMap = {};
        (users || []).forEach(function(u) { userMap[u.id] = u; });

        const { count: vpnCount } = await supabase
            .from('security_events')
            .select('*', { count: 'exact', head: true })
            .eq('event_type', 'VPN_DETECTED')
            .gte('created_at', since24h);

        const offHoursEvents = [];
        const offHoursUsers = {};
        
        sessions.forEach(session => {
            if (isOffHours(new Date(session.login_at))) {
                const identityContext = userMap[session.user_id] || {};
                const offHoursEntry = { 
                    ...session, 
                    username: identityContext.username || 'Unknown', 
                    details: { role: identityContext.role || 'Personnel' }, 
                    created_at: session.login_at 
                };
                offHoursEvents.push(offHoursEntry);
                if (!offHoursUsers[session.user_id]) offHoursUsers[session.user_id] = offHoursEntry;
            }
        });
        
        const totalSessions = sessions.length;
        const vpnPercent = totalSessions > 0 ? Math.round((vpnCount || 0) / totalSessions * 100) : 0;
        
        let avgRisk = 0;
        if (totalSessions > 0) {
            const sumRisk = sessions.reduce((acc, s) => acc + (s.risk_score || 0), 0);
            avgRisk = Math.round(sumRisk / totalSessions);
        }

        const uniqueCountries = new Set();
        const uniqueDevices = new Set();
        sessions.forEach(s => {
            if (s.country) uniqueCountries.add(s.country);
            if (s.device_fingerprint) uniqueDevices.add(s.device_fingerprint);
        });

        const hourlyCounts = Array(24).fill(0);
        sessions.forEach(s => {
            const observationHour = new Date(s.login_at).getUTCHours();
            hourlyCounts[observationHour]++;
        });
        const hourlyBreakdown = hourlyCounts.map((count, hour) => ({ hour, count }));

        const countryCounts = {};
        sessions.forEach(s => {
            const region = s.country || 'Unknown';
            countryCounts[region] = (countryCounts[region] || 0) + 1;
        });
        
        const topCountries = Object.keys(countryCounts)
            .map(k => ({ country: k, count: countryCounts[k] }))
            .sort((a, b) => b.count - a.count)
            .slice(0, 10);

        const networkBreakdown = { office: 0, secure_remote: 0, untrusted: 0, anonymized: 0 };
        for (const s of sessions) {
            try {
                const trustRole = await classifyNetwork(s.user_id, s.ip, s.country, false);
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

        const recentList = sessions.slice(0, 25).map(s => {
            const identity = userMap[s.user_id] || {};
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
                avgRiskScore: avgRisk,
                uniqueCountries: uniqueCountries.size,
                uniqueDevices: uniqueDevices.size
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
