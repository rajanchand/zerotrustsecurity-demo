// routes/dashboardRoutes.js
// main dashboard and related API endpoints

var express = require('express');
var path = require('path');
var { supabase } = require('../db');
var { getRiskHistory } = require('../services/riskEngine');
var { getUserAuditLog } = require('../services/auditService');
var { getDeviceHealth } = require('../services/deviceService');

var router = express.Router();

// role specific dashboard content
var dashboardContent = {
    SuperAdmin: {
        title: 'Super Admin Control Centre',
        description: 'Full system access. Manage users, view all logs, monitor the platform.',
        cards: [
            { icon: 'U', title: 'User Management', description: 'View and manage user accounts', link: '/mapping' },
            { icon: 'R', title: 'System Risk', description: 'Monitor risk scores across users', link: '/risk' },
            { icon: 'A', title: 'Audit Trail', description: 'Complete security event log', link: '/mapping' },
            { icon: 'D', title: 'Device Registry', description: 'Manage registered devices', link: '/register-device' }
        ]
    },
    HR: {
        title: 'HR Department Dashboard',
        description: 'Human Resources portal. Employee management tools.',
        cards: [
            { icon: 'E', title: 'Employee Records', description: 'View and manage employee data', link: '#' },
            { icon: 'L', title: 'Leave Management', description: 'Track leave requests', link: '#' },
            { icon: 'R', title: 'HR Reports', description: 'Generate department reports', link: '#' }
        ]
    },
    Finance: {
        title: 'Finance Department Dashboard',
        description: 'Financial operations and reporting tools.',
        cards: [
            { icon: 'B', title: 'Budget Tracker', description: 'Monitor departmental budgets', link: '#' },
            { icon: 'I', title: 'Invoices', description: 'Manage invoicing workflow', link: '#' },
            { icon: 'F', title: 'Financial Reports', description: 'Generate financial summaries', link: '#' }
        ]
    },
    IT: {
        title: 'IT Department Dashboard',
        description: 'Infrastructure, security, and support tools.',
        cards: [
            { icon: 'S', title: 'System Health', description: 'Monitor server status', link: '#' },
            { icon: 'T', title: 'Tickets', description: 'View support tickets', link: '#' },
            { icon: 'N', title: 'Network', description: 'Network management tools', link: '/network' }
        ]
    },
    CustomerSupport: {
        title: 'Customer Support Dashboard',
        description: 'Customer service management tools.',
        cards: [
            { icon: 'T', title: 'Open Tickets', description: 'View customer tickets', link: '#' },
            { icon: 'K', title: 'Knowledge Base', description: 'Internal support articles', link: '#' },
            { icon: 'F', title: 'Feedback', description: 'Customer feedback log', link: '#' }
        ]
    }
};

// serve dashboard page
router.get('/dashboard', function (req, res) {
    res.sendFile(path.join(__dirname, '..', 'views', 'dashboard.html'));
});

// dashboard data API
router.get('/api/dashboard-data', async function (req, res) {
    try {
        var role = req.session.role;
        var content = dashboardContent[role] || dashboardContent.HR;

        // add security card for all roles
        var securityCard = { icon: 'S', title: 'My Security', description: 'View your risk score', link: '/risk' };
        var cards = content.cards.slice();
        cards.push(securityCard);

        // get session count
        var { count: sessionCount } = await supabase
            .from('sessions_log')
            .select('*', { count: 'exact', head: true })
            .eq('user_id', req.session.userId);

        // get latest session info
        var { data: lastSession } = await supabase
            .from('sessions_log')
            .select('country, device_fingerprint')
            .eq('user_id', req.session.userId)
            .order('login_at', { ascending: false })
            .limit(1)
            .single();

        // check if device is new
        var isNewDevice = false;
        if (lastSession) {
            var { count: deviceCount } = await supabase
                .from('devices')
                .select('*', { count: 'exact', head: true })
                .eq('user_id', req.session.userId)
                .eq('fingerprint', lastSession.device_fingerprint);
            isNewDevice = deviceCount === 0;
        }

        res.json({
            user: {
                username: req.session.username,
                role: req.session.role,
                department: req.session.department
            },
            dashboard: {
                title: content.title,
                description: content.description,
                cards: cards
            },
            security: {
                riskScore: req.session.riskScore || 0,
                riskLevel: req.session.riskLevel || 'Low',
                sessionCount: sessionCount || 0,
                loginContext: {
                    country: lastSession ? lastSession.country : req.session.loginCountry || 'Unknown',
                    isNewDevice: isNewDevice
                }
            }
        });
    } catch (err) {
        console.error('Dashboard data error:', err);
        res.status(500).json({ error: 'Failed to load dashboard data' });
    }
});

// activity log API
router.get('/api/activity', async function (req, res) {
    try {
        var logs = await getUserAuditLog(req.session.userId, 20);
        res.json(logs);
    } catch (err) {
        res.json([]);
    }
});

// risk score page
router.get('/risk', function (req, res) {
    res.sendFile(path.join(__dirname, '..', 'views', 'risk.html'));
});

// risk data API
router.get('/api/risk-data', async function (req, res) {
    try {
        var history = await getRiskHistory(req.session.userId, 20);
        var currentScore = req.session.riskScore || 0;
        var currentLevel = req.session.riskLevel || 'Low';
        var factors = req.session.riskFactors || [];

        res.json({
            currentScore: currentScore,
            currentLevel: currentLevel,
            factors: factors,
            history: history
        });
    } catch (err) {
        res.json({ currentScore: 0, currentLevel: 'Low', factors: [], history: [] });
    }
});

// admin system-wide stats (SuperAdmin only)
router.get('/api/admin-stats', async function (req, res) {
    if (req.session.role !== 'SuperAdmin') {
        return res.status(403).json({ error: 'Access denied' });
    }

    try {
        // total users
        var { count: totalUsers } = await supabase
            .from('users').select('*', { count: 'exact', head: true });

        // active users
        var { count: activeUsers } = await supabase
            .from('users').select('*', { count: 'exact', head: true })
            .eq('status', 'active');

        // blocked users
        var { count: blockedUsers } = await supabase
            .from('users').select('*', { count: 'exact', head: true })
            .eq('status', 'blocked');

        // devices pending approval
        var { count: pendingDevices } = await supabase
            .from('devices').select('*', { count: 'exact', head: true })
            .eq('approved', false);

        // security events in last 24 hours
        var since24h = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();

        var { count: events24h } = await supabase
            .from('audit_log').select('*', { count: 'exact', head: true })
            .gte('created_at', since24h);

        // login failures in last 24 hours
        var { count: loginFails } = await supabase
            .from('audit_log').select('*', { count: 'exact', head: true })
            .eq('action', 'LOGIN_FAILED')
            .gte('created_at', since24h);

        // total sessions ever
        var { count: totalSessions } = await supabase
            .from('sessions_log').select('*', { count: 'exact', head: true });

        // recent security events (last 10)
        var { data: recentEvents } = await supabase
            .from('audit_log')
            .select('id, user_id, action, detail, ip, created_at')
            .order('created_at', { ascending: false })
            .limit(10);

        // users by role
        var { data: usersData } = await supabase
            .from('users')
            .select('role, status');

        var roleCount = {};
        (usersData || []).forEach(function (u) {
            roleCount[u.role] = (roleCount[u.role] || 0) + 1;
        });

        res.json({
            users: {
                total:   totalUsers   || 0,
                active:  activeUsers  || 0,
                blocked: blockedUsers || 0
            },
            devices: {
                pendingApproval: pendingDevices || 0
            },
            activity: {
                events24h:    events24h    || 0,
                loginFails24h: loginFails  || 0,
                totalSessions: totalSessions || 0
            },
            roleBreakdown: roleCount,
            recentEvents: recentEvents || []
        });

    } catch (err) {
        console.error('Admin stats error:', err);
        res.status(500).json({ error: 'Failed to load stats' });
    }
});

module.exports = router;
