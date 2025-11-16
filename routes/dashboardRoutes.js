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

module.exports = router;
