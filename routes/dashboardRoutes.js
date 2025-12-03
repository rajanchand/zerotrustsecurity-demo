const express = require('express');
const path = require('path');
const { supabase } = require('../db');
const { getRiskHistory } = require('../services/riskEngine');
const { getUserAuditLog } = require('../services/auditService');
const { getDeviceHealth } = require('../services/deviceService');

const router = express.Router();

const dashboardContent = {
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

router.get('/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'views', 'dashboard.html'));
});

router.get('/api/dashboard-data', async (req, res) => {
    try {
        const role = req.session.role;
        const content = dashboardContent[role] || dashboardContent.HR;

        const securityCard = { icon: 'S', title: 'My Security', description: 'View your risk score', link: '/risk' };
        const cards = content.cards.slice();
        cards.push(securityCard);

        const { count: sessionCount } = await supabase
            .from('sessions_log')
            .select('*', { count: 'exact', head: true })
            .eq('user_id', req.session.userId);

        const { data: lastSession } = await supabase
            .from('sessions_log')
            .select('country, device_fingerprint')
            .eq('user_id', req.session.userId)
            .order('login_at', { ascending: false })
            .limit(1)
            .single();

        let isNewDevice = false;
        if (lastSession) {
            const { count: deviceCount } = await supabase
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
        const currentScore = req.session.riskScore || 0;
        const currentLevel = req.session.riskLevel || 'Low';
        const factors = req.session.riskFactors || [];

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

router.get('/api/admin-stats', async (req, res) => {
    if (req.session.role !== 'SuperAdmin') {
        return res.status(403).json({ error: 'Access denied' });
    }

    // DEVICE POSTURE ENFORCEMENT
    // Check if the current device is approved
    const { data: currentDevice } = await supabase
        .from('devices')
        .select('approved')
        .eq('user_id', req.session.userId)
        .eq('fingerprint', req.session.deviceFingerprint)
        .single();

    if (!currentDevice || !currentDevice.approved) {
        return res.status(403).json({ 
            error: 'Access denied: Your device is not managed or approved by IT. Admin functions restricted.' 
        });
    }

    try {
        const { count: totalUsers } = await supabase
            .from('users').select('*', { count: 'exact', head: true });

        const { count: activeUsers } = await supabase
            .from('users').select('*', { count: 'exact', head: true })
            .eq('status', 'active');

        const { count: blockedUsers } = await supabase
            .from('users').select('*', { count: 'exact', head: true })
            .eq('status', 'blocked');

        const { count: pendingDevices } = await supabase
            .from('devices').select('*', { count: 'exact', head: true })
            .eq('approved', false);

        const since24h = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();

        const { count: events24h } = await supabase
            .from('audit_log').select('*', { count: 'exact', head: true })
            .gte('created_at', since24h);

        const { count: loginFails } = await supabase
            .from('audit_log').select('*', { count: 'exact', head: true })
            .eq('action', 'LOGIN_FAILED')
            .gte('created_at', since24h);

        const { count: totalSessions } = await supabase
            .from('sessions_log').select('*', { count: 'exact', head: true });

        const { data: recentEvents } = await supabase
            .from('audit_log')
            .select('id, user_id, action, detail, ip, created_at')
            .order('created_at', { ascending: false })
            .limit(10);

        const { data: usersData } = await supabase
            .from('users')
            .select('role, status');

        const roleCount = {};
        (usersData || []).forEach(u => {
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
