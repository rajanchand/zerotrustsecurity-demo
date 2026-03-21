const express = require('express');
const path = require('path');
const { addClient, getRecentEvents, getStats24h } = require('../services/monitorService');
const { supabase } = require('../db');

const router = express.Router();

router.get('/admin/live-monitoring', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'views', 'live-monitoring.html'));
});

router.get('/api/monitor/stream', (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders();

    res.write('data: {"type":"connected"}\n\n');
    addClient(res);

    const keepAlive = setInterval(() => {
        try {
            res.write('data: {"type":"ping"}\n\n');
        } catch (err) {
            clearInterval(keepAlive);
        }
    }, 20000);

    req.on('close', () => {
        clearInterval(keepAlive);
    });
});

router.get('/api/monitor/events', async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 100;
        const securityEvents = await getRecentEvents(limit);
        res.json(securityEvents);
    } catch (err) {
        res.json([]);
    }
});

router.get('/api/monitor/stats', async (req, res) => {
    try {
        const stats = await getStats24h();
        res.json(stats);
    } catch (err) {
        res.json({ total: 0, critical: 0, high: 0, login_failed: 0, blocked: 0, access_denied: 0, vpn_detected: 0, avg_risk: 0 });
    }
});

router.get('/admin/user-log', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'views', 'user-log.html'));
});

router.get('/api/admin/users/:userId/forensics', async (req, res) => {
    try {
        var userId = parseInt(req.params.userId);

        var { data: user } = await supabase
            .from('users')
            .select('id, username, email, role, department, status, failed_attempts, created_at, active_session_token, permissions')
            .eq('id', userId)
            .single();

        if (!user) {
            return res.status(404).json({ error: 'User not found.' });
        }

        var results = await Promise.all([
            supabase.from('devices').select('*').eq('user_id', userId).order('created_at', { ascending: false }),
            supabase.from('sessions_log').select('*').eq('user_id', userId).order('login_at', { ascending: false }).limit(30),
            supabase.from('audit_log').select('*').eq('user_id', userId).order('created_at', { ascending: false }).limit(100),
            supabase.from('security_events').select('*').eq('user_id', userId).order('timestamp', { ascending: false }).limit(50)
        ]);

        var devices = results[0].data || [];
        var sessions = results[1].data || [];
        var auditLogs = results[2].data || [];
        var securityEvents = results[3].data || [];

        var totalSessions = sessions.length;
        var vpnSessions = sessions.filter(function(s) { return s.vpn; }).length;

        var offHourLogins = sessions.filter(function(s) {
            var hour = new Date(s.login_at).getHours();
            return hour >= 18 || hour < 9;
        }).length;

        var lastRisk = totalSessions > 0 ? (sessions[0].risk_score || 0) : 0;
        var avgRisk = totalSessions > 0
            ? (sessions.reduce(function(sum, s) { return sum + (s.risk_score || 0); }, 0) / totalSessions).toFixed(1)
            : 0;

        res.json({
            identity: user,
            inventory: {
                devices: devices,
                sessions: sessions
            },
            info: {
                audit: auditLogs,
                security: securityEvents
            },
            report: {
                total_sessions: totalSessions,
                vpn_sessions: vpnSessions,
                off_hour_logins: offHourLogins,
                risk_summary: {
                    last_risk: lastRisk,
                    average_risk: avgRisk
                }
            }
        });
    } catch (err) {
        console.error('User detail load error:', err);
        res.status(500).json({ error: 'Failed to load user details.' });
    }
});

router.get('/api/admin/logs/all', async (req, res) => {
    try {
        const { getAllAuditLogs } = require('../services/auditService');
        const limit = parseInt(req.query.limit) || 200;
        const logs = await getAllAuditLogs(limit);
        res.json(logs);
    } catch (err) {
        res.json([]);
    }
});

module.exports = router;
