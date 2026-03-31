// routes/monitoringRoutes.js
// Live monitoring page and API — SuperAdmin only

var express = require('express');
var path = require('path');
var { addClient, getRecentEvents, getStats24h } = require('../services/monitorService');

var router = express.Router();

// serve the HTML page
router.get('/admin/live-monitoring', function (req, res) {
    res.sendFile(path.join(__dirname, '..', 'views', 'live-monitoring.html'));
});

// SSE stream — browser connects here and receives live events
router.get('/api/monitor/stream', function (req, res) {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders();

    // send a welcome ping so the browser knows it's connected
    res.write('data: {"type":"connected"}\n\n');

    // register this response as an active client
    addClient(res);

    // keep alive ping every 20 seconds
    var timer = setInterval(function () {
        try { res.write('data: {"type":"ping"}\n\n'); } catch (e) { clearInterval(timer); }
    }, 20000);

    req.on('close', function () {
        clearInterval(timer);
    });
});

// REST: return recent events for initial page load
router.get('/api/monitor/events', async function (req, res) {
    try {
        var events = await getRecentEvents(parseInt(req.query.limit) || 100);
        res.json(events);
    } catch (e) {
        res.json([]);
    }
});

// REST: 24h summary stats for the KPI cards
router.get('/api/monitor/stats', async function (req, res) {
    try {
        var stats = await getStats24h();
        res.json(stats);
    } catch (e) {
        res.json({ total: 0, critical: 0, high: 0, login_failed: 0, blocked: 0, access_denied: 0, vpn_detected: 0, avg_risk: 0 });
    }
});

// REST: user-log standalone page
router.get('/admin/user-log', function (req, res) {
    res.sendFile(path.join(__dirname, '..', 'views', 'user-log.html'));
});

// REST: user comprehensive forensics (reports, devices, sessions, risk)
router.get('/api/admin/users/:userId/forensics', async function (req, res) {
    try {
        var userId = parseInt(req.params.userId);

        // 1. User base data
        var { data: user } = await require('../db').supabase
            .from('users')
            .select('id, username, email, role, department, status, failed_attempts, created_at, active_session_token, permissions')
            .eq('id', userId)
            .single();

        if (!user) return res.status(404).json({ error: 'Identity not found' });

        // 2. Devices registry
        var { data: devices } = await require('../db').supabase
            .from('devices')
            .select('*')
            .eq('user_id', userId)
            .order('created_at', { ascending: false });

        // 3. High Fidelity Session Logs
        var { data: sessions } = await require('../db').supabase
            .from('sessions_log')
            .select('*')
            .eq('user_id', userId)
            .order('login_at', { ascending: false })
            .limit(30);

        // 4. Audit & Policy Events
        var { data: audit } = await require('../db').supabase
            .from('audit_log')
            .select('*')
            .eq('user_id', userId)
            .order('created_at', { ascending: false })
            .limit(100);
            
        // 5. Correlated Security Pulse
        var { data: secEvents } = await require('../db').supabase
            .from('security_events')
            .select('*')
            .eq('user_id', userId)
            .order('timestamp', { ascending: false })
            .limit(50);

        // 6. Aggregate Forensic Statistics
        var totalSessions = sessions ? sessions.length : 0;
        var vpnSessions = sessions ? sessions.filter(s => s.vpn).length : 0;
        
        // Off-hours: 22:00 - 06:00
        var offHourLogins = sessions ? sessions.filter(s => {
            const hour = new Date(s.login_at).getHours();
            return hour >= 22 || hour < 6;
        }).length : 0;

        var uniqueCountries = [...new Set((sessions || []).map(s => s.country ))].length;
        var uniqueIPs = [...new Set((sessions || []).map(s => s.ip))].length;

        res.json({
            identity: user,
            inventory: {
                devices: devices || [],
                sessions: sessions || []
            },
            telemetry: {
                audit: audit || [],
                security: secEvents || []
            },
            report: {
                total_sessions: totalSessions,
                vpn_sessions: vpnSessions,
                off_hour_logins: offHourLogins,
                geo_velocity: {
                    countries: uniqueCountries,
                    ips: uniqueIPs
                },
                risk_summary: {
                    avg_score: sessions && sessions.length ? (sessions.reduce((acc, s) => acc + (s.risk_score || 0), 0) / sessions.length).toFixed(1) : 0,
                    last_risk: sessions && sessions.length ? sessions[0].risk_score : 0
                }
            }
        });
    } catch (e) {
        console.error('Forensic retrieval failure:', e);
        res.status(500).json({ error: 'Forensic engine error' });
    }
});

// REST: Unified Audit Ledger for the entire platform
router.get('/api/admin/logs/all', async function (req, res) {
    try {
        const { getAllAuditLogs } = require('../services/auditService');
        const logs = await getAllAuditLogs(parseInt(req.query.limit) || 200);
        res.json(logs);
    } catch (e) {
        console.error('Audit ledger retrieval failure:', e);
        res.json([]);
    }
});

module.exports = router;
