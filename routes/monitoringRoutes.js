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

// REST: user comprehensive details
router.get('/api/admin/users/:userId/details', async function (req, res) {
    try {
        var userId = parseInt(req.params.userId);

        // 1. User base data
        var { data: user } = await require('../db').supabase
            .from('users')
            .select('id, username, email, role, department, status, failed_attempts, created_at, active_session_token')
            .eq('id', userId)
            .single();

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // 2. Devices
        var { data: devices } = await require('../db').supabase
            .from('devices')
            .select('*')
            .eq('user_id', userId)
            .order('created_at', { ascending: false });

        // 3. Sessions Logs
        var { data: sessions } = await require('../db').supabase
            .from('sessions_log')
            .select('*')
            .eq('user_id', userId)
            .order('login_at', { ascending: false })
            .limit(20);

        // 4. Audit events
        var { data: audit } = await require('../db').supabase
            .from('audit_log')
            .select('*')
            .eq('user_id', userId)
            .order('created_at', { ascending: false })
            .limit(10);

        // Compute online status
        var isOnline = false;
        if (user.active_session_token && sessions && sessions.length > 0) {
            var lastLoginMs = new Date(sessions[0].login_at).getTime();
            // simple heuristic: if they have a session token and logged in recently
            isOnline = true; 
        }

        res.json({
            user: user,
            isOnline: isOnline,
            devices: devices || [],
            sessions: sessions || [],
            audit: audit || []
        });
    } catch (e) {
        console.error('Error fetching user details:', e);
        res.status(500).json({ error: 'Failed to fetch user details' });
    }
});

module.exports = router;
