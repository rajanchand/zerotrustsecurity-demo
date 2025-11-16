// routes/networkRoutes.js
// IP management and device health views

var express = require('express');
var path = require('path');
var { supabase } = require('../db');
var { logEvent } = require('../services/auditService');
var { getAllDevices } = require('../services/deviceService');

var router = express.Router();

// serve network page
router.get('/network', function (req, res) {
    res.sendFile(path.join(__dirname, '..', 'views', 'network.html'));
});

// get all IP rules
router.get('/api/network/ip-rules', async function (req, res) {
    try {
        var { data } = await supabase
            .from('ip_rules')
            .select('*, users(username)')
            .order('created_at', { ascending: false });

        var rules = (data || []).map(function (r) {
            return Object.assign({}, r, {
                created_by_name: r.users ? r.users.username : 'Unknown'
            });
        });

        res.json(rules);
    } catch (err) {
        res.json([]);
    }
});

// add IP rule (allow or block)
router.post('/api/network/ip-rules/add', async function (req, res) {
    try {
        var { ipAddress, action, reason } = req.body;

        if (!ipAddress) {
            return res.json({ success: false, message: 'IP address is required.' });
        }

        action = action || 'block';
        reason = reason || '';

        // check if rule already exists
        var { data: existing } = await supabase
            .from('ip_rules')
            .select('id')
            .eq('ip_address', ipAddress)
            .single();

        if (existing) {
            // update existing rule
            await supabase.from('ip_rules').update({
                action: action,
                reason: reason,
                created_by: req.session.userId
            }).eq('id', existing.id);

            await logEvent(req.session.userId, 'IP_RULE_UPDATED', action + ' IP: ' + ipAddress + ' - ' + reason, req.ip);
            return res.json({ success: true, message: 'IP rule updated.' });
        }

        await supabase.from('ip_rules').insert({
            ip_address: ipAddress,
            action: action,
            reason: reason,
            created_by: req.session.userId
        });

        await logEvent(req.session.userId, 'IP_RULE_ADDED', action + ' IP: ' + ipAddress + ' - ' + reason, req.ip);
        res.json({ success: true, message: 'IP rule added.' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

// delete IP rule
router.post('/api/network/ip-rules/delete', async function (req, res) {
    try {
        var ruleId = req.body.ruleId;

        var { data: rule } = await supabase.from('ip_rules').select('ip_address, action').eq('id', ruleId).single();

        await supabase.from('ip_rules').delete().eq('id', ruleId);

        if (rule) {
            await logEvent(req.session.userId, 'IP_RULE_DELETED', 'Removed ' + rule.action + ' rule for: ' + rule.ip_address, req.ip);
        }

        res.json({ success: true, message: 'IP rule removed.' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

// device health overview (all devices across all users)
router.get('/api/network/device-health', async function (req, res) {
    try {
        var devices = await getAllDevices();
        var total = devices.length;
        var approved = devices.filter(function (d) { return d.approved; }).length;
        var pending = total - approved;

        res.json({
            total: total,
            approved: approved,
            pending: pending,
            healthScore: total > 0 ? Math.round((approved / total) * 100) : 100,
            devices: devices
        });
    } catch (err) {
        res.json({ total: 0, approved: 0, pending: 0, healthScore: 100, devices: [] });
    }
});

module.exports = router;
