var express = require('express');
var path = require('path');
var { supabase } = require('../db');
var { logEvent } = require('../services/auditService');
var { getAllDevices } = require('../services/deviceService');

var router = express.Router();

// serve network management page
router.get('/network', function(req, res) {
    res.sendFile(path.join(__dirname, '..', 'views', 'network.html'));
});

// get all ip rules
router.get('/api/network/ip-rules', async function(req, res) {
    if (req.session.highRisk) {
        return res.status(403).json({ error: 'Access blocked: your risk score is too high.' });
    }

    try {
        var { data: rules } = await supabase
            .from('ip_rules')
            .select('*, users(username)')
            .order('created_at', { ascending: false });

        var formatted = (rules || []).map(function(rule) {
            return {
                id: rule.id,
                ip_address: rule.ip_address,
                action: rule.action,
                reason: rule.reason,
                created_by: rule.created_by,
                created_at: rule.created_at,
                created_by_name: rule.users ? rule.users.username : 'System'
            };
        });

        res.json(formatted);
    } catch (err) {
        res.json([]);
    }
});

// add or update an ip rule
router.post('/api/network/ip-rules/add', async function(req, res) {
    if (req.session.highRisk) {
        return res.status(403).json({ success: false, message: 'Access blocked: your risk score is too high.' });
    }

    try {
        var ipAddress = req.body.ipAddress;
        var action = req.body.action || 'block';
        var reason = req.body.reason || '';

        if (!ipAddress) {
            return res.status(400).json({ success: false, message: 'IP address is required.' });
        }

        var { data: existing } = await supabase
            .from('ip_rules')
            .select('id')
            .eq('ip_address', ipAddress)
            .single();

        if (existing) {
            await supabase.from('ip_rules').update({
                action: action,
                reason: reason,
                created_by: req.session.userId
            }).eq('id', existing.id);

            await logEvent(req.session.userId, 'NETWORK_POLICY_MODIFIED', 'Updated ' + action + ' rule for ' + ipAddress + ': ' + reason, req.ip);
            return res.json({ success: true, message: 'Rule updated.' });
        }

        await supabase.from('ip_rules').insert({
            ip_address: ipAddress,
            action: action,
            reason: reason,
            created_by: req.session.userId
        });

        await logEvent(req.session.userId, 'NETWORK_POLICY_ESTABLISHED', 'Created ' + action + ' rule for ' + ipAddress + ': ' + reason, req.ip);
        res.json({ success: true, message: 'Rule created.' });
    } catch (err) {
        console.error('Network rule error:', err);
        res.status(500).json({ success: false, message: 'Failed to create rule.' });
    }
});

// delete an ip rule
router.post('/api/network/ip-rules/delete', async function(req, res) {
    if (req.session.highRisk) {
        return res.status(403).json({ success: false, message: 'Access blocked: your risk score is too high.' });
    }

    try {
        var ruleId = req.body.ruleId;
        var { data: rule } = await supabase.from('ip_rules').select('ip_address, action').eq('id', ruleId).single();

        await supabase.from('ip_rules').delete().eq('id', ruleId);

        if (rule) {
            await logEvent(req.session.userId, 'NETWORK_POLICY_RESCINDED', 'Deleted ' + rule.action + ' rule for ' + rule.ip_address, req.ip);
        }

        res.json({ success: true, message: 'Rule deleted.' });
    } catch (err) {
        console.error('Network rule delete error:', err);
        res.status(500).json({ success: false, message: 'Failed to delete rule.' });
    }
});

// device health overview
router.get('/api/network/device-health', async function(req, res) {
    if (req.session.highRisk) {
        return res.status(403).json({ error: 'Access blocked: your risk score is too high.' });
    }

    try {
        var devices = await getAllDevices();
        var total = devices.length;
        var approved = devices.filter(function(d) { return d.approved; }).length;

        res.json({
            total: total,
            approved: approved,
            pending: total - approved,
            healthScore: total > 0 ? Math.round((approved / total) * 100) : 100,
            devices: devices
        });
    } catch (err) {
        console.error('Device health check error:', err);
        res.json({ total: 0, approved: 0, pending: 0, healthScore: 100, devices: [] });
    }
});

module.exports = router;
