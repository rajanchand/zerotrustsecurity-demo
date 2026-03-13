var SLACK_WEBHOOK = process.env.SLACK_WEBHOOK_URL || '';

var ALERT_COLORS = {
    AUTHENTICATION: '#22c55e',
    VPN_ALERT: '#ef4444',
    OFF_HOURS_ALERT: '#f59e0b',
    INITIAL_ENROLLMENT: '#3b82f6',
    SECURITY_DEVIATION: '#ef4444'
};

var ALERT_TITLES = {
    AUTHENTICATION: 'User Logged In',
    VPN_ALERT: 'VPN or Unusual Location',
    OFF_HOURS_ALERT: 'Off-Hours Login',
    INITIAL_ENROLLMENT: 'New User Created',
    SECURITY_DEVIATION: 'Security Issue'
};

/**
 * Send a security alert to the Slack channel.
 */
async function sendSlackAlert(params) {
    if (!SLACK_WEBHOOK) {
        console.log('[Slack] Not configured, skipping alert');
        return { dispatched: false, failureReason: 'Slack not configured' };
    }

    var type = params.type || 'AUTHENTICATION';
    var title = ALERT_TITLES[type] || 'Security Event';
    var color = ALERT_COLORS[type] || '#64748b';
    var time = new Date().toUTCString();

    var fields = [
        { title: 'User', value: params.username || 'System', short: true },
        { title: 'Role', value: params.role || 'N/A', short: true },
        { title: 'IP', value: params.ip || 'Unknown', short: true },
        { title: 'Location', value: params.country || 'Unknown', short: true },
        { title: 'Risk', value: (params.riskScore || 0) + ' (' + (params.riskLevel || 'Low') + ')', short: true },
        { title: 'Time', value: time, short: true }
    ];

    if (params.device) {
        fields.push({ title: 'Device', value: params.device, short: true });
    }

    if (params.loginReasons) {
        fields.push({ title: 'Flags', value: params.loginReasons, short: false });
    }

    if (type === 'VPN_ALERT' && params.previousCountry) {
        fields.push({ title: 'Previous Location', value: params.previousCountry, short: true });
    }

    if (params.reason) {
        fields.push({ title: 'Details', value: params.reason, short: false });
    }

    var payload = {
        text: 'ZTS Alert - ' + title,
        attachments: [{
            color: color,
            fields: fields,
            footer: 'ZTS Admin Portal',
            ts: Math.floor(Date.now() / 1000)
        }]
    };

    try {
        var res = await fetch(SLACK_WEBHOOK, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (!res.ok) {
            var errText = await res.text();
            console.error('[Slack] Failed to send (' + res.status + '): ' + errText);
            return { dispatched: false, failureReason: 'Slack error: ' + res.status };
        }

        console.log('[Slack] Alert sent for user: ' + (params.username || 'System'));
        return { dispatched: true };
    } catch (err) {
        console.error('[Slack] Error sending alert:', err.message);
        return { dispatched: false, failureReason: err.message };
    }
}

module.exports = { sendSlackAlert };
