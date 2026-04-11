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

    // Build a simple text message instead of a fancy table
    var msg = 'User: ' + (params.username || 'System') + 
              ', Role: ' + (params.role || 'N/A') + 
              ', IP: ' + (params.ip || 'Unknown') + 
              ', Location: ' + (params.country || 'Unknown') + 
              ', Risk: ' + (params.riskScore || 0) + ' (' + (params.riskLevel || 'Low') + ')' +
              ', Time: ' + time;

    if (params.device) {
        msg += ', Device: ' + params.device;
    }

    if (params.loginReasons) {
        msg += ', Flags: ' + params.loginReasons;
    }

    if (type === 'VPN_ALERT' && params.previousCountry) {
        msg += ', Previous Location: ' + params.previousCountry;
    }

    if (params.reason) {
        msg += ', Details: ' + params.reason;
    }

    var payload = {
        text: 'ZTS Alert (' + title + ')\n' + msg
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
