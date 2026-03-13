var client = require('prom-client');

// Prometheus metrics registry
var registry = new client.Registry();

// Collect default Node.js metrics
client.collectDefaultMetrics({ register: registry });

// Login attempts (success/failure)
var loginTotal = new client.Counter({
    name: 'zts_login_attempts_total',
    help: 'Total login attempts by outcome',
    labelNames: ['outcome'],
    registers: [registry]
});

// VPN detections
var vpnDetected = new client.Counter({
    name: 'zts_vpn_detected_total',
    help: 'Number of VPN connections detected',
    registers: [registry]
});

// OTP codes sent
var otpSent = new client.Counter({
    name: 'zts_otp_sent_total',
    help: 'Number of OTP codes sent',
    registers: [registry]
});

// Latest risk score per user
var riskScore = new client.Gauge({
    name: 'zts_risk_score_latest',
    help: 'Latest risk score for a user',
    labelNames: ['user'],
    registers: [registry]
});

// Active sessions count
var activeUsers = new client.Gauge({
    name: 'zts_active_sessions',
    help: 'Number of active sessions',
    registers: [registry]
});

module.exports = {
    register: registry,
    loginTotal: loginTotal,
    vpnDetected: vpnDetected,
    otpSent: otpSent,
    riskScore: riskScore,
    activeUsers: activeUsers
};
