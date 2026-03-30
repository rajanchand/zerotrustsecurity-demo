// services/metricsService.js
const client = require('prom-client');

// Default system metrics (CPU, memory, event loop lag, etc.)
const register = new client.Registry();
client.collectDefaultMetrics({ register });

// ── Custom ZTS counters ──

const loginTotal = new client.Counter({
    name: 'zts_login_total',
    help: 'Total login attempts',
    labelNames: ['result'], // 'success' or 'failed'
    registers: [register]
});

const vpnDetected = new client.Counter({
    name: 'zts_vpn_detected_total',
    help: 'Total VPN logins detected',
    registers: [register]
});

const otpSent = new client.Counter({
    name: 'zts_otp_sent_total',
    help: 'Total OTPs sent',
    registers: [register]
});

const riskScore = new client.Gauge({
    name: 'zts_risk_score_last',
    help: 'Risk score of the most recent login',
    labelNames: ['username'],
    registers: [register]
});

const activeUsers = new client.Gauge({
    name: 'zts_active_sessions',
    help: 'Currently active user sessions',
    registers: [register]
});

module.exports = { register, loginTotal, vpnDetected, otpSent, riskScore, activeUsers };
