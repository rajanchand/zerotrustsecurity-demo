require('dotenv').config();

const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const path = require('path');

const app = express();
const isProduction = process.env.NODE_ENV === 'production';

// Fail-fast: require SESSION_SECRET in production
if (isProduction && (!process.env.SESSION_SECRET || process.env.SESSION_SECRET === 'zts-default-secret')) {
    console.error('FATAL: SESSION_SECRET must be set to a strong random value in production.');
    process.exit(1);
}

// 1. HELMET — set security headers (CSP, X-Frame-Options, etc.)
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com", "https://cdn.jsdelivr.net"],
            scriptSrcAttr: ["'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'"],
            upgradeInsecureRequests: null
        }
    },
    crossOriginEmbedderPolicy: false,
    hsts: isProduction ? { maxAge: 31536000, includeSubDomains: true } : false
}));

// 2. Load environment variables and trust proxies
app.set('trust proxy', 1);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// 3. SESSION — secure, HttpOnly, SameSite=Strict cookies
app.use(session({
    secret: process.env.SESSION_SECRET || 'zts-default-secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: isProduction,
        httpOnly: true,
        maxAge: 30 * 60 * 1000, // 30 minutes rolling window
        sameSite: 'strict'
    },
    rolling: true
}));

// 4. CSRF protection middleware
const { csrfProtection, generateCSRFToken } = require('./middleware/csrf');

// 5. Rate limiters
const { apiLimiter } = require('./middleware/rateLimiter');

// 6. HMAC request integrity verification
const { verifyHMAC } = require('./middleware/hmacVerify');

// Route files
const authRoutes = require('./routes/authRoutes');
const dashboardRoutes = require('./routes/dashboardRoutes');
const profileRoutes = require('./routes/profileRoutes');
const mappingRoutes = require('./routes/mappingRoutes');
const networkRoutes = require('./routes/networkRoutes');
const monitoringRoutes = require('./routes/monitoringRoutes');
const securityPostureRoutes = require('./routes/securityPostureRoutes');

// Middleware imports
const { requireLogin } = require('./middleware/auth');
const { requireRole } = require('./middleware/rbac');
const { flagHighRisk } = require('./middleware/riskCheck');
const { handleReAuth } = require('./middleware/stepUpAuth');

// ── Prometheus metrics endpoint ──
// Registered BEFORE requireLogin — Prometheus scrapes with no session.
// Blocked to external IPs in production (localhost only).
const { register } = require('./services/metricservice');
app.get('/metrics', async function (req, res) {
    var clientIP = (req.headers['x-forwarded-for'] || req.ip || '').split(',')[0].trim();
    var isLocal  = clientIP === '127.0.0.1' || clientIP === '::1' || clientIP === '::ffff:127.0.0.1' || clientIP === '';
    if (!isLocal && process.env.NODE_ENV === 'production') {
        return res.status(403).send('Forbidden');
    }
    res.set('Content-Type', register.contentType);
    res.end(await register.metrics());
});

// ── Global middleware chain ──
app.use(requireLogin);   // must be logged in
app.use(flagHighRisk);   // continuous behavioural risk check
app.use(csrfProtection); // CSRF validation on POST/PUT/DELETE
app.use(verifyHMAC);     // HMAC request integrity check

// CSRF token endpoint — frontend fetches this on page load
app.get('/api/csrf-token', function (req, res) {
    var token = generateCSRFToken(req);
    res.json({ csrfToken: token });
});

// Step-up re-authentication endpoint
app.post('/api/verify-reauth', handleReAuth);

// General API rate limiter
app.use('/api', apiLimiter);

// ── Route mounting ──
// Auth routes are public (login / logout / otp)
app.use('/', authRoutes);

// Dashboard and profile — available to all authenticated users
app.use('/', dashboardRoutes);
app.use('/', profileRoutes);

// Admin panel routes — SuperAdmin and IT both have access
// IT needs access for device management and network tooling
// HR needs access to mapping routes for user management
app.use('/', requireRole(['SuperAdmin', 'HR', 'IT']), mappingRoutes);
app.use('/', requireRole(['SuperAdmin', 'IT']), monitoringRoutes);
app.use('/', requireRole(['SuperAdmin', 'IT']), networkRoutes);

// Security posture — available to all authenticated roles
app.use('/', securityPostureRoutes);

// Root redirect
app.get('/', function (req, res) {
    res.redirect('/dashboard');
});

// Security block page (shown for high-risk sessions)
app.get('/security-block', function (req, res) {
    res.sendFile(path.join(__dirname, 'views', 'security-block.html'));
});

// Branded 404 handler — must be after all routes
app.use(function (req, res) {
    res.status(404).sendFile(path.join(__dirname, 'views', '404.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', function () {
    console.log('\n  ZTS - Zero Trust Security Demo');
    console.log('  NIST SP 800-207 Continuous Verification');
    console.log('  Security: Helmet, Rate-Limit, CSRF, HMAC, AES-256-GCM');
    console.log('  Environment: ' + (isProduction ? 'PRODUCTION' : 'DEVELOPMENT'));
    console.log('  Listening on 0.0.0.0:' + PORT + '\n');
});

// ── Global safety net ──
// Prevent a single unhandled promise rejection from crashing the process.
// PM2 will still restart on an uncaughtException, but logging here gives
// a useful stack trace in the PM2 log before it does.
process.on('unhandledRejection', function (reason, promise) {
    console.error('[FATAL] Unhandled promise rejection:', reason);
});

process.on('uncaughtException', function (err) {
    console.error('[FATAL] Uncaught exception — process will exit:', err);
    process.exit(1);
});
