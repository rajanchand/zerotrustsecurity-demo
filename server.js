require('dotenv').config();

const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const path = require('path');

const app = express();
const isProduction = process.env.NODE_ENV === 'production';

// 1. HELMET — set security headers (CSP, X-Frame-Options, etc.)
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            scriptSrcAttr: ["'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'"],
            upgradeInsecureRequests: null
        }
    },
    crossOriginEmbedderPolicy: false,
    hsts: false
}));

// 2. Force HTTPS in production (behind a proxy like nginx)
if (isProduction) {
    app.use(function (req, res, next) {
        if (req.headers['x-forwarded-proto'] !== 'https') {
            return res.redirect('https://' + req.headers.host + req.url);
        }
        next();
    });
}

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
app.use('/', requireRole(['SuperAdmin', 'IT']), mappingRoutes);
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

const PORT = process.env.PORT || 3000;
app.listen(PORT, function () {
    console.log('\n  ZTS - Zero Trust Security Demo');
    console.log('  NIST SP 800-207 Implementation');
    console.log('  Security: Helmet, Rate-Limit, CSRF, HMAC, AES-256');
    console.log('  Environment: ' + (isProduction ? 'PRODUCTION' : 'DEVELOPMENT'));
    console.log('  Running on http://localhost:' + PORT + '\n');
});


