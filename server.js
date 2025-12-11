require('dotenv').config();
const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const path = require('path');

const app = express();
const isProduction = process.env.NODE_ENV === 'production';

// 1. HELMET — security headers (CSP, HSTS, X-Frame-Options, etc.)
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            scriptSrcAttr: ["'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'"]
        }
    },
    crossOriginEmbedderPolicy: false,
    hsts: false
}));

// 2. HTTPS redirect in production
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

// 3. SESSION — secure cookies, SameSite strict
app.use(session({
    secret: process.env.SESSION_SECRET || 'zts-default-secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: isProduction,
        httpOnly: true,
        maxAge: 30 * 60 * 1000,
        sameSite: 'strict'
    },
    rolling: true
}));

// 4. CSRF protection
const { csrfProtection, generateCSRFToken } = require('./middleware/csrf');

// 5. Rate limiters
const { apiLimiter } = require('./middleware/rateLimiter');

// 6. HMAC request verification
const { verifyHMAC } = require('./middleware/hmacVerify');

// Route imports
const authRoutes       = require('./routes/authRoutes');
const dashboardRoutes  = require('./routes/dashboardRoutes');
const profileRoutes    = require('./routes/profileRoutes');
const mappingRoutes    = require('./routes/mappingRoutes');
const networkRoutes    = require('./routes/networkRoutes');
const monitoringRoutes = require('./routes/monitoringRoutes');
const securityPostureRoutes = require('./routes/securityPostureRoutes');
const { requireLogin } = require('./middleware/auth');
const { requireRole }  = require('./middleware/rbac');
const { flagHighRisk } = require('./middleware/riskCheck');
const { handleReAuth } = require('./middleware/stepUpAuth');

// Global middleware chain
app.use(requireLogin); // auth check first
app.use(flagHighRisk); // continuous risk check
app.use(csrfProtection); // CSRF validation on POST/PUT/DELETE
app.use(verifyHMAC); // HMAC integrity check

// CSRF token endpoint — frontend fetches this token
app.get('/api/csrf-token', function (req, res) {
    var token = generateCSRFToken(req);
    res.json({ csrfToken: token });
});

// Step-up re-authentication endpoint
app.post('/api/verify-reauth', handleReAuth);

// Apply general API rate limiter to all /api/ routes
app.use('/api', apiLimiter);

// Mount routes
app.use('/', authRoutes);
app.use('/', dashboardRoutes);
app.use('/', profileRoutes);
app.use('/', requireRole(['SuperAdmin']), mappingRoutes);
app.use('/', requireRole(['SuperAdmin']), monitoringRoutes);
app.use('/', requireRole(['SuperAdmin']), networkRoutes);
app.use('/', securityPostureRoutes);

app.get('/', (req, res) => {
    res.redirect('/dashboard');
});

app.get('/security-block', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'security-block.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`\n  ZTS - Zero Trust Security Demo`);
    console.log(`  NIST SP 800-207 Implementation`);
    console.log(`  Security Features: Helmet, Rate-Limit, CSRF, HMAC, AES-256`);
    console.log(`  Environment: ${isProduction ? 'PRODUCTION' : 'DEVELOPMENT'}`);
    console.log(`  Running on http://localhost:${PORT}\n`);
});
