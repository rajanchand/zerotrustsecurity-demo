require('dotenv').config();

var express = require('express');
var session = require('express-session');
var helmet = require('helmet');
var path = require('path');
var crypto = require('crypto');

// Create the app
var app = express();
var isProduction = process.env.NODE_ENV === 'production';

// Check session secret in production
if (isProduction && (!process.env.SESSION_SECRET || process.env.SESSION_SECRET === 'zts-default-secret')) {
    console.error('ERROR: Session secret is missing. Set SESSION_SECRET in your .env file.');
    process.exit(1);
}

// Security headers
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com", "https://cdn.jsdelivr.net"],
            scriptSrcAttr: ["'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'", process.env.GRAFANA_URL || "*"],
            frameSrc: ["'self'", process.env.GRAFANA_URL || "*"],
            upgradeInsecureRequests: null
        }
    },
    crossOriginEmbedderPolicy: false,
    hsts: isProduction ? { maxAge: 31536000, includeSubDomains: true } : false
}));

// Trust proxy (for Cloudflare)
app.set('trust proxy', 1);

// Body parsing and static files
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Add a unique ID to each request for tracking
app.use(function(req, res, next) {
    req.correlationId = crypto.randomUUID();
    res.setHeader('X-Correlation-ID', req.correlationId);
    next();
});

// Disable caching for security
app.use(function(req, res, next) {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
    res.setHeader('Pragma', 'no-cache');
    next();
});

// Session setup
app.use(session({
    secret: process.env.SESSION_SECRET || 'zts-default-secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: isProduction,
        httpOnly: true,
        maxAge: 30 * 60 * 1000, // 30 mins
        sameSite: 'strict'
    },
    rolling: true
}));

// Middleware imports
var { csrfProtection, generateCSRFToken } = require('./middleware/csrf');
var { apiLimiter } = require('./middleware/rateLimiter');
var { verifyHMAC } = require('./middleware/hmacVerify');

// Route imports
var authRoutes = require('./routes/authRoutes');
var dashboardRoutes = require('./routes/dashboardRoutes');
var profileRoutes = require('./routes/profileRoutes');
var mappingRoutes = require('./routes/mappingRoutes');
var networkRoutes = require('./routes/networkRoutes');
var monitoringRoutes = require('./routes/monitoringRoutes');
var securityPostureRoutes = require('./routes/securityPostureRoutes');

var { requireLogin } = require('./middleware/auth');
var { requireRole } = require('./middleware/rbac');
var { flagHighRisk } = require('./middleware/riskCheck');
var { handleReAuth } = require('./middleware/stepUpAuth');

// Metrics endpoint (only accessible from localhost in production)
var { register } = require('./services/metricservice');
app.get('/metrics', async function(req, res) {
    var ip = (req.headers['x-forwarded-for'] || req.ip || '').split(',')[0].trim();
    var isLocal = ['127.0.0.1', '::1', '::ffff:127.0.0.1', ''].includes(ip);

    if (!isLocal && isProduction) {
        return res.status(403).send('Access denied.');
    }
    res.set('Content-Type', register.contentType);
    res.end(await register.metrics());
});

// Apply security middleware to all routes below
app.use(requireLogin);
app.use(flagHighRisk);
app.use(csrfProtection);
app.use(verifyHMAC);

// CSRF token endpoint
app.get('/api/csrf-token', function(req, res) {
    var token = generateCSRFToken(req);
    res.json({ csrfToken: token });
});

// Re-auth and rate limiting
app.post('/api/verify-reauth', handleReAuth);
app.use('/api', apiLimiter);

// Routes - open to all logged-in users
app.use('/', authRoutes);
app.use('/', dashboardRoutes);
app.use('/', profileRoutes);

// Routes - restricted by role
app.use('/', requireRole(['SuperAdmin', 'HR', 'IT']), mappingRoutes);
app.use('/', requireRole(['SuperAdmin', 'IT']), monitoringRoutes);
app.use('/', requireRole(['SuperAdmin', 'IT']), networkRoutes);
app.use('/', securityPostureRoutes);

// Home page redirect
app.get('/', function(req, res) {
    res.redirect('/dashboard');
});

// Security block page
app.get('/security-block', function(req, res) {
    res.sendFile(path.join(__dirname, 'views', 'security-block.html'));
});

// 404 page
app.use(function(req, res) {
    res.status(404).sendFile(path.join(__dirname, 'views', '404.html'));
});

// --- Server Start ---

var PORT = process.env.PORT || 3000;
var server = app.listen(PORT, '0.0.0.0', function() {
    console.log('\n================================');
    console.log('  ZTS Server');
    console.log('================================');
    console.log('  Status : Running');
    console.log('  Port   : ' + PORT);
    console.log('  Mode   : ' + (isProduction ? 'Production' : 'Development'));
    console.log('--------------------------------');
    console.log('  Server is ready.\n');
});

// --- Error Handling ---

process.on('unhandledRejection', function(reason) {
    console.error('Unhandled error:', reason);
});

process.on('uncaughtException', function(err) {
    console.error('Fatal error:', err);
    process.exit(1);
});

// Graceful shutdown
process.on('SIGTERM', function() {
    console.log('Shutting down server...');
    server.close(function() {
        console.log('Server stopped.');
        process.exit(0);
    });
    setTimeout(function() { process.exit(1); }, 10000);
});
