require('dotenv').config();

var express = require('express');
var session = require('express-session');
var helmet = require('helmet');
var path = require('path');
var crypto = require('crypto');

var app = express();
var isProduction = process.env.NODE_ENV === 'production';

// make sure session secret is set in production
if (isProduction && (!process.env.SESSION_SECRET || process.env.SESSION_SECRET === 'zts-default-secret')) {
    console.error('ERROR: Session secret is missing. Set SESSION_SECRET in your .env file.');
    process.exit(1);
}

// security headers using helmet
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            // Note: 'unsafe-inline' is required because demo HTML templates use inline <script> blocks.
            // In production, these should be moved to external .js files and use nonce-based CSP.
            scriptSrc: ["'self'", "'unsafe-inline'"],
            // styleSrc needs 'unsafe-inline' for inline styles used in the demo HTML templates
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'", process.env.GRAFANA_URL || "'self'"].filter(function(v, i, a) { return a.indexOf(v) === i; }),
            frameSrc: ["'self'", process.env.GRAFANA_URL || "'self'"].filter(function(v, i, a) { return a.indexOf(v) === i; }),
            upgradeInsecureRequests: isProduction ? [] : null
        }
    },
    crossOriginEmbedderPolicy: false,
    hsts: isProduction ? { maxAge: 31536000, includeSubDomains: true } : false
}));

// trust proxy for cloudflare
app.set('trust proxy', 1);

// body parsing + static files
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// add a unique id to each request for tracking
app.use(function(req, res, next) {
    req.correlationId = crypto.randomUUID();
    res.setHeader('X-Correlation-ID', req.correlationId);
    next();
});

// no caching for security pages
app.use(function(req, res, next) {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
    res.setHeader('Pragma', 'no-cache');
    next();
});

// session config (postgres backed via connect-pg-simple)
var sessionOptions = {
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
};

if (process.env.DATABASE_URL) {
    var pgSession = require('connect-pg-simple')(session);
    var pg = require('pg');
    var pgPool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
    sessionOptions.store = new pgSession({
        pool: pgPool,
        tableName: 'session'
    });
} else {
    if (isProduction) {
        console.error('WARNING: DATABASE_URL is missing. Postgres session store is required for stable production. Falling back to MemoryStore.');
    } else {
        console.warn('WARNING: DATABASE_URL not set. Falling back to MemoryStore for sessions.');
    }
}

app.use(session(sessionOptions));

// middleware
var { csrfProtection, generateCSRFToken } = require('./middleware/csrf');
var { apiLimiter } = require('./middleware/rateLimiter');
var { verifyHMAC } = require('./middleware/hmacVerify');

// dev-only request logger (does not log session IDs or sensitive data)
if (!isProduction) {
    app.use(function(req, res, next) {
        if (req.path.startsWith('/api/')) {
            console.log('[REQ] ' + req.method + ' ' + req.path);
        }
        next();
    });
}

// routes
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
var { getClientIP } = require('./services/ipService');

// prometheus metrics (only from localhost in prod)
var { register } = require('./services/metricservice');
app.get('/metrics', async function(req, res) {
    var ip = getClientIP(req);
    var isLocal = ['127.0.0.1', '::1', '::ffff:127.0.0.1', ''].includes(ip);

    if (!isLocal && isProduction) {
        return res.status(403).send('Access denied.');
    }
    res.set('Content-Type', register.contentType);
    res.end(await register.metrics());
});

// rate limit on api routes
app.use('/api', apiLimiter);

// csrf token setup
app.use(csrfProtection);
app.get('/api/csrf-token', function(req, res) {
    var token = generateCSRFToken(req);
    res.json({ csrfToken: token });
});

// auth routes go before requireLogin so login page is accessible
app.use('/', authRoutes);

// security block page needs to be before requireLogin too
// otherwise high risk users get stuck in a redirect loop
app.get('/security-block', function(req, res) {
    res.sendFile(path.join(__dirname, 'views', 'security-block.html'));
});

// everything below here requires login
app.use(requireLogin);
app.use(flagHighRisk);
app.use(verifyHMAC);

// re-auth endpoint for sensitive actions
app.post('/api/verify-reauth', handleReAuth);

// logged in user routes
app.use('/', dashboardRoutes);
app.use('/', profileRoutes);

// role restricted routes
app.use('/', requireRole(['SuperAdmin', 'HR', 'IT']), mappingRoutes);
app.use('/', requireRole(['SuperAdmin', 'IT']), monitoringRoutes);
app.use('/', requireRole(['SuperAdmin', 'IT']), networkRoutes);
app.use('/', securityPostureRoutes);

// home page just goes to dashboard
app.get('/', function(req, res) {
    res.redirect('/dashboard');
});

// 404 page
app.use(function(req, res) {
    res.status(404).sendFile(path.join(__dirname, 'views', '404.html'));
});

// start the server
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

// error handling
process.on('unhandledRejection', function(reason) {
    console.error('Unhandled error:', reason);
});

process.on('uncaughtException', function(err) {
    console.error('Fatal error:', err);
    process.exit(1);
});

// graceful shutdown on SIGTERM and SIGINT (ctrl+c)
function shutdownServer() {
    console.log('Shutting down server...');
    server.close(function() {
        console.log('Server stopped.');
        process.exit(0);
    });
    setTimeout(function() { process.exit(1); }, 10000);
}

process.on('SIGTERM', shutdownServer);
process.on('SIGINT', shutdownServer);
