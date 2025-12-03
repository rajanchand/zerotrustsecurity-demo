require('dotenv').config();
const express = require('express');
const session = require('express-session');
const path = require('path');

const app = express();

app.set('trust proxy', true);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
    secret: process.env.SESSION_SECRET || 'zts-default-secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false,
        httpOnly: true,
        maxAge: 30 * 60 * 1000
    },
    rolling: true
}));

const authRoutes       = require('./routes/authRoutes');
const dashboardRoutes  = require('./routes/dashboardRoutes');
const profileRoutes    = require('./routes/profileRoutes');
const mappingRoutes    = require('./routes/mappingRoutes');
const networkRoutes    = require('./routes/networkRoutes');
const monitoringRoutes = require('./routes/monitoringRoutes');
const { requireLogin } = require('./middleware/auth');
const { requireRole }  = require('./middleware/rbac');
const { flagHighRisk } = require('./middleware/riskCheck');

app.use(requireLogin);
app.use(flagHighRisk);

app.use('/', authRoutes);
app.use('/', dashboardRoutes);
app.use('/', profileRoutes);
app.use('/', requireRole(['SuperAdmin']), mappingRoutes);
app.use('/', requireRole(['SuperAdmin']), monitoringRoutes);
app.use('/', networkRoutes);

app.get('/', (req, res) => {
    res.redirect('/dashboard');
});

app.get('/security-block', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'security-block.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`\n  ZTS - Zero Trust Security Demo\n  NIST SP 800-207 Implementation\n  Running on http://localhost:${PORT}\n`);
});
