// server.js
// ZTS - Zero Trust Security Demo

require('dotenv').config();
var express = require('express');
var session = require('express-session');
var path = require('path');

var app = express();

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

var authRoutes       = require('./routes/authRoutes');
var dashboardRoutes  = require('./routes/dashboardRoutes');
var profileRoutes    = require('./routes/profileRoutes');
var mappingRoutes    = require('./routes/mappingRoutes');
var networkRoutes    = require('./routes/networkRoutes');
var monitoringRoutes = require('./routes/monitoringRoutes');
var { requireLogin } = require('./middleware/auth');
var { requireRole }  = require('./middleware/rbac');
var { flagHighRisk } = require('./middleware/riskCheck');

app.use(requireLogin);
app.use(flagHighRisk);

app.use('/', authRoutes);
app.use('/', dashboardRoutes);
app.use('/', profileRoutes);
app.use('/', requireRole(['SuperAdmin']), mappingRoutes);
app.use('/', requireRole(['SuperAdmin']), monitoringRoutes);
app.use('/', networkRoutes);

app.get('/', function (req, res) {
    res.redirect('/dashboard');
});

var PORT = process.env.PORT || 3000;
app.listen(PORT, function () {
    console.log('');
    console.log('  ZTS - Zero Trust Security Demo');
    console.log('  NIST SP 800-207 Implementation');
    console.log('  Running on http://localhost:' + PORT);
    console.log('');
});
