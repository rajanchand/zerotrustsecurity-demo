// server.js
// ZTS - Zero Trust Security Demo
// main entry point

require('dotenv').config();
var express = require('express');
var session = require('express-session');
var path = require('path');

var app = express();

// trust proxy when behind Nginx on VPS
app.set('trust proxy', true);

// middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// session setup
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

// import route files
var authRoutes = require('./routes/authRoutes');
var dashboardRoutes = require('./routes/dashboardRoutes');
var profileRoutes = require('./routes/profileRoutes');
var mappingRoutes = require('./routes/mappingRoutes');
var networkRoutes = require('./routes/networkRoutes');
var { requireLogin } = require('./middleware/auth');
var { requireRole } = require('./middleware/rbac');
var { flagHighRisk } = require('./middleware/riskCheck');

// apply middleware
app.use(requireLogin);
app.use(flagHighRisk);

// mount routes
app.use('/', authRoutes);
app.use('/', dashboardRoutes);
app.use('/', profileRoutes);
app.use('/', requireRole(['SuperAdmin']), mappingRoutes);
app.use('/', networkRoutes);

// home redirect
app.get('/', function (req, res) {
  res.redirect('/dashboard');
});

// start server
var PORT = process.env.PORT || 3000;
app.listen(PORT, function () {
  console.log('');
  console.log('  ZTS - Zero Trust Security Demo');
  console.log('  NIST SP 800-207 Implementation');
  console.log('  Running on http://localhost:' + PORT);
  console.log('');
});
