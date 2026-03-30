// middleware/rbac.js
// role-based access control — enforced at the route level

function requireRole(allowedRoles) {
    return function (req, res, next) {
        var userRole = req.session.role;

        // SuperAdmin always passes through
        if (userRole === 'SuperAdmin') {
            return next();
        }

        if (!allowedRoles.includes(userRole)) {
            return res.status(403).send(
                '<html><body style="font-family:sans-serif;text-align:center;padding:80px">' +
                '<h1>403 — Access Denied</h1>' +
                '<p>You do not have permission to view this page.</p>' +
                '<p>Your role: <strong>' + userRole + '</strong></p>' +
                '<p>Required: <strong>' + allowedRoles.join(', ') + '</strong></p>' +
                '<a href="/dashboard">Back to Dashboard</a>' +
                '</body></html>'
            );
        }

        next();
    };
}

module.exports = { requireRole };
