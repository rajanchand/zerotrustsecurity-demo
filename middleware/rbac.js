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
                '<html><body style="font-family:sans-serif;text-align:center;padding:80px;background:#f8fafc;">' +
                '<h1 style="color:#0f172a;">403 — Access Denied</h1>' +
                '<p style="color:#64748b;">You do not have permission to view this page.</p>' +
                '<div style="margin:20px 0; background:#fff; display:inline-block; padding:20px; border-radius:12px; border:1px solid #e2e8f0; text-align:left;">' +
                '<p style="margin:0 0 10px; color:#334155;">Your role: <strong>' + userRole + '</strong></p>' +
                '<p style="margin:0; color:#334155;">Required: <strong>' + allowedRoles.join(', ') + '</strong></p>' +
                '</div><br>' +
                '<button onclick="window.location.href=\'/dashboard\'" style="padding:12px 24px; background:#3730a3; color:#fff; border:none; border-radius:8px; font-weight:700; cursor:pointer;">Return to Dashboard</button>' +
                '</body></html>'
            );
        }

        next();
    };
}

module.exports = { requireRole };
