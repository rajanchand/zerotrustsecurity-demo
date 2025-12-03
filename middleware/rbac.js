// middleware/rbac.js
// role-based access control

// check if user has one of the allowed roles
function requireRole(allowedRoles) {
  return function (req, res, next) {
    var userRole = req.session.role;

    if (userRole === 'SuperAdmin') {
      return next();
    }

    if (!allowedRoles.includes(userRole)) {
      return res.status(403).send(
        `<html><body style="font-family:sans-serif; text-align:center; padding:80px;">` +
        `<h1>403 - Access Denied</h1>` +
        `<p>You do not have permission to access this page.</p>` +
        `<p>Your role: <strong>${userRole}</strong></p>` +
        `<p>Required: <strong>${allowedRoles.join(', ')}</strong></p>` +
        `<a href="/dashboard">Back to Dashboard</a>` +
        `</body></html>`
      );
    }

    next();
  };
}

module.exports = { requireRole };
