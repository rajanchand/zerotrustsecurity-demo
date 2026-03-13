/**
 * Middleware: check if a user has a specific permission.
 * SuperAdmin always passes. Other roles need the permission set in their profile.
 */
function requirePermission(permissionName) {
    return function(req, res, next) {
        // SuperAdmin can do everything
        if (req.session.role === 'SuperAdmin') {
            return next();
        }

        var userPermissions = req.session.permissions || {};

        if (userPermissions[permissionName] === true) {
            return next();
        }

        // Check if it's an API request
        var isApiRequest = req.xhr || (req.headers?.accept || '').includes('json');

        if (isApiRequest) {
            return res.status(403).json({
                success: false,
                message: 'You do not have permission for this action.'
            });
        }

        res.status(403).send('You do not have permission for this action.');
    };
}

module.exports = { requirePermission: requirePermission };
