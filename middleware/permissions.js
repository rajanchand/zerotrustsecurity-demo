// middleware/permissions.js
// Granular permission check middleware for Zero Trust Access Control.
// Checks req.session.permissions (JSONB from DB) for specific access rights.

function requirePermission(permName) {
    return function (req, res, next) {
        // SuperAdmin always has all permissions
        if (req.session.role === 'SuperAdmin') {
            return next();
        }

        var permissions = req.session.permissions || {};

        // If the specific permission is explicitly true, allow it.
        // If not, return 403 Forbidden.
        if (permissions[permName] === true) {
            return next();
        }

        console.log('[PERMISSIONS] Access Denied for ' + (req.session.username || 'unknown') + ' on ' + req.path + ' (missing: ' + permName + ')');
        
        if (req.xhr || req.headers.accept.indexOf('json') > -1) {
            return res.status(403).json({
                success: false,
                message: 'Access denied: You do not have the required permission (' + permName + ') to perform this action.'
            });
        }
        
        res.status(403).send('Access Denied: Missing Permission (' + permName + ')');
    };
}

module.exports = { requirePermission };
