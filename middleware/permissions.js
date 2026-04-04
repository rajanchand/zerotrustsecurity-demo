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

        if (permissions[permName] === true) {
            return next();
        }

        // Determine response type safely — req.headers.accept may be absent
        var acceptHeader = req.headers && req.headers.accept ? req.headers.accept : '';
        var isJSON = req.xhr || acceptHeader.indexOf('json') > -1;

        if (isJSON) {
            return res.status(403).json({
                success: false,
                message: 'Access denied: missing permission (' + permName + ').'
            });
        }

        res.status(403).send('Access Denied: Missing Permission (' + permName + ')');
    };
}

module.exports = { requirePermission };
