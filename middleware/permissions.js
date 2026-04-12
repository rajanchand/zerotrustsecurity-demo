// check if user has a specific permission
// superadmin can do everything, others need the permission set
function requirePermission(permissionName) {
    return function(req, res, next) {
        if (req.session.role === 'SuperAdmin') {
            return next();
        }

        var userPermissions = req.session.permissions || {};

        if (userPermissions[permissionName] === true) {
            return next();
        }

        // check if its an api or page request
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
