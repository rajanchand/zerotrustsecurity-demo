var { logSecurityEvent } = require('../services/monitorService');

// restrict access to specific departments
// superadmin always gets through
function requireDepartmentAccess(allowedDepartments) {
    return function(req, res, next) {
        if (req.session.role === 'SuperAdmin') {
            return next();
        }

        var userDept = (req.session.department || '').toLowerCase();
        var allowed = allowedDepartments.map(function(d) { return d.toLowerCase(); });

        if (!allowed.includes(userDept)) {
            logSecurityEvent({
                event_type: 'SEGMENTATION_VIOLATION',
                user_id: req.session.userId,
                username: req.session.username || 'System',
                ip: req.ip,
                details: {
                    reason: 'Department access denied',
                    user_department: req.session.department,
                    required: allowedDepartments,
                    path: req.path
                }
            }).catch(function() {});

            return res.status(403).json({
                success: false,
                message: 'Access denied. This page is only for: ' + allowedDepartments.join(', ')
            });
        }

        next();
    };
}

module.exports = { requireDepartmentAuthorization: requireDepartmentAccess };
