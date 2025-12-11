// middleware/departmentAccess.js
// micro-segmentation: restrict resource access by department

function requireDepartment(allowedDepartments) {
    return function (req, res, next) {
        // SuperAdmin bypasses all department restrictions
        if (req.session.role === 'SuperAdmin') {
            return next();
        }

        var userDept = (req.session.department || '').toLowerCase();
        var allowed = allowedDepartments.map(function (d) { return d.toLowerCase(); });

        if (!allowed.includes(userDept)) {
            var { logSecurityEvent } = require('../services/monitorService');
            logSecurityEvent({
                event_type: 'ACCESS_DENIED',
                user_id: req.session.userId,
                username: req.session.username || 'unknown',
                ip: req.ip,
                details: {
                    reason: 'Department restriction',
                    user_department: req.session.department,
                    required_departments: allowedDepartments,
                    path: req.path
                }
            }).catch(function () { });

            return res.status(403).json({
                success: false,
                message: 'Access denied. This resource is restricted to: ' + allowedDepartments.join(', ')
            });
        }

        next();
    };
}

module.exports = { requireDepartment };
