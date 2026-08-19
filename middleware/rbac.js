// check if user role is allowed for this route
// superadmin always gets through
function requireRole(allowedRoles) {
    return function(req, res, next) {
        var userRole = req.session.role;

        if (userRole === 'SuperAdmin') {
            return next();
        }

        if (!allowedRoles.includes(userRole)) {
            if (req.path.startsWith('/api/') || (req.headers.accept && req.headers.accept.includes('application/json'))) {
                return res.status(403).json({
                    success: false,
                    error: 'Access denied. Insufficient permissions.',
                    requiredRoles: allowedRoles,
                    currentRole: userRole || 'None'
                });
            }
            return res.status(403).send(
                '<!DOCTYPE html>' +
                '<html lang="en">' +
                '<head>' +
                    '<meta charset="UTF-8">' +
                    '<title>Access Denied - ZTS</title>' +
                    '<style>' +
                        'body { font-family: "Inter", system-ui, sans-serif; text-align: center; padding: 100px 20px; background: #fafafa; color: #333; margin: 0; }' +
                        '.box { max-width: 480px; margin: 0 auto; background: #fff; padding: 48px; border-radius: 12px; border: 1px solid #e0e0e0; }' +
                        'h1 { font-size: 20px; font-weight: 700; margin-bottom: 12px; color: #dc2626; }' +
                        'p { color: #666; font-size: 15px; margin-bottom: 24px; }' +
                        '.info { text-align: left; background: #f9f9f9; padding: 20px; border-radius: 8px; margin-bottom: 24px; font-size: 13px; border: 1px solid #eee; }' +
                        '.info-row { margin-bottom: 8px; display: flex; justify-content: space-between; }' +
                        '.info-row strong { color: #333; }' +
                        '.info-row span { color: #888; }' +
                        '.btn { background: #333; color: #fff; border: none; padding: 12px 24px; border-radius: 8px; font-size: 14px; font-weight: 600; cursor: pointer; }' +
                        '.btn:hover { background: #555; }' +
                    '</style>' +
                '</head>' +
                '<body>' +
                    '<div class="box">' +
                        '<h1>Access Denied</h1>' +
                        '<p>You do not have permission to view this page.</p>' +
                        '<div class="info">' +
                            '<div class="info-row"><strong>Your Role</strong> <span>' + (userRole || 'None') + '</span></div>' +
                            '<div class="info-row"><strong>Required Role</strong> <span>' + allowedRoles.join(', ') + '</span></div>' +
                        '</div>' +
                        '<button class="btn" onclick="window.location.href=\'/dashboard\'">Go to Dashboard</button>' +
                    '</div>' +
                '</body>' +
                '</html>'
            );
        }

        next();
    };
}

module.exports = { requireRole: requireRole };
