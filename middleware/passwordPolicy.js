// middleware/passwordPolicy.js
// Password strength enforcement per NIST SP 800-63B guidelines.

function validatePassword(password) {
    var errors = [];

    if (!password || password.length < 12) {
        errors.push('Password must be at least 12 characters long.');
    }
    if (!/[A-Z]/.test(password)) {
        errors.push('Password must contain at least one uppercase letter.');
    }
    if (!/[a-z]/.test(password)) {
        errors.push('Password must contain at least one lowercase letter.');
    }
    if (!/[0-9]/.test(password)) {
        errors.push('Password must contain at least one number.');
    }
    if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
        errors.push('Password must contain at least one special character (!@#$%^&* etc).');
    }

    return {
        valid: errors.length === 0,
        errors: errors
    };
}

module.exports = { validatePassword };
