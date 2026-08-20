// check if password meets our requirements
// returns { valid: true/false, errors: [...] }
function validatePassword(password) {
    var errors = [];

    if (!password || password.length < 8) {
        errors.push('Password must be at least 8 characters.');
    }
    if (!/[A-Z]/.test(password)) {
        errors.push('Must include an uppercase letter.');
    }
    if (!/[a-z]/.test(password)) {
        errors.push('Must include a lowercase letter.');
    }
    if (!/[0-9]/.test(password)) {
        errors.push('Must include a number.');
    }
    if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
        errors.push('Must include a special character (e.g., !@#$%^&*).');
    }

    return {
        valid: errors.length === 0,
        errors: errors
    };
}

module.exports = { validatePassword: validatePassword };
