var { supabase } = require('../db');

// Office/corporate IPs from environment variable
var CORPORATE_IPS = (process.env.CORPORATE_IPS || '')
    .split(',')
    .map(function(s) { return s.trim(); })
    .filter(Boolean);

// Network trust levels
var TRUST_TIERS = {
    INSTITUTIONAL: { tier: 'INSTITUTIONAL', label: 'Office Network', riskModifier: -10, color: '#16a34a' },
    SECURE_REMOTE: { tier: 'SECURE_REMOTE', label: 'Trusted Remote', riskModifier: -15, color: '#3b82f6' },
    ANONYMIZED:    { tier: 'ANONYMIZED',    label: 'VPN/Proxy', riskModifier: 0, color: '#f59e0b' },
    UNTRUSTED:     { tier: 'UNTRUSTED',     label: 'Unknown Network', riskModifier: 0, color: '#64748b' }
};

/**
 * Check if an IP is in the corporate IP list.
 */
function isCorporateIP(ip) {
    if (!ip || CORPORATE_IPS.length === 0) return false;

    for (var i = 0; i < CORPORATE_IPS.length; i++) {
        var rule = CORPORATE_IPS[i];
        if (rule.includes('/')) {
            var parts = rule.split('/');
            var prefix = parts[0];
            var bits = parseInt(parts[1]);
            var bytes = Math.floor(bits / 8);

            var ipPart = ip.split('.').slice(0, bytes).join('.');
            var rulePart = prefix.split('.').slice(0, bytes).join('.');

            if (ipPart === rulePart) return true;
        } else if (ip === rule) {
            return true;
        }
    }
    return false;
}

/**
 * Classify the trust level of a network connection.
 * Returns { tier, label, riskModifier, color }
 */
async function classifyNetwork(userId, ip, country, isVPN) {
    // VPN/proxy detected
    if (isVPN) {
        return Object.assign({}, TRUST_TIERS.ANONYMIZED);
    }

    // Corporate IP match
    if (isCorporateIP(ip)) {
        return Object.assign({}, TRUST_TIERS.INSTITUTIONAL);
    }

    // Local/private network
    if (
        ['127.0.0.1', '::1'].indexOf(ip) !== -1 ||
        ip.startsWith('192.168.') ||
        ip.startsWith('10.') ||
        /^172\.(1[6-9]|2\d|3[0-1])\./.test(ip) ||
        ip.startsWith('::ffff:192.168.') ||
        ip.startsWith('::ffff:10.') ||
        ip.startsWith('::ffff:127.')
    ) {
        return Object.assign({}, TRUST_TIERS.SECURE_REMOTE, { label: 'Local Network' });
    }

    // Check trusted locations in database
    try {
        var { data: ipMatch } = await supabase
            .from('trusted_locations')
            .select('label')
            .eq('user_id', userId)
            .eq('ip_address', ip)
            .eq('status', 'approved')
            .maybeSingle();

        if (ipMatch) {
            return Object.assign({}, TRUST_TIERS.SECURE_REMOTE, { label: ipMatch.label || 'Home Network' });
        }

        if (country) {
            var { data: countryMatch } = await supabase
                .from('trusted_locations')
                .select('label')
                .eq('user_id', userId)
                .eq('country', country)
                .eq('status', 'approved')
                .maybeSingle();

            if (countryMatch) {
                return Object.assign({}, TRUST_TIERS.SECURE_REMOTE, { label: countryMatch.label || 'Trusted Country' });
            }
        }
    } catch (err) {
        // Database error - default to untrusted
    }

    return Object.assign({}, TRUST_TIERS.UNTRUSTED);
}

module.exports = {
    classifyNetwork: classifyNetwork,
    TRUST_TIERS: TRUST_TIERS
};
