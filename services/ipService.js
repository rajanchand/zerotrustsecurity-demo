// services/ipService.js
// Centralized client IP address parsing utility for ZTS

function getClientIP(req) {
    if (!req) return '127.0.0.1';

    // CF-Connecting-IP is set by Cloudflare and is the most trusted client IP header
    // X-Forwarded-For contains a comma-separated list of proxy IPs, first is actual client
    // X-Real-IP is passed by reverse proxies like Nginx
    var ipHeader = req.headers['cf-connecting-ip'] || 
                   req.headers['x-forwarded-for'] || 
                   req.headers['x-real-ip'] || 
                   req.ip || 
                   '127.0.0.1';

    return ipHeader.split(',')[0].trim().replace('::ffff:', '');
}

module.exports = { getClientIP: getClientIP };
