var http = require('http');

// Cache geo lookups for 30 minutes
var CACHE_TTL = 30 * 60 * 1000;
var geoCache = {};

/**
 * IPv6-mapped IPv4 addresses (e.g., "::ffff:1.2.3.4" -> "1.2.3.4").
 */
function cleanIP(ip) {
    if (!ip) return ip;
    return ip.startsWith('::ffff:') ? ip.slice(7) : ip;
}

/**
 * Check if an IP is a local/private network address.
 */
function isLocalIP(ip) {
    if (!ip) return true;
    var clean = cleanIP(ip);
    return (
        clean === '127.0.0.1' ||
        clean === '::1' ||
        clean.startsWith('192.168.') ||
        clean.startsWith('10.') ||
        /^172\.(1[6-9]|2\d|3[01])\./.test(clean)
    );
}

/**
 *  country, city, ISP, and proxy status for an IP address.
 *  ip-api.com .
 */
function getGeoFromIP(ip) {
    return new Promise(function (resolve) {
        var clean = cleanIP(ip);

        // Local IPs don't need lookup
        if (isLocalIP(clean)) {
            return resolve({
                country: 'Local Network',
                city: 'Private',
                isp: 'Local',
                isProxy: false
            });
        }

        // Check cache first
        var cached = geoCache[clean];
        if (cached && cached.expiresAt > Date.now()) {
            return resolve(cached.data);
        }

        // Look up the IP
        var url = 'http://ip-api.com/json/' + clean + '?fields=status,country,city,isp,proxy';

        var req = http.get(url, function (res) {
            var body = '';
            res.on('data', function (chunk) { body += chunk; });
            res.on('end', function () {
                try {
                    var result = JSON.parse(body);
                    if (result.status === 'success') {
                        var geo = {
                            country: result.country || 'Unknown',
                            city: result.city || 'Unknown',
                            isp: result.isp || 'Unknown',
                            isProxy: !!result.proxy
                        };
                        geoCache[clean] = {
                            data: geo,
                            expiresAt: Date.now() + CACHE_TTL
                        };
                        resolve(geo);
                    } else {
                        resolve({ country: 'Unknown', city: 'Unknown', isp: 'Unknown', isProxy: false });
                    }
                } catch (err) {
                    resolve({ country: 'Unknown', city: 'Unknown', isp: 'Unknown', isProxy: false });
                }
            });
        });

        req.setTimeout(5000, function () {
            req.destroy();
            resolve({ country: 'Unknown', city: 'Unknown', isp: 'Unknown', isProxy: false });
        });

        req.on('error', function () {
            resolve({ country: 'Unknown', city: 'Unknown', isp: 'Unknown', isProxy: false });
        });
    });
}

/**
 * Get the country for an IP from cache. Returns 'Unknown' if not cached.
 */
function getCountryFromIP(ip) {
    var clean = cleanIP(ip);
    if (isLocalIP(clean)) return 'Local Network';
    var cached = geoCache[clean];
    if (cached && cached.expiresAt > Date.now()) return cached.data.country;
    return 'Unknown';
}

/**
 * Check if an IP address looks like it's from a VPN or proxy.
 */
function isVPNConnection(ip) {
    if (!ip) return false;
    var clean = cleanIP(ip);
    var cached = geoCache[clean];

    if (cached && cached.expiresAt > Date.now() && cached.data.isProxy) return true;

    // Known VPN IP ranges
    var vpnRanges = ['10.8.', '10.9.', '172.20.', '172.29.', '100.64.'];
    return vpnRanges.some(function (range) { return clean.startsWith(range); });
}

/**
 * Check for impossible travel: same user logging in from two countries
 * within 2 hours (120 minutes).
 */
function checkImpossibleTravel(currentCountry, previousCountry, minutesBetween) {
    if (!previousCountry || !currentCountry) return false;
    if (currentCountry === previousCountry) return false;
    return minutesBetween < 120;
}

// Clean up expired cache entries every 15 minutes
setInterval(function () {
    var now = Date.now();
    Object.keys(geoCache).forEach(function (key) {
        if (geoCache[key].expiresAt < now) {
            delete geoCache[key];
        }
    });
}, 15 * 60 * 1000).unref();

module.exports = {
    getCountryFromIP: getCountryFromIP,
    getGeoFromIP: getGeoFromIP,
    isVPNConnection: isVPNConnection,
    checkImpossibleTravel: checkImpossibleTravel
};
