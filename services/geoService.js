var http = require('http');
var https = require('https');


// Cache geo lookups for 30 minutes
var CACHE_TTL = 30 * 60 * 1000;
var geoCache = {};

// strip ipv6 prefix from ipv4-mapped addresses
function cleanIP(ip) {
    if (!ip) return ip;
    return ip.startsWith('::ffff:') ? ip.slice(7) : ip;
}

// check for local/private ips
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

// look up location for an ip using ip-api.com
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

        // Look up the IP securely over HTTPS
        var url = 'https://ipwho.is/' + clean;

        var req = https.get(url, function (res) {
            var body = '';
            res.on('data', function (chunk) { body += chunk; });
            res.on('end', function () {
                try {
                    var result = JSON.parse(body);
                    if (result.success) {
                        var geo = {
                            country: result.country || 'Unknown',
                            city: result.city || 'Unknown',
                            isp: (result.connection && result.connection.isp) || 'Unknown',
                            isProxy: !!(result.security && (result.security.proxy || result.security.vpn))
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

// get country from cache, returns 'Unknown' if not cached
function getCountryFromIP(ip) {
    var clean = cleanIP(ip);
    if (isLocalIP(clean)) return 'Local Network';
    var cached = geoCache[clean];
    if (cached && cached.expiresAt > Date.now()) return cached.data.country;
    return 'Unknown';
}

// check if the ip is likely a vpn or proxy
function isVPNConnection(ip) {
    if (!ip) return false;
    var clean = cleanIP(ip);
    var cached = geoCache[clean];

    if (cached && cached.expiresAt > Date.now() && cached.data.isProxy) return true;

    // Known VPN IP ranges
    var vpnRanges = ['10.8.', '10.9.', '172.20.', '172.29.', '100.64.'];
    return vpnRanges.some(function (range) { return clean.startsWith(range); });
}

// flag impossible travel (two countries in under 2 hours)
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
