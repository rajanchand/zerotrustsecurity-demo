// services/geoService.js
// IP geolocation and VPN detection via ip-api.com

'use strict';

const http = require('http');

// In-memory cache with TTL — prevents unbounded memory growth and stale data.
// ip-api.com free tier: 45 requests/min, so caching aggressively is important.
const GEO_CACHE_TTL_MS = 30 * 60 * 1000; // 30 minutes
const geoCache = {};

// Strip IPv4-mapped IPv6 prefix (::ffff:1.2.3.4 → 1.2.3.4)
function normaliseIP(ip) {
    if (!ip) return ip;
    if (ip.startsWith('::ffff:')) return ip.slice(7);
    return ip;
}

function isPrivateIP(ip) {
    if (!ip) return true;
    const n = normaliseIP(ip);
    return (
        n === '127.0.0.1' ||
        n === '::1'        ||
        n.startsWith('192.168.') ||
        n.startsWith('10.')      ||
        /^172\.(1[6-9]|2\d|3[01])\./.test(n)
    );
}

function getGeoFromIP(ip) {
    return new Promise((resolve) => {
        const normIP = normaliseIP(ip);

        if (isPrivateIP(normIP)) {
            return resolve({ country: 'Local Network', city: 'Local', isp: 'Local', isProxy: false });
        }

        const cached = geoCache[normIP];
        if (cached && cached.expiresAt > Date.now()) {
            return resolve(cached.data);
        }

        const url = `http://ip-api.com/json/${normIP}?fields=status,country,city,isp,proxy`;

        const req = http.get(url, (res) => {
            let body = '';
            res.on('data', (chunk) => { body += chunk; });
            res.on('end', () => {
                try {
                    const data = JSON.parse(body);
                    if (data.status === 'success') {
                        const result = {
                            country: data.country  || 'Unknown',
                            city:    data.city     || 'Unknown',
                            isp:     data.isp      || 'Unknown',
                            isProxy: !!data.proxy
                        };
                        geoCache[normIP] = { data: result, expiresAt: Date.now() + GEO_CACHE_TTL_MS };
                        resolve(result);
                    } else {
                        resolve({ country: 'Unknown', city: 'Unknown', isp: 'Unknown', isProxy: false });
                    }
                } catch (e) {
                    resolve({ country: 'Unknown', city: 'Unknown', isp: 'Unknown', isProxy: false });
                }
            });
        });

        // 5-second timeout — prevent login requests from hanging if ip-api.com is unreachable
        req.setTimeout(5000, () => {
            req.destroy();
            resolve({ country: 'Unknown', city: 'Unknown', isp: 'Unknown', isProxy: false });
        });

        req.on('error', () => {
            resolve({ country: 'Unknown', city: 'Unknown', isp: 'Unknown', isProxy: false });
        });
    });
}

function getCountryFromIP(ip) {
    const normIP = normaliseIP(ip);
    if (isPrivateIP(normIP)) return 'Local Network';
    const cached = geoCache[normIP];
    if (cached && cached.expiresAt > Date.now()) return cached.data.country;
    return 'Resolving...';
}

function isVPNConnection(ip) {
    if (!ip) return false;
    const normIP = normaliseIP(ip);
    const cached = geoCache[normIP];
    if (cached && cached.expiresAt > Date.now() && cached.data.isProxy) return true;

    const vpnRanges = ['10.8.', '10.9.', '172.20.', '172.29.', '100.64.'];
    return vpnRanges.some((range) => normIP.startsWith(range));
}

function checkImpossibleTravel(currentCountry, lastCountry, timeDiffMinutes) {
    if (!lastCountry || !currentCountry) return false;
    if (currentCountry === lastCountry)   return false;
    return timeDiffMinutes < 120;
}

module.exports = { getCountryFromIP, getGeoFromIP, isVPNConnection, checkImpossibleTravel };
