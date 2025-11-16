// services/geoService.js
// IP geolocation and VPN detection
// uses ip-api.com (free, no API key needed, 45 requests per minute)

var http = require('http');

// cache results to avoid repeated API calls
var geoCache = {};

// get real country and city from IP using ip-api.com
function getGeoFromIP(ip) {
    return new Promise(function (resolve) {
        // local/private IPs can't be geolocated
        if (!ip || ip === '127.0.0.1' || ip === '::1' || ip.startsWith('192.168') || ip.startsWith('10.') || ip.startsWith('172.')) {
            resolve({ country: 'Local Network', city: 'Local', isp: 'Local' });
            return;
        }

        // check cache
        if (geoCache[ip]) {
            resolve(geoCache[ip]);
            return;
        }

        var url = 'http://ip-api.com/json/' + ip + '?fields=status,country,city,isp,proxy';

        http.get(url, function (res) {
            var body = '';
            res.on('data', function (chunk) { body += chunk; });
            res.on('end', function () {
                try {
                    var data = JSON.parse(body);
                    if (data.status === 'success') {
                        var result = {
                            country: data.country || 'Unknown',
                            city: data.city || 'Unknown',
                            isp: data.isp || 'Unknown',
                            isProxy: data.proxy || false
                        };
                        geoCache[ip] = result;
                        resolve(result);
                    } else {
                        resolve({ country: 'Unknown', city: 'Unknown', isp: 'Unknown' });
                    }
                } catch (e) {
                    resolve({ country: 'Unknown', city: 'Unknown', isp: 'Unknown' });
                }
            });
        }).on('error', function () {
            resolve({ country: 'Unknown', city: 'Unknown', isp: 'Unknown' });
        });
    });
}

// simple sync version for backward compatibility
function getCountryFromIP(ip) {
    if (!ip || ip === '127.0.0.1' || ip === '::1' || ip.startsWith('192.168') || ip.startsWith('10.')) {
        return 'Local Network';
    }
    // on VPS this will initially return 'Resolving...'
    // the real location is fetched async and stored in the device record
    if (geoCache[ip]) return geoCache[ip].country;
    return 'Resolving...';
}

// check if the IP looks like a VPN
function isVPNConnection(ip) {
    if (!ip) return false;
    // check cache for proxy flag from ip-api
    if (geoCache[ip] && geoCache[ip].isProxy) return true;
    // known VPN ranges
    var vpnRanges = ['10.8.', '10.9.', '172.20.'];
    for (var i = 0; i < vpnRanges.length; i++) {
        if (ip.startsWith(vpnRanges[i])) return true;
    }
    return false;
}

// check for impossible travel
function checkImpossibleTravel(currentCountry, lastCountry, timeDiffMinutes) {
    if (!lastCountry) return false;
    if (currentCountry === lastCountry) return false;
    return timeDiffMinutes < 120;
}

module.exports = { getCountryFromIP, getGeoFromIP, isVPNConnection, checkImpossibleTravel };
