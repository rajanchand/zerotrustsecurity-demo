// services/geoService.js
// IP geolocation and VPN detection
// uses ip-api.com 

let geoCache = {};

// get real country and city from IP using ip-api.com
function getGeoFromIP(ip) {
    return new Promise((resolve) => {
        if (!ip || ip === '127.0.0.1' || ip === '::1' || ip.startsWith('192.168') || ip.startsWith('10.') || ip.startsWith('172.')) {
            resolve({ country: 'Local Network', city: 'Local', isp: 'Local' });
            return;
        }

        if (geoCache[ip]) {
            resolve(geoCache[ip]);
            return;
        }

        const url = `http://ip-api.com/json/${ip}?fields=status,country,city,isp,proxy`;

        http.get(url, (res) => {
            let body = '';
            res.on('data', (chunk) => { body += chunk; });
            res.on('end', () => {
                try {
                    const data = JSON.parse(body);
                    if (data.status === 'success') {
                        const result = {
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
        }).on('error', () => {
            resolve({ country: 'Unknown', city: 'Unknown', isp: 'Unknown' });
        });
    });
}

function getCountryFromIP(ip) {
    if (!ip || ip === '127.0.0.1' || ip === '::1' || ip.startsWith('192.168') || ip.startsWith('10.')) {
        return 'Local Network';
    }
    if (geoCache[ip]) return geoCache[ip].country;
    return 'Resolving...';
}

function isVPNConnection(ip) {
    if (!ip) return false;
    if (geoCache[ip] && geoCache[ip].isProxy) return true;

    const vpnRanges = ['10.8.', '10.9.', '172.20.'];
    for (let i = 0; i < vpnRanges.length; i++) {
        if (ip.startsWith(vpnRanges[i])) return true;
    }
    return false;
}

function checkImpossibleTravel(currentCountry, lastCountry, timeDiffMinutes) {
    if (!lastCountry) return false;
    if (currentCountry === lastCountry) return false;
    return timeDiffMinutes < 120;
}

module.exports = { getCountryFromIP, getGeoFromIP, isVPNConnection, checkImpossibleTravel };
