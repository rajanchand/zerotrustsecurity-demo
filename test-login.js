const http = require('http');

function postMap(path, data, cookie) {
    return new Promise((resolve) => {
        const req = http.request({
            hostname: 'localhost', port: 3000, path: path, method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Cookie': cookie || ''
            }
        }, res => {
            let body = '';
            res.on('data', c => body += c);
            res.on('end', () => resolve({ body: JSON.parse(body), headers: res.headers, status: res.statusCode }));
        });
        req.write(JSON.stringify(data));
        req.end();
    });
}
function getMap(path, cookie) {
    return new Promise((resolve) => {
        const req = http.request({
            hostname: 'localhost', port: 3000, path: path, method: 'GET',
            headers: { 'Cookie': cookie || '' }
        }, res => {
            let body = '';
            res.on('data', c => body += c);
            res.on('end', () => resolve({ body, headers: res.headers, status: res.statusCode }));
        });
        req.end();
    });
}

(async () => {
    let res = await postMap('/login', {username: 'rajan.chand', password: 'Password123!', fingerprint: 'fp-1234'}, '');
    console.log('[LOGIN]', res.status, res.body);
    let cookie = res.headers['set-cookie'] ? res.headers['set-cookie'][0].split(';')[0] : '';
    console.log('[COOKIE]', cookie);

    // Get OTP from DB using Supabase or just let it fail and see session loss...
    // Actually we can just hit /verify-otp with wrong code. If session works, it returns {"success":false,"message":"Invalid OTP code."}
    let res2 = await postMap('/verify-otp', {code: '000000'}, cookie);
    console.log('[OTP]', res2.status, res2.body);

    let res3 = await getMap('/api/dashboard-data', cookie);
    console.log('[DASH-API]', res3.status, res3.headers.location);
})();
