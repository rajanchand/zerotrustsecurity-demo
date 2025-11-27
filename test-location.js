const { createClient } = require('@supabase/supabase-js');
const UAParser = require('ua-parser-js');
require('dotenv').config();

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);
const { registerDevice } = require('./services/deviceService');
const { getGeoFromIP } = require('./services/geoService');

async function test() {
    const { data: user } = await supabase.from('users').select('id, username').eq('username', 'nisha.basnet').single();
    if (!user) return console.log('user not found');
    
    // Simulate what login route does to register device
    const deviceResult = await registerDevice(user.id, {
        fingerprint: 'test_fingerprint_2',
        browser: 'Unknown',
        os: 'Unknown',
        ip: '104.28.21.1',
        country: 'United States'
    });
    console.log('registerDevice result:', deviceResult);
    
    // Check if device is approved
    const { data: dev } = await supabase.from('devices').select('approved').eq('id', deviceResult.device.id).single();
    console.log('device approved status in db:', dev.approved);
    
    // approve it manually
    await supabase.from('devices').update({approved: true}).eq('id', deviceResult.device.id);
    
    // output final status
    const { data: finalDev } = await supabase.from('devices').select('approved').eq('id', deviceResult.device.id).single();
    console.log('device final status in db:', finalDev.approved);
    
    console.log('Try logging in now!');
}
test();
