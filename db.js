require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');

// Database connection settings
var dbUrl = process.env.SUPABASE_URL;
var dbKey = process.env.SUPABASE_KEY;

if (!dbUrl || !dbKey || dbUrl.includes('your-project')) {
    console.error('[Error] Database settings are missing.');
    console.error('Please set SUPABASE_URL and SUPABASE_KEY in your .env file.');
    process.exit(1);
}

var supabase = createClient(dbUrl, dbKey);

module.exports = { supabase };
