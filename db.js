// db.js
// Supabase client for the ZTS app
// All database operations go through this module

require('dotenv').config();
var { createClient } = require('@supabase/supabase-js');

var supabaseUrl = process.env.SUPABASE_URL;
var supabaseKey = process.env.SUPABASE_KEY;

if (!supabaseUrl || !supabaseKey || supabaseUrl.includes('your-project')) {
    console.error('ERROR: Supabase credentials not set in .env file.');
    console.error('Please add your SUPABASE_URL and SUPABASE_KEY.');
    process.exit(1);
}

var supabase = createClient(supabaseUrl, supabaseKey);

module.exports = { supabase };
