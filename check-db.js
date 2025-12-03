const { supabase } = require('./db');

async function checkTables() {
    console.log("Checking Supabase Tables...");
    const tables = ['users', 'departments', 'devices', 'sessions_log', 'otp_store', 'risk_logs', 'audit_log', 'ip_rules', 'security_events'];
    
    for (let table of tables) {
        const { data, error } = await supabase.from(table).select('*').limit(1);
        if (error) {
            console.log(`❌ Table '${table}' check failed: ${error.message}`);
        } else {
            console.log(`✅ Table '${table}' exists.`);
        }
    }
}

checkTables();
