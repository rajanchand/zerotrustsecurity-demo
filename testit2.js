const { supabase } = require('./db');
async function run() {
    process.env.SESSION_SECRET = 'test';
    // Let's pretend to just query what would cause a problem
    // Specifically, for drona.kc, fetch dashboard-data
    const req = {
        session: {
            role: 'IT',
            userId: 40,
            username: 'drona.kc',
            department: 'Human Resources'
        }
    };
    try {
        const { count: sessionCount } = await supabase
            .from('sessions_log')
            .select('*', { count: 'exact', head: true })
            .eq('user_id', req.session.userId);

        const { data: lastSession } = await supabase
            .from('sessions_log')
            .select('country, device_fingerprint')
            .eq('user_id', req.session.userId)
            .order('login_at', { ascending: false })
            .limit(1)
            .single();

        let isNewDevice = false;
        if (lastSession) {
            const { count: deviceCount } = await supabase
                .from('devices')
                .select('*', { count: 'exact', head: true })
                .eq('user_id', req.session.userId)
                .eq('fingerprint', lastSession.device_fingerprint);
            isNewDevice = deviceCount === 0;
        }

        console.log("Success! Session count:", sessionCount);
    } catch(e) {
        console.error("Dashboard error:", e);
    }
}
run();
