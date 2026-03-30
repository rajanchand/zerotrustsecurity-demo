const { supabase } = require('./db');
async function run() {
    const userId = 40; // drona.kc
    try {
        const { count: sessionCount, error: err1 } = await supabase
            .from('sessions_log')
            .select('*', { count: 'exact', head: true })
            .eq('user_id', userId);
        if(err1) throw err1;

        const { data: lastSession, error: err2 } = await supabase
            .from('sessions_log')
            .select('country, device_fingerprint')
            .eq('user_id', userId)
            .order('login_at', { ascending: false })
            .limit(1)
            .single();
        if(err2 && err2.code !== 'PGRST116') throw err2; // handling 0 rows

        console.log("lastSession:", lastSession);

        console.log("Success");
    } catch(e) {
        console.error("ERROR:", e);
    }
}
run();
