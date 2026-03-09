const { supabase } = require('./db');

async function checkUsers() {
    try {
        const { data, error } = await supabase
            .from('users')
            .select('*');
        
        if (error) {
            console.error('Error fetching users:', error);
        } else {
            console.log('Users in database:', data);
            console.log('Total users:', data ? data.length : 0);
        }
    } catch (err) {
        console.error('Unexpected error:', err);
    }
    process.exit(0);
}

checkUsers();
