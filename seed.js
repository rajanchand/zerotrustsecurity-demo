// seed.js
// create default users for the ZTS
// run once: node seed.js

var bcrypt = require('bcryptjs');
var { supabase } = require('./db');

var defaultUsers = [
    { username: 'superadmin', password: 'Super@123', role: 'SuperAdmin', email: 'admin@zts.demo', department: 'General' },
    { username: 'hruser', password: 'Hr@12345', role: 'HR', email: 'hr@zts.demo', department: 'Human Resources' },
    { username: 'finuser', password: 'Fin@12345', role: 'Finance', email: 'finance@zts.demo', department: 'Finance' },
    { username: 'ituser', password: 'It@12345', role: 'IT', email: 'it@zts.demo', department: 'Information Technology' },
    { username: 'csuser', password: 'Cs@12345', role: 'CustomerSupport', email: 'support@zts.demo', department: 'Customer Support' },
    { username: 'testuser', password: 'Test@1234', role: 'HR', email: 'test@zts.demo', department: 'Human Resources' }
];

async function seedUsers() {
    var created = 0;

    for (var user of defaultUsers) {
        // check if already exists
        var { data: existing } = await supabase
            .from('users')
            .select('id')
            .eq('username', user.username)
            .single();

        if (existing) {
            console.log('  Skipped (exists): ' + user.username);
            continue;
        }

        var hash = bcrypt.hashSync(user.password, 10);

        var { error } = await supabase.from('users').insert({
            username: user.username,
            password_hash: hash,
            role: user.role,
            email: user.email,
            department: user.department,
            status: 'active'
        });

        if (error) {
            console.log('  Error creating ' + user.username + ': ' + error.message);
        } else {
            console.log('  Created: ' + user.username + ' (' + user.role + ')');
            created++;
        }
    }

    console.log('\nDone. ' + created + ' user(s) created.');
    console.log('\nLogin credentials:');
    console.log('  superadmin / Super@123  (SuperAdmin)');
    console.log('  hruser     / Hr@12345   (HR)');
    console.log('  finuser    / Fin@12345  (Finance)');
    console.log('  ituser     / It@12345   (IT)');
    console.log('  csuser     / Cs@12345   (CustomerSupport)');
    console.log('  testuser   / Test@1234  (HR)');
}

seedUsers();
