// update-users.js
// Run: node update-users.js

var bcrypt = require('bcryptjs');
var { supabase } = require('./db');

// Map old username → new details
var renames = [
    {
        old_username: 'superadmin',
        new_username: 'rajan.chand',
        new_email: 'rajanchand48@gmail.com',
        new_role: 'SuperAdmin',
        new_department: 'General',
        new_password: 'Rajan@123'
    },
    {
        old_username: 'hruser',
        new_username: 'priya.sharma',
        new_email: 'priya.sharma@outlook.com',
        new_role: 'HR',
        new_department: 'Human Resources',
        new_password: 'Priya@123'
    },
    {
        old_username: 'ituser',
        new_username: 'sanjay.gurung',
        new_email: 'sanjay.gurung@techmail.com',
        new_role: 'IT',
        new_department: 'Information Technology',
        new_password: 'Sanjay@123'
    },
    {
        old_username: 'finuser',
        new_username: 'nisha.basnet',
        new_email: 'nisha.basnet@yahoo.com',
        new_role: 'Finance',
        new_department: 'Finance',
        new_password: 'Nisha@123'
    },
    {
        old_username: 'csuser',
        new_username: 'sunita.limbu',
        new_email: 'sunita.limbu@support.com',
        new_role: 'CustomerSupport',
        new_department: 'Customer Support',
        new_password: 'Sunita@123'
    },
    {
        old_username: 'testuser',
        new_username: 'amit.thapa',
        new_email: 'amit.thapa22@gmail.com',
        new_role: 'HR',
        new_department: 'Human Resources',
        new_password: 'Amit@123'
    }
];

// New users to add (don't exist yet)
var newUsers = [
    {
        username: 'bhuwan.khanal',
        password: 'Bhuwan@123',
        role: 'Admin',
        email: 'bhuwankhanal12@gmail.com',
        department: 'General'
    },
    {
        username: 'deepa.rai',
        password: 'Deepa@123',
        role: 'IT',
        email: 'deepa.rai09@gmail.com',
        department: 'Information Technology'
    },
    {
        username: 'rohan.adhikari',
        password: 'Rohan@123',
        role: 'Finance',
        email: 'rohan.adhikari33@gmail.com',
        department: 'Finance'
    }
];

async function run() {
    console.log('\n  ZTS - Updating users to realistic names...\n');

    // Step 1: rename existing users
    for (var r of renames) {
        var { data: existing } = await supabase
            .from('users')
            .select('id')
            .eq('username', r.old_username)
            .single();

        if (!existing) {
            console.log('  Not found (skipping): ' + r.old_username);
            continue;
        }

        var hash = bcrypt.hashSync(r.new_password, 10);

        var { error } = await supabase.from('users').update({
            username: r.new_username,
            email: r.new_email,
            role: r.new_role,
            department: r.new_department,
            password_hash: hash,
            failed_attempts: 0,
            status: 'active'
        }).eq('username', r.old_username);

        if (error) {
            console.log('  Error updating ' + r.old_username + ': ' + error.message);
        } else {
            console.log('  Updated: ' + r.old_username + ' → ' + r.new_username + ' (' + r.new_role + ')');
        }
    }

    // Step 2: add new users
    for (var u of newUsers) {
        var { data: exists } = await supabase
            .from('users')
            .select('id')
            .eq('username', u.username)
            .single();

        if (exists) {
            console.log('  Already exists: ' + u.username);
            continue;
        }

        var hash2 = bcrypt.hashSync(u.password, 10);

        var { error: err2 } = await supabase.from('users').insert({
            username: u.username,
            password_hash: hash2,
            role: u.role,
            email: u.email,
            department: u.department,
            status: 'active',
            failed_attempts: 0
        });

        if (err2) {
            console.log('  Error creating ' + u.username + ': ' + err2.message);
        } else {
            console.log('  Created: ' + u.username + ' (' + u.role + ')');
        }
    }

    console.log('\n  ✅ Done! New login credentials:\n');
    console.log('  Username               Password       Role');
    console.log('  ──────────────────────────────────────────────────');
    console.log('  rajan.chand            Rajan@123      SuperAdmin');
    console.log('  bhuwan.khanal          Bhuwan@123     Admin');
    console.log('  priya.sharma           Priya@123      HR');
    console.log('  amit.thapa             Amit@123       HR');
    console.log('  sanjay.gurung          Sanjay@123     IT');
    console.log('  deepa.rai              Deepa@123      IT');
    console.log('  nisha.basnet           Nisha@123      Finance');
    console.log('  rohan.adhikari         Rohan@123      Finance');
    console.log('  sunita.limbu           Sunita@123     CustomerSupport');
    console.log('');
}

run();
