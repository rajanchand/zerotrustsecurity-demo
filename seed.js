// seed.js
// Run: node seed.js

var bcrypt = require('bcryptjs');
var { supabase } = require('./db');

//  users with name-based usernames,  emails, with proper roles
var users = [
    {
        username: 'rajan.chand',
        password: 'Rajan@123',
        role: 'SuperAdmin',
        email: 'rajanchand48@gmail.com',
        department: 'General'
    },
    {
        username: 'bhuwan.khanal',
        password: 'Bhuwan@123',
        role: 'Admin',
        email: 'bhuwankhanal1996@gmail.com',
        department: 'General'
    },
    {
        username: 'replica.rasaili',
        password: 'replica@123',
        role: 'HR',
        email: 'replicarasaili@gmail.com',
        department: 'Human Resources'
    },
    {
        username: 'amit.thapa',
        password: 'Amit@123',
        role: 'HR',
        email: 'amit.thapa22@gmail.com',
        department: 'Human Resources'
    },
    {
        username: 'sanjay.gurung',
        password: 'Sanjay@123',
        role: 'IT',
        email: 'sanjay.gurung@techmail.com',
        department: 'Information Technology'
    },
    {
        username: 'deepa.rai',
        password: 'Deepa@123',
        role: 'IT',
        email: 'deepa.rai09@gmail.com',
        department: 'Information Technology'
    },
    {
        username: 'nisha.basnet',
        password: 'Nisha@123',
        role: 'Finance',
        email: 'nisha.basnet@yahoo.com',
        department: 'Finance'
    },
    {
        username: 'rohan.adhikari',
        password: 'Rohan@123',
        role: 'Finance',
        email: 'rohan.adhikari33@gmail.com',
        department: 'Finance'
    },
    {
        username: 'sunita.limbu',
        password: 'Sunita@123',
        role: 'CustomerSupport',
        email: 'sunita.limbu@support.com',
        department: 'Customer Support'
    }
];

async function seedUsers() {
    console.log('\n  ZTS - Seeding users...\n');
    var created = 0;

    for (var user of users) {
        var { data: existing } = await supabase
            .from('users')
            .select('id')
            .eq('username', user.username)
            .single();

        if (existing) {
            console.log('  Skipped (already exists): ' + user.username);
            continue;
        }

        var hash = bcrypt.hashSync(user.password, 10);

        var { error } = await supabase.from('users').insert({
            username: user.username,
            password_hash: hash,
            role: user.role,
            email: user.email,
            department: user.department,
            status: 'active',
            failed_attempts: 0
        });

        if (error) {
            console.log('  Error: ' + user.username + ' — ' + error.message);
        } else {
            console.log('  Created: ' + user.username + ' (' + user.role + ')');
            created++;
        }
    }

    console.log('\n  Done. ' + created + ' user(s) created.\n');
    console.log('  Login credentials:');
    console.log('  ─────────────────────────────────────────────');
    users.forEach(function (u) {
        console.log('  ' + u.username.padEnd(20) + u.password.padEnd(14) + u.role);
    });
    console.log('');
}

seedUsers();
