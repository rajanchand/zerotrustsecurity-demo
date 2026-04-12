// update-db.js
// makes sure the session table exists in postgres
// run this before starting the app if you havent set up the db yet

var { Pool } = require('pg');
require('dotenv').config();

var pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

async function updateDatabase() {
    console.log('[DB] Connecting to database...');

    try {
        var client = await pool.connect();
        console.log('[DB] Connected OK');

        // create session table for connect-pg-simple
        await client.query('\
            CREATE TABLE IF NOT EXISTS "session" (\
                "sid" VARCHAR NOT NULL PRIMARY KEY,\
                "sess" JSON NOT NULL,\
                "expire" TIMESTAMP(6) NOT NULL\
            );\
        ');
        console.log('[DB] Session table ready');

        // add index for session expiry cleanup
        await client.query('\
            CREATE INDEX IF NOT EXISTS "IDX_session_expire" ON "session" ("expire");\
        ');
        console.log('[DB] Session index ready');

        client.release();
        console.log('[DB] All done');
    } catch (err) {
        console.error('[DB] Error:', err.message);
    } finally {
        await pool.end();
    }
}

updateDatabase();
