const { Pool } = require('pg');
const pool = new Pool({ connectionString: "postgresql://postgres:Support98479%24%23%40@db.seeinzwhsjxmadrvvjnf.supabase.co:5432/postgres" });

async function query() {
  try {
    const res = await pool.query('SELECT sid FROM session;');
    console.log('Sessions in DB:', res.rows.map(r => r.sid));
  } catch (err) {
    console.error('Error:', err.message);
  } finally {
    pool.end();
  }
}
query();
