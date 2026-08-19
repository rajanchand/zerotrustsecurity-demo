require('dotenv').config();
var fs = require('fs').promises;
var fsSync = require('fs');
var path = require('path');

// We will use a robust local JSON file-based database for the local demo/MSc dissertation presentation
// to avoid any cloud Supabase connection, project pause, or password issues.
var dbPath = path.join(__dirname, 'mock-db.json');

// Initialize mock database synchronously on startup to prevent boot race conditions
if (!fsSync.existsSync(dbPath)) {
    var initialData = {
        users: [
            {
                id: 1,
                username: "rajan.chand",
                password_hash: "$2a$10$qg8rizyXl6XsJvoE5yjhKeeCTnFnJ/eCw0RGdh/E32XO7ljg/A6CW", // Rajan33555@
                email: "rajanprakash.chand08@gmail.com",
                role: "SuperAdmin",
                status: "active",
                failed_attempts: 0,
                department: "IT",
                permissions: {},
                active_session_token: null,
                password_changed_at: new Date().toISOString()
            },
            {
                id: 2,
                username: "admin",
                password_hash: "$2a$10$oZXmHIchOsOYDCqX1TR8p.qFyK5n2pUKi7ZmeV0p03exTDdWQ5hyy", // ZeroTrust$#@
                email: "admin@zerotrust.local",
                role: "SuperAdmin",
                status: "active",
                failed_attempts: 0,
                department: "IT",
                permissions: {},
                active_session_token: null,
                password_changed_at: new Date().toISOString()
            }
        ],
        departments: [
            {
                id: 1,
                name: "IT",
                allowed_countries: "United Kingdom,Nepal,United States,Local Network",
                work_hours_start: 9,
                work_hours_end: 18,
                timezone: "Europe/London"
            }
        ],
        sessions_log: [],
        otp_store: [],
        risk_logs: [],
        audit_log: [],
        password_history: [],
        devices: [],
        ip_rules: [],
        security_events: [],
        trusted_locations: []
    };
    fsSync.writeFileSync(dbPath, JSON.stringify(initialData, null, 2));
}

// Auto-migrate: add any new tables to existing databases without losing data
var existingDB = JSON.parse(fsSync.readFileSync(dbPath, 'utf8'));
var requiredTables = ['users', 'departments', 'sessions_log', 'otp_store', 'risk_logs', 'audit_log', 'password_history', 'devices', 'ip_rules', 'security_events', 'trusted_locations'];
var migrated = false;
requiredTables.forEach(function(table) {
    if (!existingDB[table]) {
        existingDB[table] = [];
        migrated = true;
    }
});
if (migrated) {
    fsSync.writeFileSync(dbPath, JSON.stringify(existingDB, null, 2));
}

// Global Promise-based Mutex queue to serialize all database writes and prevent race conditions
var dbMutex = Promise.resolve();

async function readDB() {
    return dbMutex.then(async () => {
        var content = await fs.readFile(dbPath, 'utf8');
        return JSON.parse(content);
    });
}

async function writeDB(data) {
    var release;
    var nextLock = new Promise(resolve => { release = resolve; });
    var oldMutex = dbMutex;
    dbMutex = nextLock;

    try {
        await oldMutex;
        await fs.writeFile(dbPath, JSON.stringify(data, null, 2), 'utf8');
    } finally {
        release();
    }
}

class QueryBuilder {
    constructor(table) {
        this.table = table;
        this.filters = [];
        this.sortColumn = null;
        this.sortAscending = true;
        this.limitCount = null;
        this.action = 'select';
    }

    select(fields, options) {
        if (options && options.count === 'exact') {
            this.countMode = true;
            this.headOnly = !!options.head;
        }
        return this;
    }

    insert(record) {
        this.action = 'insert';
        this.record = record;
        return this;
    }

    update(fields) {
        this.action = 'update';
        this.fields = fields;
        return this;
    }

    delete() {
        this.action = 'delete';
        return this;
    }

    eq(column, value) {
        this.filters.push({ type: 'eq', column, value });
        return this;
    }

    in(column, values) {
        this.filters.push({ type: 'in', column, values: Array.isArray(values) ? values : [values] });
        return this;
    }

    gte(column, value) {
        this.filters.push({ type: 'gte', column, value });
        return this;
    }

    lte(column, value) {
        this.filters.push({ type: 'lte', column, value });
        return this;
    }

    neq(column, value) {
        this.filters.push({ type: 'neq', column, value });
        return this;
    }

    order(column, options) {
        this.sortColumn = column;
        this.sortAscending = options && options.ascending !== false;
        return this;
    }

    limit(count) {
        this.limitCount = count;
        return this;
    }

    async execute() {
        var db = await readDB();
        var rows = db[this.table] || [];

        // Apply filters
        var filteredRows = rows.filter(row => {
            return this.filters.every(f => {
                if (f.type === 'eq') {
                    return row[f.column] === f.value;
                }
                if (f.type === 'neq') {
                    return row[f.column] !== f.value;
                }
                if (f.type === 'in') {
                    return f.values.includes(row[f.column]);
                }
                if (f.type === 'gte') {
                    return row[f.column] >= f.value;
                }
                if (f.type === 'lte') {
                    return row[f.column] <= f.value;
                }
                return true;
            });
        });

        // Apply sort
        if (this.sortColumn) {
            filteredRows.sort((a, b) => {
                var valA = a[this.sortColumn];
                var valB = b[this.sortColumn];
                if (valA < valB) return this.sortAscending ? -1 : 1;
                if (valA > valB) return this.sortAscending ? 1 : -1;
                return 0;
            });
        }

        // Apply limit
        if (this.limitCount !== null) {
            filteredRows = filteredRows.slice(0, this.limitCount);
        }

        if (this.action === 'insert') {
            var newRecords = Array.isArray(this.record) ? this.record : [this.record];
            newRecords.forEach(rec => {
                rec.id = rec.id || (rows.length ? Math.max(...rows.map(r => r.id || 0)) + 1 : 1);
                rec.created_at = rec.created_at || new Date().toISOString();
                
                // Set default column values
                if (this.table === 'otp_store') {
                    if (rec.used === undefined) rec.used = false;
                }
                if (this.table === 'users') {
                    if (rec.failed_attempts === undefined) rec.failed_attempts = 0;
                    if (rec.status === undefined) rec.status = 'active';
                }
                if (this.table === 'devices') {
                    if (rec.approved === undefined) rec.approved = false;
                }
                
                rows.push(rec);
            });
            db[this.table] = rows;
            await writeDB(db);
            return { data: Array.isArray(this.record) ? newRecords : [newRecords[0]], error: null };
        }

        if (this.action === 'update') {
            var updatedRows = [];
            db[this.table] = rows.map(row => {
                var matches = this.filters.every(f => {
                    if (f.type === 'eq') return row[f.column] === f.value;
                    if (f.type === 'neq') return row[f.column] !== f.value;
                    if (f.type === 'in') return f.values.includes(row[f.column]);
                    if (f.type === 'gte') return row[f.column] >= f.value;
                    if (f.type === 'lte') return row[f.column] <= f.value;
                    return true;
                });
                if (matches) {
                    var updated = { ...row, ...this.fields };
                    updatedRows.push(updated);
                    return updated;
                }
                return row;
            });
            await writeDB(db);
            return { data: updatedRows, error: null };
        }

        if (this.action === 'delete') {
            var deletedRows = [];
            db[this.table] = rows.filter(row => {
                var matches = this.filters.every(f => {
                    if (f.type === 'eq') return row[f.column] === f.value;
                    if (f.type === 'neq') return row[f.column] !== f.value;
                    if (f.type === 'in') return f.values.includes(row[f.column]);
                    if (f.type === 'gte') return row[f.column] >= f.value;
                    if (f.type === 'lte') return row[f.column] <= f.value;
                    return true;
                });
                if (matches) {
                    deletedRows.push(row);
                    return false;
                }
                return true;
            });
            await writeDB(db);
            return { data: deletedRows, error: null };
        }

        // If this is a count query, return the count
        if (this.countMode) {
            return { data: this.headOnly ? null : filteredRows, count: filteredRows.length, error: null };
        }

        return { data: filteredRows, error: null };
    }

    async single() {
        var res = await this.execute();
        if (res.data && res.data.length > 0) {
            return { data: res.data[0], error: null };
        }
        return { data: null, error: { message: 'No rows found', code: 'PGRST116' } };
    }

    async maybeSingle() {
        var res = await this.execute();
        if (res.data && res.data.length > 0) {
            return { data: res.data[0], error: null };
        }
        return { data: null, error: null };
    }

    then(resolve, reject) {
        this.execute().then(resolve, reject);
    }
}

console.log('[ZTS] Initializing local JSON-based database for premium demo performance...');
var supabase = {
    from: function(table) {
        return new QueryBuilder(table);
    }
};

module.exports = { supabase: supabase };
