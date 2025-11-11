const oracledb = require('oracledb');

oracledb.outFormat = oracledb.OUT_FORMAT_OBJECT;
oracledb.autoCommit = true;

const dbConfig = {
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    connectString: process.env.DB_CONNECTION_STRING,
    poolMin: 2,
    poolMax: 10,
    poolIncrement: 2
};

let pool;

async function initializeDatabase() {
    try {
        pool = await oracledb.createPool(dbConfig);
        console.log('Oracle Database pool created successfully');
    } catch (err) {
        console.error('Error creating database pool:', err);
        throw err;
    }
}

async function getConnection() {
    try {
        return await pool.getConnection();
    } catch (err) {
        console.error('Error getting database connection:', err);
        throw err;
    }
}

async function closePool() {
    try {
        await pool.close(10);
        console.log('Database pool closed');
    } catch (err) {
        console.error('Error closing database pool:', err);
    }
}

module.exports = {
    initializeDatabase,
    getConnection,
    closePool
};