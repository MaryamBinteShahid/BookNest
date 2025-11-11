const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '.env') });
const oracledb = require('oracledb');

async function testConnection() {
    let connection;
    try {
        console.log('=== Testing Oracle Connection ===');
        console.log('User:', process.env.DB_USER);
        console.log('Connection String:', process.env.DB_CONNECTION_STRING);
        console.log('');
        
        // Check if env variables are loaded
        if (!process.env.DB_USER || !process.env.DB_CONNECTION_STRING) {
            throw new Error('.env file not loaded or missing DB variables!');
        }
        
        connection = await oracledb.getConnection({
            user: process.env.DB_USER,
            password: process.env.DB_PASSWORD,
            connectString: process.env.DB_CONNECTION_STRING
        });
        
        console.log('✓ Successfully connected to Oracle Database!');
        console.log('');
        
        const result = await connection.execute(
            `SELECT table_name FROM user_tables WHERE table_name IN ('USERS', 'OTPS')`
        );
        
        console.log('✓ Tables found:', result.rows.length);
        result.rows.forEach(row => {
            console.log('  -', row.TABLE_NAME);
        });
        
        console.log('');
        console.log('=== Connection Test Successful! ===');
        
    } catch (err) {
        console.error('✗ Connection failed!');
        console.error('Error:', err.message);
    } finally {
        if (connection) {
            await connection.close();
            console.log('Connection closed.');
        }
    }
}

testConnection();