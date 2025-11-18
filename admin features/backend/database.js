const { createClient } = require('@supabase/supabase-js');

// Supabase configuration
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_KEY;

// Validate environment variables
if (!supabaseUrl || !supabaseKey) {
  console.error(' Missing Supabase configuration in environment variables');
  console.error('Please check your SUPABASE_URL and SUPABASE_SERVICE_KEY in .env file');
  process.exit(1);
}

// Create Supabase client
const supabase = createClient(supabaseUrl, supabaseKey);

// Test connection on startup
async function initializeDatabase() {
  try {
    console.log(' Testing Supabase connection...');
    
    // Test the connection by making a simple query
    const { data, error } = await supabase
      .from('users')
      .select('count')
      .limit(1);
    
    if (error) {
      // If table doesn't exist, it's okay - we'll create it later
      if (error.code === 'PGRST204') {
        console.log(' Supabase connected successfully (tables will be created automatically)');
      } else {
        throw error;
      }
    } else {
      console.log('Supabase connected successfully');
    }
    
    return true;
  } catch (error) {
    console.error(' Error connecting to Supabase:', error.message);
    console.error('Please check your Supabase credentials in .env file');
    throw error;
  }
}

// Supabase doesn't need connection pooling like Oracle
// The client handles connections automatically
async function getConnection() {
  // Supabase client is already initialized, just return it
  return supabase;
}

// Supabase doesn't need manual connection closing
async function closePool() {
  console.log(' Supabase connection closed (managed automatically)');
  // No need to close anything - Supabase handles connections automatically
}

module.exports = {
  initializeDatabase,
  getConnection,
  closePool,
  supabase // Export supabase client directly for convenience
};