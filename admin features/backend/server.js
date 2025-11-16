require('dotenv').config();
const express = require('express');
const app = express();
const adminRoutes = require('./adminRoutes');
const { initializeDatabase } = require('./database');
const bookRoutes = require('./bookRoutes');




app.use(express.json());


// Initialize database
initializeDatabase().catch(err => console.error(err));

// Mount routes with mock admin middleware
app.use('/admin', adminRoutes);
app.use('/books', bookRoutes);


app.listen(3000, () => console.log('Server running on port 3000'));
