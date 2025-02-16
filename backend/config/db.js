const mysql = require('mysql2');

// Create a connection to MySQL
const db = mysql.createConnection({
  host: 'localhost',      // Change this if using a remote DB
  user: 'root',           // Your MySQL username
  password: '123456@Safenet',           // Your MySQL password (leave empty if none)
  database: 'signup_system' // Your database name
});

// Connect to MySQL
db.connect((err) => {
  if (err) {
    console.error('Database connection failed:', err.message);
  } else {
    console.log('Connected to MySQL database');
  }
});

module.exports = db;
