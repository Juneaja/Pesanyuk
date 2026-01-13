const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./delivery.db');

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    role TEXT,
    name TEXT,
    address TEXT,
    phone TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    customerId INTEGER,
    driverId INTEGER DEFAULT NULL,
    items TEXT,
    address TEXT,
    status TEXT DEFAULT 'pending',
    date TEXT,
    FOREIGN KEY (customerId) REFERENCES users(id),
    FOREIGN KEY (driverId) REFERENCES users(id)
  )`);

  // Data awal admin dan driver (password: admin123/driver123, hash dengan bcrypt)
  const bcrypt = require('bcryptjs');
  const hashedAdminPass = bcrypt.hashSync('admin123', 10);
  const hashedDriverPass = bcrypt.hashSync('driver123', 10);
  db.run(`INSERT OR IGNORE INTO users (username, password, role, name, address, phone) VALUES (?, ?, ?, ?, ?, ?)`,
    ['admin', hashedAdminPass, 'admin', 'Admin', 'Office', '123456789']);
  db.run(`INSERT OR IGNORE INTO users (username, password, role, name, address, phone) VALUES (?, ?, ?, ?, ?, ?)`,
    ['driver1', hashedDriverPass, 'driver', 'Driver One', 'Warehouse', '987654321']);
});

module.exports = db;
