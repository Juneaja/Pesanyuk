const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const db = require('./database');

const app = express();
app.use(bodyParser.json());
app.use(express.static('public'));

const SECRET_KEY = 'your-secret-key'; // Ganti dengan key aman di produksi

function authenticateToken(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

app.post('/register', (req, res) => {
  const { username, password, name, address, phone } = req.body;
  const hashedPassword = bcrypt.hashSync(password, 10);
  db.run('INSERT INTO users (username, password, role, name, address, phone) VALUES (?, ?, ?, ?, ?, ?)',
    [username, hashedPassword, 'customer', name, address, phone], function(err) {
      if (err) return res.status(400).json({ message: 'Username sudah ada' });
      res.json({ message: 'Registrasi berhasil' });
    });
});

app.post('/login', (req, res) => {
  const { username, password, role } = req.body;
  db.get('SELECT * FROM users WHERE username = ? AND role = ?', [username, role], (err, user) => {
    if (err) return res.status(500).json({ message: 'Error database' });
    if (user && bcrypt.compareSync(password, user.password)) {
      const token = jwt.sign({ id: user.id, role: user.role }, SECRET_KEY);
      res.json({ token });
    } else {
      res.status(401).json({ message: 'Kredensial salah' });
    }
  });
});

app.post('/order', authenticateToken, (req, res) => {
  if (req.user.role !== 'customer') return res.sendStatus(403);
  const { items, address } = req.body;
  db.run('INSERT INTO orders (customerId, items, address, date) VALUES (?, ?, ?, ?)',
    [req.user.id, items, address, new Date().toISOString()], function(err) {
      if (err) return res.status(500).json({ message: 'Error database' });
      res.json({ message: 'Pesanan berhasil dibuat' });
    });
});

app.get('/orders', authenticateToken, (req, res) => {
  if (req.user.role === 'customer') {
    db.all('SELECT * FROM orders WHERE customerId = ?', [req.user.id], (err, orders) => {
      if (err) return res.status(500).json({ message: 'Error database' });
      res.json({ orders });
    });
  } else if (req.user.role === 'driver') {
    db.all('SELECT * FROM orders WHERE driverId = ?', [req.user.id], (err, orders) => {
      if (err) return res.status(500).json({ message: 'Error database' });
      res.json({ orders });
    });
  } else if (req.user.role === 'admin') {
    db.all('SELECT o.*, u.name AS customerName FROM orders o JOIN users u ON o.customerId = u.id', [], (err, orders) => {
      if (err) return res.status(500).json({ message: 'Error database' });
      db.all('SELECT * FROM users WHERE role = ?', ['driver'], (err, drivers) => {
        if (err) return res.status(500).json({ message: 'Error database' });
        res.json({ orders, drivers });
      });
    });
  }
});

app.post('/assign-driver/:orderId', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') return res.sendStatus(403);
  const { driverId } = req.body;
  db.run('UPDATE orders SET driverId = ?, status = ? WHERE id = ?', [driverId, 'assigned', req.params.orderId], function(err) {
    if (err) return res.status(500).json({ message: 'Error database' });
    res.json({ message: 'Driver assigned' });
  });
});

app.post('/update-status/:orderId', authenticateToken, (req, res) => {
  if (req.user.role !== 'driver') return res.sendStatus(403);
  const { status } = req.body;
  db.run('UPDATE orders SET status = ? WHERE id = ? AND driverId = ?', [status, req.params.orderId, req.user.id], function(err) {
    if (err) return res.status(500).json({ message: 'Error database' });
    res.json({ message: 'Status updated' });
  });
});

app.listen(3000, () => console.log('Server berjalan di port 3000'));
