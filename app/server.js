const express = require('express');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
app.use(express.json());

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// FLAW 4: hardcoded JWT secret and default admin password
const JWT_SECRET = 'shopcart-secret-123';

function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: 'no token' });
  try {
    req.user = jwt.verify(header.split(' ')[1], JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'invalid token' });
  }
}

function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'admin only' });
  next();
}

app.get('/health', (req, res) => res.json({ status: 'ok' }));

app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;
  const hash = await bcrypt.hash(password, 10);
  try {
    const r = await pool.query(
      'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email, role',
      [email, hash]
    );
    res.status(201).json(r.rows[0]);
  } catch (e) {
    res.status(400).json({ error: 'could not register' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const r = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
  const user = r.rows[0];
  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return res.status(401).json({ error: 'bad credentials' });
  }
  const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, {
    expiresIn: '7d'
  });
  res.json({ token });
});

// FLAW 1: SQL injection through string concatenation
app.get('/api/products', async (req, res) => {
  const q = req.query.q || '';
  try {
    const r = await pool.query(
      `SELECT id, name, price, stock FROM products WHERE name ILIKE '%${q}%'`
    );
    res.json(r.rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// FLAW 2: price is taken from the client instead of the database
app.post('/api/orders', auth, async (req, res) => {
  const { items, shipping_address } = req.body;
  const total = items.reduce((sum, i) => sum + i.price * i.qty, 0);
  const r = await pool.query(
    'INSERT INTO orders (user_id, total, items, shipping_address) VALUES ($1, $2, $3, $4) RETURNING id, total',
    [req.user.id, total, JSON.stringify(items), shipping_address]
  );
  res.status(201).json(r.rows[0]);
});

// FLAW 3: IDOR, any logged-in user can read any order by ID
app.get('/api/orders/:id', auth, async (req, res) => {
  const r = await pool.query('SELECT * FROM orders WHERE id = $1', [req.params.id]);
  if (!r.rows[0]) return res.status(404).json({ error: 'not found' });
  res.json(r.rows[0]);
});

app.get('/api/admin/users', auth, requireAdmin, async (req, res) => {
  const r = await pool.query('SELECT id, email, role FROM users');
  res.json(r.rows);
});

async function waitForDb(retries = 30) {
  for (let i = 1; i <= retries; i++) {
    try {
      await pool.query('SELECT 1');
      console.log('database ready');
      return;
    } catch (e) {
      console.log(`waiting for database (${i}/${retries})`);
      await new Promise((r) => setTimeout(r, 2000));
    }
  }
  throw new Error('database never became ready');
}

async function seedAdmin() {
  const hash = await bcrypt.hash('admin123', 10);
  await pool.query(
    `INSERT INTO users (email, password_hash, role)
     VALUES ('admin@shopcart.local', $1, 'admin')
     ON CONFLICT (email) DO NOTHING`,
    [hash]
  );
}

const PORT = 3000;
waitForDb()
  .then(seedAdmin)
  .then(() => app.listen(PORT, () => console.log(`ShopCart on :${PORT}`)))
  .catch((e) => {
    console.error('startup failed', e);
    process.exit(1);
  });