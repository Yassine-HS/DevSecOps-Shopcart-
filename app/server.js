const express = require('express');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
app.use(express.json());

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// FIX 4: secrets come from the environment, never from the code
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
if (!JWT_SECRET || !ADMIN_PASSWORD) {
  console.error('JWT_SECRET and ADMIN_PASSWORD must be set');
  process.exit(1);
}

function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'no token' });
  }
  try {
    req.user = jwt.verify(header.slice(7), JWT_SECRET, { algorithms: ['HS256'] });
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
  if (!email || !password || password.length < 8) {
    return res.status(400).json({ error: 'email and a password of at least 8 characters are required' });
  }
  try {
    const hash = await bcrypt.hash(password, 10);
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
  try {
    const { email, password } = req.body;
    const r = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = r.rows[0];
    if (!user || !(await bcrypt.compare(password || '', user.password_hash))) {
      return res.status(401).json({ error: 'bad credentials' });
    }
    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, {
      expiresIn: '7d',
      algorithm: 'HS256'
    });
    res.json({ token });
  } catch (e) {
    res.status(500).json({ error: 'server error' });
  }
});

// FIX 1: parameterized query, user input is never concatenated into SQL
app.get('/api/products', async (req, res) => {
  const q = typeof req.query.q === 'string' ? req.query.q : '';
  try {
    const r = await pool.query(
      'SELECT id, name, price, stock FROM products WHERE name ILIKE $1',
      [`%${q}%`]
    );
    res.json(r.rows);
  } catch (e) {
    res.status(500).json({ error: 'server error' });
  }
});

// FIX 2: prices come from the database, quantities are validated
app.post('/api/orders', auth, async (req, res) => {
  try {
    const { items, shipping_address } = req.body;
    if (!Array.isArray(items) || items.length === 0 || !shipping_address) {
      return res.status(400).json({ error: 'items and shipping_address are required' });
    }
    for (const i of items) {
      if (!Number.isInteger(i.productId) || !Number.isInteger(i.qty) || i.qty <= 0) {
        return res.status(400).json({ error: 'invalid item' });
      }
    }

    const ids = [...new Set(items.map((i) => i.productId))];
    const pr = await pool.query('SELECT id, price, stock FROM products WHERE id = ANY($1)', [ids]);
    const products = new Map(pr.rows.map((p) => [p.id, p]));

    let total = 0;
    const priced = [];
    for (const i of items) {
      const p = products.get(i.productId);
      if (!p) return res.status(400).json({ error: 'unknown product' });
      if (i.qty > p.stock) return res.status(400).json({ error: 'not enough stock' });
      total += Number(p.price) * i.qty;
      priced.push({ productId: p.id, qty: i.qty, price: Number(p.price) });
    }

    const r = await pool.query(
      'INSERT INTO orders (user_id, total, items, shipping_address) VALUES ($1, $2, $3, $4) RETURNING id, total',
      [req.user.id, total.toFixed(2), JSON.stringify(priced), shipping_address]
    );
    res.status(201).json(r.rows[0]);
  } catch (e) {
    res.status(500).json({ error: 'server error' });
  }
});

// FIX 3: an order is only visible to its owner or an admin
app.get('/api/orders/:id', auth, async (req, res) => {
  if (!/^\d+$/.test(req.params.id)) return res.status(400).json({ error: 'invalid id' });
  try {
    const r = await pool.query('SELECT * FROM orders WHERE id = $1', [req.params.id]);
    const order = r.rows[0];
    if (!order || (order.user_id !== req.user.id && req.user.role !== 'admin')) {
      return res.status(404).json({ error: 'not found' });
    }
    res.json(order);
  } catch (e) {
    res.status(500).json({ error: 'server error' });
  }
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
  const hash = await bcrypt.hash(ADMIN_PASSWORD, 10);
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