CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'customer'
);

CREATE TABLE products (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  price NUMERIC(10,2) NOT NULL,
  stock INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE orders (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id),
  total NUMERIC(10,2) NOT NULL,
  items JSONB NOT NULL,
  shipping_address TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT NOW()
);

INSERT INTO products (name, price, stock) VALUES
  ('Wireless Mouse', 25.00, 50),
  ('Mechanical Keyboard', 90.00, 20),
  ('USB-C Hub', 40.00, 30),
  ('27in Monitor', 220.00, 10);
