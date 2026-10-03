const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'safevault-dev-secret-change-me';

app.use(express.json());

// Security headers (basic hardening, suggested by Copilot)
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Content-Security-Policy', "default-src 'self'");
  next();
});

// Request logger
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// ===== Database (parameterized queries prevent SQL injection) =====
const db = new sqlite3.Database(':memory:');
db.serialize(() => {
  db.run(`CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user'
  )`);
  db.run(`CREATE TABLE secrets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    body TEXT NOT NULL
  )`);
});

// Promise helpers for sqlite3
function dbGet(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => (err ? reject(err) : resolve(row)));
  });
}
function dbAll(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => (err ? reject(err) : resolve(rows)));
  });
}
function dbRun(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) reject(err);
      else resolve({ id: this.lastID, changes: this.changes });
    });
  });
}
// ===== Input validation (Copilot-generated, reviewed) =====
function validateUsername(u) {
  return typeof u === 'string' && /^[a-zA-Z0-9_]{3,30}$/.test(u);
}
function validatePassword(p) {
  return typeof p === 'string' && p.length >= 8 && p.length <= 128;
}
function validateSecret(title, body) {
  return (
    typeof title === 'string' && title.trim().length >= 1 && title.length <= 100 &&
    typeof body === 'string' && body.trim().length >= 1 && body.length <= 2000
  );
}
// XSS prevention: escape HTML on output
function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// ===== Auth: JWT + RBAC (Copilot-assisted) =====
function signToken(user) {
  return jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
}
function requireAuth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Missing token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}
function requireRole(role) {
  return (req, res, next) => {
    if (!req.user || req.user.role !== role) {
      return res.status(403).json({ error: 'Forbidden: admin only' });
    }
    next();
  };
}
// ===== Routes =====

// POST /register - Copilot scaffolded bcrypt hashing; I added validation + parameterized INSERT
app.post('/register', async (req, res) => {
  try {
    const { username, password, role } = req.body || {};
    if (!validateUsername(username)) return res.status(400).json({ error: 'Invalid username (3-30 alnum/_)' });
    if (!validatePassword(password)) return res.status(400).json({ error: 'Invalid password (min 8 chars)' });
    const safeRole = role === 'admin' ? 'admin' : 'user';
    const hash = await bcrypt.hash(password, 10);
    // Parameterized query: prevents SQL injection (never string-concatenate input)
    const r = await dbRun('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)', [username, hash, safeRole]);
    res.status(201).json({ id: r.id, username, role: safeRole });
  } catch (e) {
    if (String(e.message).includes('UNIQUE')) return res.status(409).json({ error: 'Username taken' });
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /login - parameterized SELECT + bcrypt.compare + JWT
app.post('/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!validateUsername(username) || typeof password !== 'string') {
    return res.status(400).json({ error: 'Invalid credentials format' });
  }
  const user = await dbGet('SELECT * FROM users WHERE username = ?', [username]);
  if (!user) return res.status(401).json({ error: 'Invalid username or password' });
  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: 'Invalid username or password' });
  res.json({ token: signToken(user), role: user.role });
});

// GET /secrets - owner sees own; admin sees all (RBAC)
app.get('/secrets', requireAuth, async (req, res) => {
  let rows;
  if (req.user.role === 'admin') {
    rows = await dbAll('SELECT id, owner_id, title, body FROM secrets ORDER BY id', []);
  } else {
    rows = await dbAll('SELECT id, owner_id, title, body FROM secrets WHERE owner_id = ? ORDER BY id', [req.user.id]);
  }
  // Escape output to prevent stored XSS when rendered in a browser
  res.json(rows.map((r) => ({ id: r.id, owner_id: r.owner_id, title: escapeHtml(r.title), body: escapeHtml(r.body) })));
});

// POST /secrets - validated + parameterized INSERT
app.post('/secrets', requireAuth, async (req, res) => {
  const { title, body } = req.body || {};
  if (!validateSecret(title, body)) return res.status(400).json({ error: 'Invalid title/body' });
  const r = await dbRun('INSERT INTO secrets (owner_id, title, body) VALUES (?, ?, ?)', [req.user.id, title.trim(), body.trim()]);
  res.status(201).json({ id: r.id });
});

// GET /admin/users - RBAC admin-only demo
app.get('/admin/users', requireAuth, requireRole('admin'), async (req, res) => {
  const rows = await dbAll('SELECT id, username, role FROM users ORDER BY id', []);
  res.json(rows);
});

app.get('/', (req, res) => {
  res.json({ message: 'SafeVault running', endpoints: ['POST /register', 'POST /login', 'GET /secrets', 'POST /secrets', 'GET /admin/users'] });
});

if (require.main === module) {
  app.listen(PORT, () => console.log(`SafeVault on port ${PORT}`));
}

module.exports = app;
