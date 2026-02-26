'use strict';

const express      = require('express');
const bcrypt       = require('bcryptjs');
const jwt          = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const Database     = require('better-sqlite3');
const path         = require('path');
const crypto       = require('crypto');

/* ── Config ───────────────────────────────────────── */
const PORT       = process.env.PORT || 3000;
const JWT_EXPIRY = '7d';
const SALT_ROUNDS = 12;

if (!process.env.JWT_SECRET) {
  console.warn('WARNING: JWT_SECRET env var not set. Sessions will be lost on restart. Set it in production!');
}
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');

/* ── Database setup ───────────────────────────────── */
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'data.db');
const db = new Database(DB_PATH);

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    email        TEXT    UNIQUE NOT NULL COLLATE NOCASE,
    username     TEXT    UNIQUE NOT NULL COLLATE NOCASE,
    password     TEXT    NOT NULL,
    created_at   TEXT    NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS settings (
    user_id    INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    start_date TEXT    NOT NULL DEFAULT (date('now')),
    cal_goal   INTEGER NOT NULL DEFAULT 2000,
    ex_goal    INTEGER NOT NULL DEFAULT 45,
    water_goal INTEGER NOT NULL DEFAULT 8
  );

  CREATE TABLE IF NOT EXISTS days (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    date    TEXT    NOT NULL,
    data    TEXT    NOT NULL DEFAULT '{}',
    PRIMARY KEY (user_id, date)
  );
`);

/* ── Prepared statements ──────────────────────────── */
const stmts = {
  findByEmail:    db.prepare('SELECT * FROM users WHERE email = ?'),
  findByUsername: db.prepare('SELECT * FROM users WHERE username = ?'),
  findById:       db.prepare('SELECT id, email, username, created_at FROM users WHERE id = ?'),
  insertUser:     db.prepare('INSERT INTO users (email, username, password) VALUES (?, ?, ?)'),
  insertSettings: db.prepare('INSERT OR IGNORE INTO settings (user_id) VALUES (?)'),
  getSettings:    db.prepare('SELECT * FROM settings WHERE user_id = ?'),
  saveSettings:   db.prepare(`
    INSERT INTO settings (user_id, start_date, cal_goal, ex_goal, water_goal)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(user_id) DO UPDATE SET
      start_date = excluded.start_date,
      cal_goal   = excluded.cal_goal,
      ex_goal    = excluded.ex_goal,
      water_goal = excluded.water_goal
  `),
  getDay:  db.prepare('SELECT data FROM days WHERE user_id = ? AND date = ?'),
  saveDay: db.prepare(`
    INSERT INTO days (user_id, date, data) VALUES (?, ?, ?)
    ON CONFLICT(user_id, date) DO UPDATE SET data = excluded.data
  `),
  getAllDays: db.prepare('SELECT date, data FROM days WHERE user_id = ? ORDER BY date'),
};

/* ── Express app ──────────────────────────────────── */
const app = express();
app.use(express.json());
app.use(cookieParser());

/* ── Auth middleware ──────────────────────────────── */
function requireAuth(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: 'Not authenticated' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.sub;
    next();
  } catch {
    res.clearCookie('token');
    res.status(401).json({ error: 'Session expired, please log in again' });
  }
}

function setAuthCookie(res, userId) {
  const token = jwt.sign({ sub: userId }, JWT_SECRET, { expiresIn: JWT_EXPIRY });
  res.cookie('token', token, {
    httpOnly: true,
    sameSite: 'strict',
    maxAge:   7 * 24 * 60 * 60 * 1000,
  });
}

/* ══════════════════════════════════════════
   AUTH ROUTES
══════════════════════════════════════════ */

/* POST /api/auth/register */
app.post('/api/auth/register', async (req, res) => {
  const { email, username, password } = req.body || {};

  if (!email || !username || !password)
    return res.status(400).json({ error: 'Email, username, and password are required' });

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    return res.status(400).json({ error: 'Invalid email address' });

  if (username.length < 3 || username.length > 30 || !/^[a-zA-Z0-9_]+$/.test(username))
    return res.status(400).json({ error: 'Username must be 3–30 characters (letters, numbers, _)' });

  if (password.length < 8)
    return res.status(400).json({ error: 'Password must be at least 8 characters' });

  if (stmts.findByEmail.get(email))
    return res.status(409).json({ error: 'An account with that email already exists' });

  if (stmts.findByUsername.get(username))
    return res.status(409).json({ error: 'That username is taken' });

  const hash = await bcrypt.hash(password, SALT_ROUNDS);
  const info = stmts.insertUser.run(email, username, hash);
  stmts.insertSettings.run(info.lastInsertRowid);

  setAuthCookie(res, info.lastInsertRowid);
  res.status(201).json({ user: { id: info.lastInsertRowid, email, username } });
});

/* POST /api/auth/login */
app.post('/api/auth/login', async (req, res) => {
  const { identifier, password } = req.body || {};
  if (!identifier || !password)
    return res.status(400).json({ error: 'Email/username and password are required' });

  const user = stmts.findByEmail.get(identifier) || stmts.findByUsername.get(identifier);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

  setAuthCookie(res, user.id);
  res.json({ user: { id: user.id, email: user.email, username: user.username } });
});

/* POST /api/auth/logout */
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ ok: true });
});

/* GET /api/auth/me */
app.get('/api/auth/me', requireAuth, (req, res) => {
  const user = stmts.findById.get(req.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ user });
});

/* ══════════════════════════════════════════
   SETTINGS ROUTES
══════════════════════════════════════════ */

/* GET /api/settings */
app.get('/api/settings', requireAuth, (req, res) => {
  let s = stmts.getSettings.get(req.userId);
  if (!s) { stmts.insertSettings.run(req.userId); s = stmts.getSettings.get(req.userId); }
  res.json(s);
});

/* PUT /api/settings */
app.put('/api/settings', requireAuth, (req, res) => {
  const { start_date, cal_goal, ex_goal, water_goal } = req.body || {};
  stmts.saveSettings.run(req.userId, start_date, cal_goal, ex_goal, water_goal);
  res.json({ ok: true });
});

/* ══════════════════════════════════════════
   DAYS ROUTES
══════════════════════════════════════════ */

/* GET /api/days/:date */
app.get('/api/days/:date', requireAuth, (req, res) => {
  const row = stmts.getDay.get(req.userId, req.params.date);
  res.json(row ? JSON.parse(row.data) : { foods: [], exercises: [], water: 0, habits: {}, done: false });
});

/* PUT /api/days/:date */
app.put('/api/days/:date', requireAuth, (req, res) => {
  stmts.saveDay.run(req.userId, req.params.date, JSON.stringify(req.body));
  res.json({ ok: true });
});

/* GET /api/days */
app.get('/api/days', requireAuth, (req, res) => {
  const rows = stmts.getAllDays.all(req.userId);
  const result = {};
  rows.forEach(r => { result[r.date] = JSON.parse(r.data); });
  res.json(result);
});

/* ══════════════════════════════════════════
   SERVE FRONTEND
══════════════════════════════════════════ */
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

/* ── Start ────────────────────────────────────────── */
app.listen(PORT, () => {
  console.log(`\n  75 Soft Tracker running at http://localhost:${PORT}\n`);
});
