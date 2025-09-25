// server.js
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const path = require('path');
const cookieParser = require('cookie-parser');
const fs = require('fs');

const JWT_SECRET = process.env.JWT_SECRET || 'replace_this_with_a_strong_secret_in_prod';
const TOKEN_NAME = 'music_token'; // cookie name
const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'db.sqlite');

// create db file if doesn't exist
if(!fs.existsSync(DB_FILE)){
  fs.writeFileSync(DB_FILE, '');
}

const db = new Database(DB_FILE);

// Create users table if not exists
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
`);

// Prepared statements
const insertUser = db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)');
const getUserByUsername = db.prepare('SELECT id, username, password_hash FROM users WHERE username = ?');
const getUserById = db.prepare('SELECT id, username FROM users WHERE id = ?');

const app = express();

app.use(express.json());
app.use(cookieParser());

// Serve static files from public/
app.use(express.static(path.join(__dirname, 'public')));

// --- Helpers ---
function signToken(payload) {
  // expires in 7 days (adjust as needed)
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
}

function authMiddleware(req, res, next){
  const token = req.cookies[TOKEN_NAME];
  if(!token) return res.status(401).json({ error: 'unauthenticated' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = { id: payload.id, username: payload.username };
    next();
  } catch (err) {
    return res.status(401).json({ error: 'invalid_token' });
  }
}

// --- API routes ---

// Signup
app.post('/api/signup', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'username_and_password_required' });
    const existing = getUserByUsername.get(username);
    if (existing) return res.status(409).json({ error: 'username_taken' });

    const saltRounds = 10;
    const hash = await bcrypt.hash(password, saltRounds);
    const info = insertUser.run(username, hash);
    const userId = info.lastInsertRowid;

    const token = signToken({ id: userId, username });
    // set HttpOnly cookie
    res.cookie(TOKEN_NAME, token, {
      httpOnly: true,
      sameSite: 'lax',
      // secure: true, // enable in production + https
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    return res.json({ id: userId, username });
  } catch (err) {
    console.error('signup error', err);
    return res.status(500).json({ error: 'server_error' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'username_and_password_required' });

    const user = getUserByUsername.get(username);
    if (!user) return res.status(401).json({ error: 'invalid_credentials' });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'invalid_credentials' });

    const token = signToken({ id: user.id, username: user.username });
    res.cookie(TOKEN_NAME, token, {
      httpOnly: true,
      sameSite: 'lax',
      // secure: true,
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    return res.json({ id: user.id, username: user.username });
  } catch (err) {
    console.error('login error', err);
    return res.status(500).json({ error: 'server_error' });
  }
});

// Logout
app.post('/api/logout', (req, res) => {
  res.clearCookie(TOKEN_NAME, { httpOnly: true, sameSite: 'lax' });
  return res.json({ ok: true });
});

// Get current user
app.get('/api/me', authMiddleware, (req, res) => {
  const u = getUserById.get(req.user.id);
  if(!u) return res.status(404).json({ error: 'not_found' });
  return res.json({ id: u.id, username: u.username });
});

// Example protected route: save playlist (optional)
// For demonstration, we store playlists in a simple table (optional).
db.exec(`
CREATE TABLE IF NOT EXISTS playlists (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  name TEXT,
  data TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
`);

const insertPlaylist = db.prepare('INSERT INTO playlists (user_id, name, data) VALUES (?, ?, ?)');
const getPlaylistsForUser = db.prepare('SELECT id, name, data, created_at FROM playlists WHERE user_id = ? ORDER BY created_at DESC');

app.post('/api/playlists', authMiddleware, (req, res) => {
  try {
    const { name, data } = req.body || {};
    if (!data) return res.status(400).json({ error: 'data_required' });
    const info = insertPlaylist.run(req.user.id, name || 'My Playlist', JSON.stringify(data));
    return res.json({ id: info.lastInsertRowid });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'server_error' });
  }
});

app.get('/api/playlists', authMiddleware, (req, res) => {
  try {
    const rows = getPlaylistsForUser.all(req.user.id);
    // parse JSON data
    const list = rows.map(r => ({ id: r.id, name: r.name, data: JSON.parse(r.data), created_at: r.created_at }));
    return res.json(list);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'server_error' });
  }
});

// Fallback - serve index.html for SPA routing
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start
app.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT} (NODE_ENV=${process.env.NODE_ENV || 'development'})`);
});
