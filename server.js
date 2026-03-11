const express = require('express');
const http = require('http');
const { WebSocketServer } = require('ws');
const cors = require('cors');
const crypto = require('crypto');
const Database = require('better-sqlite3');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });
const PORT = process.env.PORT || 3000;

// ==================== DATABASE ====================
const dbPath = process.env.DB_PATH || path.join(__dirname, 'data.db');
const db = new Database(dbPath);
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS tokens (
    token TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    expires_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    from_user_id TEXT NOT NULL,
    from_username TEXT NOT NULL,
    to_user_id TEXT NOT NULL,
    to_username TEXT NOT NULL,
    domain TEXT NOT NULL,
    session_data TEXT NOT NULL,
    duration_label TEXT DEFAULT 'unlimited',
    expires_at TEXT,
    revoked INTEGER DEFAULT 0,
    delivered INTEGER DEFAULT 0,
    applied INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
  );
`);

const q = {
  userByName: db.prepare('SELECT * FROM users WHERE username = ? COLLATE NOCASE'),
  userById: db.prepare('SELECT * FROM users WHERE id = ?'),
  createUser: db.prepare('INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)'),
  createToken: db.prepare('INSERT INTO tokens (token, user_id, expires_at) VALUES (?, ?, ?)'),
  getToken: db.prepare("SELECT * FROM tokens WHERE token = ? AND expires_at > datetime('now')"),
  deleteToken: db.prepare('DELETE FROM tokens WHERE token = ?'),
  cleanTokens: db.prepare("DELETE FROM tokens WHERE expires_at < datetime('now')"),

  createSession: db.prepare('INSERT INTO sessions (id, from_user_id, from_username, to_user_id, to_username, domain, session_data, duration_label, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'),

  getInbox: db.prepare("SELECT id, from_username, domain, duration_label, expires_at, revoked, applied, created_at FROM sessions WHERE to_user_id = ? AND revoked = 0 AND (expires_at IS NULL OR expires_at > datetime('now')) ORDER BY created_at DESC"),
  getSent: db.prepare("SELECT id, to_username, domain, duration_label, expires_at, revoked, applied, created_at FROM sessions WHERE from_user_id = ? ORDER BY created_at DESC LIMIT 100"),
  getSession: db.prepare('SELECT * FROM sessions WHERE id = ?'),
  markDelivered: db.prepare('UPDATE sessions SET delivered = 1 WHERE id = ?'),
  markApplied: db.prepare('UPDATE sessions SET applied = 1 WHERE id = ?'),
  revokeSession: db.prepare('UPDATE sessions SET revoked = 1 WHERE id = ? AND from_user_id = ?'),
  cleanExpired: db.prepare("DELETE FROM sessions WHERE expires_at IS NOT NULL AND expires_at < datetime('now', '-7 days')"),

  // ANTI-RESHARE: Check if user received (not sent) an active session for this domain
  checkReceivedDomain: db.prepare("SELECT id FROM sessions WHERE to_user_id = ? AND domain = ? AND revoked = 0 AND (expires_at IS NULL OR expires_at > datetime('now')) LIMIT 1"),
};

setInterval(() => { q.cleanTokens.run(); q.cleanExpired.run(); }, 3600000);

// ==================== HELPERS ====================
function hash(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  return salt + ':' + crypto.scryptSync(pw, salt, 64).toString('hex');
}
function verify(pw, stored) {
  const [salt, h] = stored.split(':');
  return h === crypto.scryptSync(pw, salt, 64).toString('hex');
}
function makeToken(userId) {
  const t = crypto.randomBytes(48).toString('hex');
  q.createToken.run(t, userId, new Date(Date.now() + 30 * 86400000).toISOString());
  return t;
}
function auth(req, res, next) {
  const h = req.headers.authorization;
  if (!h?.startsWith('Bearer ')) return res.status(401).json({ error: 'Login required' });
  const row = q.getToken.get(h.split(' ')[1]);
  if (!row) return res.status(401).json({ error: 'Session expired, please login again' });
  req.user = q.userById.get(row.user_id);
  if (!req.user) return res.status(401).json({ error: 'User not found' });
  next();
}
function calcExpiry(label) {
  if (!label || label === 'unlimited') return null;
  const map = { '1h': 3600, '4h': 14400, '12h': 43200, '1d': 86400, '3d': 259200, '7d': 604800, '14d': 1209600, '30d': 2592000 };
  const secs = map[label];
  return secs ? new Date(Date.now() + secs * 1000).toISOString() : null;
}

// ==================== ROUTES ====================
app.use(cors());
app.use(express.json({ limit: '10mb' }));

app.get('/', (req, res) => {
  res.json({ name: 'Elite Access Server', status: 'running', online: clients.size });
});

app.post('/api/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  if (!/^[a-zA-Z0-9_.]{3,20}$/.test(username)) return res.status(400).json({ error: 'Username: 3-20 characters, letters/numbers/._' });
  if (password.length < 4) return res.status(400).json({ error: 'Password too short (min 4)' });
  if (q.userByName.get(username)) return res.status(409).json({ error: 'Username already taken' });
  const id = uuidv4();
  q.createUser.run(id, username, hash(password));
  res.status(201).json({ id, username, token: makeToken(id) });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  const user = q.userByName.get(username);
  if (!user || !verify(password, user.password_hash)) return res.status(401).json({ error: 'Wrong username or password' });
  res.json({ id: user.id, username: user.username, token: makeToken(user.id) });
});

app.get('/api/me', auth, (req, res) => {
  res.json({ id: req.user.id, username: req.user.username });
});

app.get('/api/user/:username', auth, (req, res) => {
  const u = q.userByName.get(req.params.username);
  if (!u) return res.status(404).json({ error: 'User not found' });
  res.json({ id: u.id, username: u.username, online: clients.has(u.id) });
});

// ==================== SEND SESSION (with anti-reshare) ====================
app.post('/api/send', auth, (req, res) => {
  const { toUsername, domain, sessionData, duration } = req.body;
  if (!toUsername || !domain || !sessionData) return res.status(400).json({ error: 'Missing fields' });

  const to = q.userByName.get(toUsername);
  if (!to) return res.status(404).json({ error: 'User not found' });
  if (to.id === req.user.id) return res.status(400).json({ error: 'Cannot send to yourself' });

  // ---- ANTI-RESHARE CHECK ----
  // If the sender received this domain from someone else, BLOCK the share
  const receivedSession = q.checkReceivedDomain.get(req.user.id, domain);
  if (receivedSession) {
    return res.status(403).json({
      error: 'Reshare not allowed. You received access to this site from someone else — only the original owner can share it.',
      code: 'RESHARE_BLOCKED'
    });
  }
  // ---- END ANTI-RESHARE ----

  const id = uuidv4();
  const expiresAt = calcExpiry(duration || 'unlimited');

  q.createSession.run(id, req.user.id, req.user.username, to.id, to.username, domain, JSON.stringify(sessionData), duration || 'unlimited', expiresAt);

  const delivered = sendWS(to.id, {
    type: 'session-received',
    sessionId: id, from: req.user.username, domain, durationLabel: duration || 'unlimited', expiresAt,
    sessionData, timestamp: new Date().toISOString()
  });
  if (delivered) q.markDelivered.run(id);

  res.json({ id, delivered, message: delivered ? 'Delivered instantly!' : 'User offline — will receive when they open Elite.' });
});

app.get('/api/inbox', auth, (req, res) => {
  res.json({ sessions: q.getInbox.all(req.user.id) });
});

app.get('/api/sent', auth, (req, res) => {
  res.json({ sessions: q.getSent.all(req.user.id) });
});

app.get('/api/session/:id', auth, (req, res) => {
  const s = q.getSession.get(req.params.id);
  if (!s) return res.status(404).json({ error: 'Session not found' });
  if (s.to_user_id !== req.user.id) return res.status(403).json({ error: 'Not your session' });
  if (s.revoked) return res.status(410).json({ error: 'Access was revoked by the sender' });
  if (s.expires_at && new Date(s.expires_at) < new Date()) return res.status(410).json({ error: 'This access has expired' });
  q.markApplied.run(s.id);
  res.json({ id: s.id, domain: s.domain, sessionData: JSON.parse(s.session_data), from: s.from_username });
});

app.post('/api/revoke/:id', auth, (req, res) => {
  const s = q.getSession.get(req.params.id);
  if (!s) return res.status(404).json({ error: 'Session not found' });
  if (s.from_user_id !== req.user.id) return res.status(403).json({ error: 'Only the sender can revoke' });
  q.revokeSession.run(req.params.id, req.user.id);
  sendWS(s.to_user_id, { type: 'session-revoked', sessionId: req.params.id, domain: s.domain });
  res.json({ success: true });
});

// Check if user can share a domain (anti-reshare pre-check)
app.get('/api/canshare/:domain', auth, (req, res) => {
  const received = q.checkReceivedDomain.get(req.user.id, req.params.domain);
  res.json({ canShare: !received });
});

app.post('/api/logout', auth, (req, res) => {
  q.deleteToken.run(req.headers.authorization.split(' ')[1]);
  res.json({ success: true });
});

// ==================== WEBSOCKET ====================
const clients = new Map();

wss.on('connection', (ws) => {
  let userId = null;
  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });

  ws.on('message', (raw) => {
    try {
      const msg = JSON.parse(raw.toString());
      if (msg.type === 'auth') {
        const row = q.getToken.get(msg.token);
        if (!row) { ws.send(JSON.stringify({ type: 'error', message: 'Invalid token' })); ws.close(); return; }
        const user = q.userById.get(row.user_id);
        if (!user) { ws.close(); return; }
        userId = user.id;
        clients.set(userId, ws);
        ws.send(JSON.stringify({ type: 'authenticated', username: user.username }));

        // Deliver pending inbox items
        const pending = q.getInbox.all(userId);
        pending.forEach(p => {
          const full = q.getSession.get(p.id);
          if (full && !full.revoked && !full.delivered) {
            ws.send(JSON.stringify({
              type: 'session-received', sessionId: p.id, from: p.from_username,
              domain: p.domain, durationLabel: p.duration_label, expiresAt: p.expires_at,
              sessionData: JSON.parse(full.session_data), timestamp: p.created_at
            }));
            q.markDelivered.run(p.id);
          }
        });
      }
      else if (msg.type === 'check-online') {
        const u = q.userByName.get(msg.username);
        ws.send(JSON.stringify({ type: 'online-status', username: msg.username, online: u ? clients.has(u.id) : false }));
      }
      else if (msg.type === 'ping') ws.send('{"type":"pong"}');
    } catch (e) { console.error('WS:', e.message); }
  });

  ws.on('close', () => { if (userId) clients.delete(userId); });
});

setInterval(() => {
  wss.clients.forEach(ws => { if (!ws.isAlive) return ws.terminate(); ws.isAlive = false; ws.ping(); });
}, 30000);

function sendWS(userId, data) {
  const ws = clients.get(userId);
  if (ws?.readyState === 1) { ws.send(JSON.stringify(data)); return true; }
  return false;
}

server.listen(PORT, () => console.log(`Elite server running on port ${PORT}`));
