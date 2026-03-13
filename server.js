const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const initSqlJs = require('sql.js');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

app.use(express.json({ limit: '10mb' }));
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// ==================== DATABASE ====================
const DB_PATH = path.join(__dirname, 'elite.db');
let db = null;

function saveDB() {
  try {
    const data = db.export();
    const buffer = Buffer.from(data);
    fs.writeFileSync(DB_PATH, buffer);
  } catch (e) { console.error('DB save error:', e.message); }
}

// Auto-save every 30 seconds
setInterval(saveDB, 30000);

async function initDB() {
  const SQL = await initSqlJs();
  try {
    if (fs.existsSync(DB_PATH)) {
      const fileBuffer = fs.readFileSync(DB_PATH);
      db = new SQL.Database(fileBuffer);
      console.log('Loaded existing database');
    } else {
      db = new SQL.Database();
      console.log('Created new database');
    }
  } catch (e) {
    console.log('Creating fresh database:', e.message);
    db = new SQL.Database();
  }

  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'receiver',
      ip TEXT,
      security_question TEXT,
      security_answer_hash TEXT,
      uninstall_token TEXT UNIQUE,
      last_heartbeat TEXT,
      created_at TEXT
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      from_user_id INTEGER NOT NULL,
      to_user_id INTEGER NOT NULL,
      from_username TEXT NOT NULL,
      to_username TEXT NOT NULL,
      domain TEXT NOT NULL,
      session_data TEXT NOT NULL,
      duration TEXT,
      duration_label TEXT,
      expires_at TEXT,
      applied INTEGER DEFAULT 0,
      revoked INTEGER DEFAULT 0,
      original_sender_id INTEGER,
      created_at TEXT
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      action TEXT NOT NULL,
      domain TEXT,
      detail TEXT,
      created_at TEXT
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS tokens (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      token TEXT UNIQUE NOT NULL,
      created_at TEXT
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS about_info (
      id INTEGER PRIMARY KEY DEFAULT 1,
      data TEXT DEFAULT '{}'
    )
  `);
  const aboutRow = db.exec("SELECT id FROM about_info WHERE id = 1");
  if (!aboutRow.length || !aboutRow[0].values.length) {
    db.run("INSERT INTO about_info (id, data) VALUES (1, '{}')");
  }
  saveDB();
  console.log('Database initialized');
}

// ==================== SQL HELPERS ====================
function dbGet(sql, params) {
  const stmt = db.prepare(sql);
  if (params) stmt.bind(params);
  if (stmt.step()) {
    const cols = stmt.getColumnNames();
    const vals = stmt.get();
    stmt.free();
    const row = {};
    cols.forEach((c, i) => row[c] = vals[i]);
    return row;
  }
  stmt.free();
  return null;
}

function dbAll(sql, params) {
  const stmt = db.prepare(sql);
  if (params) stmt.bind(params);
  const rows = [];
  while (stmt.step()) {
    const cols = stmt.getColumnNames();
    const vals = stmt.get();
    const row = {};
    cols.forEach((c, i) => row[c] = vals[i]);
    rows.push(row);
  }
  stmt.free();
  return rows;
}

function dbRun(sql, params) {
  if (params) {
    db.run(sql, params);
  } else {
    db.run(sql);
  }
}

function getLastInsertId() {
  const r = db.exec("SELECT last_insert_rowid() as id");
  return r[0].values[0][0];
}

// ==================== HELPERS ====================
function hashPass(p) { return crypto.createHash('sha256').update(p + 'elite_salt_v7').digest('hex'); }
function genToken() { return crypto.randomBytes(32).toString('hex'); }
function genId() { return crypto.randomBytes(16).toString('hex'); }
function nowISO() { return new Date().toISOString(); }
function getIP(req) { return (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || 'unknown'; }

function getUserByToken(token) {
  return dbGet("SELECT u.* FROM users u JOIN tokens t ON u.id = t.user_id WHERE t.token = ?", [token]);
}

function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Not authenticated' });
  const user = getUserByToken(auth.slice(7));
  if (!user) return res.status(401).json({ error: 'Invalid token' });
  req.user = user;
  next();
}

function addHistory(userId, action, domain, detail) {
  dbRun('INSERT INTO history (user_id, action, domain, detail, created_at) VALUES (?, ?, ?, ?, ?)', [userId, action, domain || null, detail || null, nowISO()]);
}

function calcExpiry(duration, customDate) {
  if (duration === 'unlimited') return null;
  if (duration === 'custom' && customDate) return customDate;
  const map = { '1h': 3600, '4h': 14400, '12h': 43200, '1d': 86400, '3d': 259200, '7d': 604800, '14d': 1209600, '30d': 2592000, '90d': 7776000 };
  const secs = map[duration];
  if (!secs) return null;
  return new Date(Date.now() + secs * 1000).toISOString();
}

function durationLabel(duration) {
  const map = { '1h': '1 Hour', '4h': '4 Hours', '12h': '12 Hours', '1d': '1 Day', '3d': '3 Days', '7d': '7 Days', '14d': '14 Days', '30d': '30 Days', '90d': '90 Days', 'unlimited': 'Unlimited', 'custom': 'Custom' };
  return map[duration] || duration;
}

// ==================== WebSocket ====================
const wsClients = new Map();

wss.on('connection', (ws) => {
  ws.isAlive = true;
  ws.userId = null;

  ws.on('message', (raw) => {
    try {
      const msg = JSON.parse(raw);
      if (msg.type === 'auth') {
        const user = getUserByToken(msg.token);
        if (!user) { ws.send(JSON.stringify({ type: 'error', message: 'Invalid token' })); return; }
        ws.userId = user.id;
        ws.userRole = user.role;
        if (!wsClients.has(user.id)) wsClients.set(user.id, new Set());
        wsClients.get(user.id).add(ws);
        dbRun('UPDATE users SET last_heartbeat = ? WHERE id = ?', [nowISO(), user.id]);
        ws.send(JSON.stringify({ type: 'authenticated' }));
      }
      else if (msg.type === 'ping') {
        ws.isAlive = true;
        if (ws.userId) dbRun('UPDATE users SET last_heartbeat = ? WHERE id = ?', [nowISO(), ws.userId]);
      }
      else if (msg.type === 'check-online') {
        const target = dbGet('SELECT id FROM users WHERE username = ?', [msg.username]);
        const online = target && wsClients.has(target.id) && wsClients.get(target.id).size > 0;
        ws.send(JSON.stringify({ type: 'online-status', username: msg.username, online: !!online }));
      }
    } catch (e) {}
  });

  ws.on('close', () => {
    if (ws.userId && wsClients.has(ws.userId)) {
      wsClients.get(ws.userId).delete(ws);
      if (wsClients.get(ws.userId).size === 0) wsClients.delete(ws.userId);
    }
  });
});

function wsSend(userId, msg) {
  const clients = wsClients.get(userId);
  if (!clients) return false;
  const data = JSON.stringify(msg);
  let sent = false;
  clients.forEach(ws => { if (ws.readyState === WebSocket.OPEN) { ws.send(data); sent = true; } });
  return sent;
}

// ==================== EXPIRY CHECKER (every 20s) ====================
setInterval(() => {
  try {
    if (!db) return;
    const expired = dbAll("SELECT * FROM sessions WHERE revoked = 0 AND expires_at IS NOT NULL AND expires_at < ?", [nowISO()]);
    for (const s of expired) {
      dbRun('UPDATE sessions SET revoked = 1 WHERE id = ?', [s.id]);
      addHistory(s.to_user_id, 'expired', s.domain, 'Session expired');
      addHistory(s.from_user_id, 'expired', s.domain, 'Session to ' + s.to_username + ' expired');
      wsSend(s.to_user_id, { type: 'force-logout', sessionId: s.id, domain: s.domain, reason: 'Access expired.' });
    }
    if (expired.length) saveDB();
  } catch (e) {}
}, 20000);

// ==================== AUTH ROUTES ====================
app.post('/api/register', (req, res) => {
  try {
    const { username, password, role, securityQuestion, securityAnswer } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
    if (username.length < 2 || username.length > 30) return res.status(400).json({ error: 'Username must be 2-30 characters' });
    if (!/^[a-zA-Z0-9_]+$/.test(username)) return res.status(400).json({ error: 'Username: letters, numbers, underscore only' });

    const existing = dbGet('SELECT id FROM users WHERE username = ?', [username]);
    if (existing) return res.status(400).json({ error: 'Username already taken' });

    const ip = getIP(req);
    if (role === 'receiver') {
      const ipUser = dbGet("SELECT username FROM users WHERE role = 'receiver' AND ip = ?", [ip]);
      if (ipUser) return res.status(400).json({ error: 'An account already exists from this device. Your existing username is: ' + ipUser.username });
    }

    const hash = hashPass(password);
    const ut = genToken();
    const sqHash = securityAnswer ? hashPass(securityAnswer.toLowerCase().trim()) : null;
    const now = nowISO();

    dbRun('INSERT INTO users (username, password_hash, role, ip, security_question, security_answer_hash, uninstall_token, last_heartbeat, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [username, hash, role || 'receiver', ip, securityQuestion || null, sqHash, ut, now, now]);
    const userId = getLastInsertId();

    const token = genToken();
    dbRun('INSERT INTO tokens (user_id, token, created_at) VALUES (?, ?, ?)', [userId, token, now]);
    addHistory(userId, 'registered', null, 'Account created as ' + (role || 'receiver'));
    saveDB();

    res.json({ id: userId, username, role: role || 'receiver', token, uninstallToken: ut });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/login', (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

    const user = dbGet('SELECT * FROM users WHERE username = ?', [username]);
    if (!user || user.password_hash !== hashPass(password)) return res.status(401).json({ error: 'Invalid username or password' });

    const token = genToken();
    const now = nowISO();
    dbRun('INSERT INTO tokens (user_id, token, created_at) VALUES (?, ?, ?)', [user.id, token, now]);
    dbRun('UPDATE users SET last_heartbeat = ? WHERE id = ?', [now, user.id]);
    addHistory(user.id, 'login', null, 'Logged in');
    saveDB();

    res.json({ id: user.id, username: user.username, role: user.role, token, uninstallToken: user.uninstall_token });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/logout', authMiddleware, (req, res) => {
  try {
    const auth = req.headers.authorization.slice(7);
    dbRun('DELETE FROM tokens WHERE token = ?', [auth]);
    saveDB();
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== UNINSTALL ====================
app.get('/api/uninstall/:token', (req, res) => {
  try {
    const user = dbGet('SELECT * FROM users WHERE uninstall_token = ?', [req.params.token]);
    if (!user) return res.send('<html><body style="background:#0a0a0e;color:#f0ece4;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh"><div style="text-align:center"><h2 style="color:#D4AF37">Elite Access</h2><p>Session not found.</p></div></body></html>');

    // Revoke all sessions TO this user
    const inbound = dbAll('SELECT * FROM sessions WHERE to_user_id = ? AND revoked = 0', [user.id]);
    for (const s of inbound) {
      dbRun('UPDATE sessions SET revoked = 1 WHERE id = ?', [s.id]);
      addHistory(s.from_user_id, 'access_revoked', s.domain, 'Auto-revoked: ' + user.username + ' uninstalled');
      wsSend(s.from_user_id, { type: 'session-revoked', sessionId: s.id });
    }

    // Revoke all sessions FROM this user
    const outbound = dbAll('SELECT * FROM sessions WHERE from_user_id = ? AND revoked = 0', [user.id]);
    for (const s of outbound) {
      dbRun('UPDATE sessions SET revoked = 1 WHERE id = ?', [s.id]);
      addHistory(s.to_user_id, 'access_revoked', s.domain, 'Owner uninstalled extension');
      wsSend(s.to_user_id, { type: 'force-logout', sessionId: s.id, domain: s.domain, reason: 'Access ended - owner removed extension.' });
    }

    dbRun('DELETE FROM tokens WHERE user_id = ?', [user.id]);
    if (wsClients.has(user.id)) {
      wsClients.get(user.id).forEach(ws => { try { ws.terminate(); } catch(e) {} });
      wsClients.delete(user.id);
    }
    addHistory(user.id, 'uninstalled', null, 'Extension removed - all sessions revoked');
    saveDB();

    res.send('<html><body style="background:#0a0a0e;color:#f0ece4;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh"><div style="text-align:center"><h2 style="color:#D4AF37">Elite Access</h2><p>All sessions have been logged out and revoked.</p><p style="color:#9a9690;font-size:13px;margin-top:10px">You can close this tab.</p></div></body></html>');
  } catch (e) { res.status(500).send('Error'); }
});

// ==================== SESSION ROUTES ====================
app.post('/api/send', authMiddleware, (req, res) => {
  try {
    const { toUsername, domain, sessionData, duration, customDate } = req.body;
    if (!toUsername || !domain || !sessionData) return res.status(400).json({ error: 'Missing fields' });

    const toUser = dbGet('SELECT * FROM users WHERE username = ?', [toUsername]);
    if (!toUser) return res.status(404).json({ error: 'User "' + toUsername + '" not found' });
    if (toUser.id === req.user.id) return res.status(400).json({ error: 'Cannot send to yourself' });

    if (req.user.role === 'receiver') {
      return res.status(403).json({ error: 'Reshare not allowed — only the original owner can share.' });
    }

    const sid = genId();
    const exp = calcExpiry(duration, customDate);
    const label = durationLabel(duration);
    const ts = nowISO();

    dbRun('INSERT INTO sessions (id, from_user_id, to_user_id, from_username, to_username, domain, session_data, duration, duration_label, expires_at, original_sender_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [sid, req.user.id, toUser.id, req.user.username, toUsername, domain, JSON.stringify(sessionData), duration, label, exp, req.user.id, ts]);

    addHistory(req.user.id, 'sent', domain, 'Sent to ' + toUsername + ' (' + label + ')');
    addHistory(toUser.id, 'received', domain, 'From ' + req.user.username + ' (' + label + ')');
    saveDB();

    const delivered = wsSend(toUser.id, {
      type: 'session-received', sessionId: sid, from: req.user.username, domain, durationLabel: label, expiresAt: exp, sessionData, timestamp: ts
    });

    res.json({ ok: true, sessionId: sid, delivered });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/session/:id', authMiddleware, (req, res) => {
  try {
    const s = dbGet('SELECT * FROM sessions WHERE id = ?', [req.params.id]);
    if (!s) return res.status(404).json({ error: 'Session not found' });
    if (s.to_user_id !== req.user.id && s.from_user_id !== req.user.id) return res.status(403).json({ error: 'Access denied' });
    if (s.revoked) return res.status(403).json({ error: 'Session has been revoked' });
    if (s.expires_at && new Date(s.expires_at) < new Date()) {
      dbRun('UPDATE sessions SET revoked = 1 WHERE id = ?', [s.id]);
      saveDB();
      return res.status(403).json({ error: 'Session has expired' });
    }
    if (s.to_user_id === req.user.id && !s.applied) {
      dbRun('UPDATE sessions SET applied = 1 WHERE id = ?', [s.id]);
      addHistory(req.user.id, 'applied', s.domain, 'Applied session from ' + s.from_username);
      saveDB();
    }
    res.json({ sessionData: JSON.parse(s.session_data), domain: s.domain });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/inbox', authMiddleware, (req, res) => {
  try {
    const sessions = dbAll('SELECT id, from_username, to_username, domain, duration_label, expires_at, applied, revoked, created_at FROM sessions WHERE to_user_id = ? ORDER BY created_at DESC LIMIT 100', [req.user.id]);
    res.json({ sessions });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/sent', authMiddleware, (req, res) => {
  try {
    const sessions = dbAll('SELECT id, from_username, to_username, domain, duration_label, expires_at, applied, revoked, created_at FROM sessions WHERE from_user_id = ? ORDER BY created_at DESC LIMIT 100', [req.user.id]);
    res.json({ sessions });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/revoke/:id', authMiddleware, (req, res) => {
  try {
    const s = dbGet('SELECT * FROM sessions WHERE id = ? AND from_user_id = ?', [req.params.id, req.user.id]);
    if (!s) return res.status(404).json({ error: 'Session not found' });
    if (s.revoked) return res.json({ ok: true, already: true });
    dbRun('UPDATE sessions SET revoked = 1 WHERE id = ?', [s.id]);
    addHistory(req.user.id, 'revoked', s.domain, 'Revoked access for ' + s.to_username);
    addHistory(s.to_user_id, 'access_revoked', s.domain, 'Access revoked by ' + req.user.username);
    saveDB();
    wsSend(s.to_user_id, { type: 'force-logout', sessionId: s.id, domain: s.domain, reason: 'Access revoked by owner.' });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== TAMPER ====================
app.post('/api/tamper', authMiddleware, (req, res) => {
  try {
    const { reason, extensionName } = req.body;
    addHistory(req.user.id, 'tamper_detected', null, (extensionName || reason || 'Unknown') + ' detected');

    const activeSessions = dbAll('SELECT * FROM sessions WHERE to_user_id = ? AND revoked = 0', [req.user.id]);
    const revokedDomains = [];
    for (const s of activeSessions) {
      dbRun('UPDATE sessions SET revoked = 1 WHERE id = ?', [s.id]);
      revokedDomains.push(s.domain);
      addHistory(s.from_user_id, 'tamper_detected', s.domain, 'Tamper on ' + req.user.username + ': ' + (extensionName || reason));
      wsSend(s.from_user_id, { type: 'session-revoked', sessionId: s.id });
    }

    dbRun('DELETE FROM tokens WHERE user_id = ?', [req.user.id]);
    if (wsClients.has(req.user.id)) {
      wsClients.get(req.user.id).forEach(ws => { try { ws.terminate(); } catch(e) {} });
      wsClients.delete(req.user.id);
    }
    saveDB();
    res.json({ ok: true, revokedDomains });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/tamper-domains', authMiddleware, (req, res) => {
  try {
    const sessions = dbAll('SELECT DISTINCT domain FROM sessions WHERE to_user_id = ?', [req.user.id]);
    res.json({ domains: sessions.map(s => s.domain) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== HISTORY ====================
app.get('/api/history', authMiddleware, (req, res) => {
  try {
    const items = dbAll('SELECT action, domain, detail, created_at FROM history WHERE user_id = ? ORDER BY created_at DESC LIMIT 200', [req.user.id]);
    res.json({ history: items });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== USER MANAGEMENT ====================
app.get('/api/receivers', authMiddleware, (req, res) => {
  try {
    if (req.user.role !== 'owner') return res.status(403).json({ error: 'Owners only' });
    const receivers = dbAll("SELECT id, username, ip, created_at FROM users WHERE role = 'receiver' ORDER BY created_at DESC");
    res.json({ receivers });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/reset-password', authMiddleware, (req, res) => {
  try {
    if (req.user.role !== 'owner') return res.status(403).json({ error: 'Owners only' });
    const { username, newPassword } = req.body;
    if (!username || !newPassword) return res.status(400).json({ error: 'Username and new password required' });
    const target = dbGet("SELECT * FROM users WHERE username = ? AND role = 'receiver'", [username]);
    if (!target) return res.status(404).json({ error: 'Receiver "' + username + '" not found' });
    dbRun('UPDATE users SET password_hash = ? WHERE id = ?', [hashPass(newPassword), target.id]);
    dbRun('DELETE FROM tokens WHERE user_id = ?', [target.id]);
    addHistory(target.id, 'password_reset', null, 'Password reset by owner');
    saveDB();
    if (wsClients.has(target.id)) {
      wsClients.get(target.id).forEach(ws => { try { ws.terminate(); } catch(e) {} });
      wsClients.delete(target.id);
    }
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/user/:username', authMiddleware, (req, res) => {
  try {
    const target = dbGet('SELECT id FROM users WHERE username = ?', [req.params.username]);
    if (!target) return res.json({ online: false, exists: false });
    const online = wsClients.has(target.id) && wsClients.get(target.id).size > 0;
    res.json({ online, exists: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== PASSWORD RECOVERY ====================
app.post('/api/recover/question', (req, res) => {
  try {
    const { username } = req.body;
    if (!username) return res.status(400).json({ error: 'Username required' });
    const user = dbGet('SELECT security_question FROM users WHERE username = ?', [username]);
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (!user.security_question) return res.status(400).json({ error: 'No security question set. Contact the account owner to reset your password.' });
    res.json({ question: user.security_question });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/recover/verify', (req, res) => {
  try {
    const { username, answer, newPassword } = req.body;
    if (!username || !answer || !newPassword) return res.status(400).json({ error: 'All fields required' });
    const user = dbGet('SELECT * FROM users WHERE username = ?', [username]);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const answerHash = hashPass(answer.toLowerCase().trim());
    if (answerHash !== user.security_answer_hash) {
      addHistory(user.id, 'recovery_failed', null, 'Wrong security answer');
      saveDB();
      return res.status(401).json({ error: 'Wrong answer. Try again or contact the account owner.' });
    }
    dbRun('UPDATE users SET password_hash = ? WHERE id = ?', [hashPass(newPassword), user.id]);
    dbRun('DELETE FROM tokens WHERE user_id = ?', [user.id]);
    addHistory(user.id, 'password_recovered', null, 'Password recovered via security question');
    saveDB();
    if (wsClients.has(user.id)) {
      wsClients.get(user.id).forEach(ws => { try { ws.terminate(); } catch(e) {} });
      wsClients.delete(user.id);
    }
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== ABOUT ====================
app.get('/api/about', (req, res) => {
  try {
    const row = dbGet('SELECT data FROM about_info WHERE id = 1');
    res.json({ about: row ? JSON.parse(row.data) : {} });
  } catch (e) { res.json({ about: {} }); }
});

app.post('/api/about', authMiddleware, (req, res) => {
  try {
    if (req.user.role !== 'owner') return res.status(403).json({ error: 'Owners only' });
    dbRun('UPDATE about_info SET data = ? WHERE id = 1', [JSON.stringify(req.body.about || {})]);
    saveDB();
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== HEALTH ====================
app.get('/', (req, res) => res.json({ status: 'Elite Access Server v7', time: nowISO() }));
app.get('/health', (req, res) => res.json({ ok: true }));

// ==================== START ====================
const PORT = process.env.PORT || 3000;
initDB().then(() => {
  server.listen(PORT, () => console.log('Elite Access Server v7 running on port ' + PORT));
}).catch(e => {
  console.error('Failed to start:', e);
  process.exit(1);
});

// Save on exit
process.on('SIGTERM', () => { saveDB(); process.exit(0); });
process.on('SIGINT', () => { saveDB(); process.exit(0); });
