const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const crypto = require('crypto');
const path = require('path');

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

// ==================== DATABASE (SQLite) ====================
const Database = require('better-sqlite3');
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'elite.db');
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
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
    created_at TEXT DEFAULT (datetime('now'))
  );
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
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (from_user_id) REFERENCES users(id),
    FOREIGN KEY (to_user_id) REFERENCES users(id)
  );
  CREATE TABLE IF NOT EXISTS history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    action TEXT NOT NULL,
    domain TEXT,
    detail TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
  CREATE TABLE IF NOT EXISTS tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT UNIQUE NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
  CREATE TABLE IF NOT EXISTS about_info (
    id INTEGER PRIMARY KEY DEFAULT 1,
    data TEXT DEFAULT '{}'
  );
  INSERT OR IGNORE INTO about_info (id, data) VALUES (1, '{}');
`);

// ==================== HELPERS ====================
function hashPass(p) { return crypto.createHash('sha256').update(p + 'elite_salt_v7').digest('hex'); }
function genToken() { return crypto.randomBytes(32).toString('hex'); }
function genId() { return crypto.randomBytes(16).toString('hex'); }
function nowISO() { return new Date().toISOString(); }
function getIP(req) { return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket?.remoteAddress || 'unknown'; }

function getUserByToken(token) {
  const row = db.prepare('SELECT u.* FROM users u JOIN tokens t ON u.id = t.user_id WHERE t.token = ?').get(token);
  return row || null;
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
  db.prepare('INSERT INTO history (user_id, action, domain, detail, created_at) VALUES (?, ?, ?, ?, ?)').run(userId, action, domain || null, detail || null, nowISO());
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
const wsClients = new Map(); // userId -> Set<ws>

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
        // Update heartbeat
        db.prepare('UPDATE users SET last_heartbeat = ? WHERE id = ?').run(nowISO(), user.id);
        ws.send(JSON.stringify({ type: 'authenticated' }));
      }
      else if (msg.type === 'ping') {
        ws.isAlive = true;
        if (ws.userId) db.prepare('UPDATE users SET last_heartbeat = ? WHERE id = ?').run(nowISO(), ws.userId);
      }
      else if (msg.type === 'check-online') {
        const target = db.prepare('SELECT id FROM users WHERE username = ?').get(msg.username);
        if (target) {
          const online = wsClients.has(target.id) && wsClients.get(target.id).size > 0;
          ws.send(JSON.stringify({ type: 'online-status', username: msg.username, online }));
        } else {
          ws.send(JSON.stringify({ type: 'online-status', username: msg.username, online: false }));
        }
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

// ==================== EXPIRY CHECKER ====================
setInterval(() => {
  try {
    const expired = db.prepare("SELECT * FROM sessions WHERE revoked = 0 AND expires_at IS NOT NULL AND expires_at < ?").all(nowISO());
    for (const s of expired) {
      db.prepare('UPDATE sessions SET revoked = 1 WHERE id = ?').run(s.id);
      addHistory(s.to_user_id, 'expired', s.domain, 'Session expired');
      addHistory(s.from_user_id, 'expired', s.domain, 'Session to ' + s.to_username + ' expired');
      // Send force-logout to receiver
      wsSend(s.to_user_id, { type: 'force-logout', sessionId: s.id, domain: s.domain, reason: 'Access expired.' });
    }
  } catch (e) {}
}, 20000); // Check every 20 seconds

// ==================== HEARTBEAT CHECKER ====================
// If receiver hasn't sent heartbeat in 5 minutes, consider disconnected
setInterval(() => {
  try {
    const cutoff = new Date(Date.now() - 5 * 60 * 1000).toISOString();
    const staleReceivers = db.prepare("SELECT id, username FROM users WHERE role = 'receiver' AND last_heartbeat IS NOT NULL AND last_heartbeat < ?").all(cutoff);
    // Just clean up WS connections for stale users
    for (const u of staleReceivers) {
      if (wsClients.has(u.id)) {
        wsClients.get(u.id).forEach(ws => { try { ws.terminate(); } catch(e) {} });
        wsClients.delete(u.id);
      }
    }
  } catch (e) {}
}, 60000);

// ==================== AUTH ROUTES ====================
app.post('/api/register', (req, res) => {
  try {
    const { username, password, role, securityQuestion, securityAnswer } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
    if (username.length < 2 || username.length > 30) return res.status(400).json({ error: 'Username must be 2-30 characters' });
    if (!/^[a-zA-Z0-9_]+$/.test(username)) return res.status(400).json({ error: 'Username: letters, numbers, underscore only' });

    const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
    if (existing) return res.status(400).json({ error: 'Username already taken' });

    const ip = getIP(req);
    // IP lock for receivers
    if (role === 'receiver') {
      const ipUser = db.prepare("SELECT username FROM users WHERE role = 'receiver' AND ip = ?").get(ip);
      if (ipUser) return res.status(400).json({ error: 'An account already exists from this device. Your existing username is: ' + ipUser.username });
    }

    const hash = hashPass(password);
    const ut = genToken();
    const sqHash = securityAnswer ? hashPass(securityAnswer.toLowerCase().trim()) : null;

    const result = db.prepare('INSERT INTO users (username, password_hash, role, ip, security_question, security_answer_hash, uninstall_token, last_heartbeat, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)').run(username, hash, role || 'receiver', ip, securityQuestion || null, sqHash, ut, nowISO(), nowISO());

    const token = genToken();
    db.prepare('INSERT INTO tokens (user_id, token, created_at) VALUES (?, ?, ?)').run(result.lastInsertRowid, token, nowISO());
    addHistory(result.lastInsertRowid, 'registered', null, 'Account created as ' + (role || 'receiver'));

    res.json({ id: result.lastInsertRowid, username, role: role || 'receiver', token, uninstallToken: ut });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/login', (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    if (!user || user.password_hash !== hashPass(password)) return res.status(401).json({ error: 'Invalid username or password' });

    const token = genToken();
    db.prepare('INSERT INTO tokens (user_id, token, created_at) VALUES (?, ?, ?)').run(user.id, token, nowISO());
    db.prepare('UPDATE users SET last_heartbeat = ? WHERE id = ?').run(nowISO(), user.id);
    addHistory(user.id, 'login', null, 'Logged in');

    res.json({ id: user.id, username: user.username, role: user.role, token, uninstallToken: user.uninstall_token });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/logout', authMiddleware, (req, res) => {
  try {
    const auth = req.headers.authorization.slice(7);
    db.prepare('DELETE FROM tokens WHERE token = ?').run(auth);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== UNINSTALL HANDLER ====================
app.get('/api/uninstall/:token', (req, res) => {
  try {
    const user = db.prepare('SELECT * FROM users WHERE uninstall_token = ?').get(req.params.token);
    if (!user) return res.send('<html><body style="background:#0a0a0e;color:#f0ece4;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh"><div style="text-align:center"><h2 style="color:#D4AF37">Elite Access</h2><p>Session not found.</p></div></body></html>');

    // Revoke ALL active sessions where this user is the receiver
    const activeSessions = db.prepare('SELECT * FROM sessions WHERE to_user_id = ? AND revoked = 0').all(user.id);
    for (const s of activeSessions) {
      db.prepare('UPDATE sessions SET revoked = 1 WHERE id = ?').run(s.id);
      addHistory(s.from_user_id, 'access_revoked', s.domain, 'Auto-revoked: ' + user.username + ' uninstalled extension');
      // Notify the owner that the session was revoked
      wsSend(s.from_user_id, { type: 'session-revoked', sessionId: s.id });
      // Try to force-logout the receiver (probably won't work since extension is gone, but try)
      wsSend(user.id, { type: 'force-logout', sessionId: s.id, domain: s.domain, reason: 'Extension removed' });
    }

    // Also revoke sessions this user SENT (if owner)
    const sentSessions = db.prepare('SELECT * FROM sessions WHERE from_user_id = ? AND revoked = 0').all(user.id);
    for (const s of sentSessions) {
      db.prepare('UPDATE sessions SET revoked = 1 WHERE id = ?').run(s.id);
      addHistory(s.to_user_id, 'access_revoked', s.domain, 'Owner uninstalled extension');
      wsSend(s.to_user_id, { type: 'force-logout', sessionId: s.id, domain: s.domain, reason: 'Access ended - owner removed extension.' });
    }

    // Delete all tokens for this user
    db.prepare('DELETE FROM tokens WHERE user_id = ?').run(user.id);
    // Close WS connections
    if (wsClients.has(user.id)) {
      wsClients.get(user.id).forEach(ws => { try { ws.terminate(); } catch(e) {} });
      wsClients.delete(user.id);
    }

    addHistory(user.id, 'uninstalled', null, 'Extension removed - all sessions revoked');

    res.send('<html><body style="background:#0a0a0e;color:#f0ece4;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh"><div style="text-align:center"><h2 style="color:#D4AF37">Elite Access</h2><p>All sessions have been logged out and revoked.</p><p style="color:#9a9690;font-size:13px;margin-top:10px">You can close this tab.</p></div></body></html>');
  } catch (e) { res.status(500).send('Error'); }
});

// ==================== SESSION ROUTES ====================
app.post('/api/send', authMiddleware, (req, res) => {
  try {
    const { toUsername, domain, sessionData, duration, customDate } = req.body;
    if (!toUsername || !domain || !sessionData) return res.status(400).json({ error: 'Missing fields' });

    const toUser = db.prepare('SELECT * FROM users WHERE username = ?').get(toUsername);
    if (!toUser) return res.status(404).json({ error: 'User "' + toUsername + '" not found' });
    if (toUser.id === req.user.id) return res.status(400).json({ error: 'Cannot send to yourself' });

    // Anti-reshare: only owners can send, OR check if receiver is trying to reshare
    if (req.user.role === 'receiver') {
      return res.status(403).json({ error: 'Reshare not allowed — only the original owner can share.' });
    }

    const sid = genId();
    const exp = calcExpiry(duration, customDate);
    const label = durationLabel(duration);
    const ts = nowISO();

    db.prepare('INSERT INTO sessions (id, from_user_id, to_user_id, from_username, to_username, domain, session_data, duration, duration_label, expires_at, original_sender_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').run(
      sid, req.user.id, toUser.id, req.user.username, toUsername, domain, JSON.stringify(sessionData), duration, label, exp, req.user.id, ts
    );

    addHistory(req.user.id, 'sent', domain, 'Sent to ' + toUsername + ' (' + label + ')');
    addHistory(toUser.id, 'received', domain, 'From ' + req.user.username + ' (' + label + ')');

    const delivered = wsSend(toUser.id, {
      type: 'session-received', sessionId: sid, from: req.user.username, domain, durationLabel: label, expiresAt: exp, sessionData, timestamp: ts
    });

    res.json({ ok: true, sessionId: sid, delivered });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/session/:id', authMiddleware, (req, res) => {
  try {
    const s = db.prepare('SELECT * FROM sessions WHERE id = ?').get(req.params.id);
    if (!s) return res.status(404).json({ error: 'Session not found' });
    if (s.to_user_id !== req.user.id && s.from_user_id !== req.user.id) return res.status(403).json({ error: 'Access denied' });
    if (s.revoked) return res.status(403).json({ error: 'Session has been revoked' });
    if (s.expires_at && new Date(s.expires_at) < new Date()) {
      db.prepare('UPDATE sessions SET revoked = 1 WHERE id = ?').run(s.id);
      return res.status(403).json({ error: 'Session has expired' });
    }

    // Mark as applied
    if (s.to_user_id === req.user.id && !s.applied) {
      db.prepare('UPDATE sessions SET applied = 1 WHERE id = ?').run(s.id);
      addHistory(req.user.id, 'applied', s.domain, 'Applied session from ' + s.from_username);
    }

    res.json({ sessionData: JSON.parse(s.session_data), domain: s.domain });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/inbox', authMiddleware, (req, res) => {
  try {
    const sessions = db.prepare('SELECT id, from_username, to_username, domain, duration_label, expires_at, applied, revoked, created_at FROM sessions WHERE to_user_id = ? ORDER BY created_at DESC LIMIT 100').all(req.user.id);
    res.json({ sessions });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/sent', authMiddleware, (req, res) => {
  try {
    const sessions = db.prepare('SELECT id, from_username, to_username, domain, duration_label, expires_at, applied, revoked, created_at FROM sessions WHERE from_user_id = ? ORDER BY created_at DESC LIMIT 100').all(req.user.id);
    res.json({ sessions });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/revoke/:id', authMiddleware, (req, res) => {
  try {
    const s = db.prepare('SELECT * FROM sessions WHERE id = ? AND from_user_id = ?').get(req.params.id, req.user.id);
    if (!s) return res.status(404).json({ error: 'Session not found' });
    if (s.revoked) return res.json({ ok: true, already: true });

    db.prepare('UPDATE sessions SET revoked = 1 WHERE id = ?').run(s.id);
    addHistory(req.user.id, 'revoked', s.domain, 'Revoked access for ' + s.to_username);
    addHistory(s.to_user_id, 'access_revoked', s.domain, 'Access revoked by ' + req.user.username);

    // Force-logout the receiver
    wsSend(s.to_user_id, { type: 'force-logout', sessionId: s.id, domain: s.domain, reason: 'Access revoked by owner.' });

    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== TAMPER ENDPOINT ====================
app.post('/api/tamper', authMiddleware, (req, res) => {
  try {
    const { reason, extensionName } = req.body;
    addHistory(req.user.id, 'tamper_detected', null, (extensionName || reason || 'Unknown') + ' detected');

    // Revoke ALL active sessions for this user (receiver)
    const activeSessions = db.prepare('SELECT * FROM sessions WHERE to_user_id = ? AND revoked = 0').all(req.user.id);
    const revokedDomains = [];
    for (const s of activeSessions) {
      db.prepare('UPDATE sessions SET revoked = 1 WHERE id = ?').run(s.id);
      revokedDomains.push(s.domain);
      addHistory(s.from_user_id, 'tamper_detected', s.domain, 'Tamper detected on ' + req.user.username + ': ' + (extensionName || reason));
      wsSend(s.from_user_id, { type: 'session-revoked', sessionId: s.id });
    }

    // Delete tokens to force re-login
    db.prepare('DELETE FROM tokens WHERE user_id = ?').run(req.user.id);

    // Close WS connections
    if (wsClients.has(req.user.id)) {
      wsClients.get(req.user.id).forEach(ws => { try { ws.terminate(); } catch(e) {} });
      wsClients.delete(req.user.id);
    }

    res.json({ ok: true, revokedDomains });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== TAMPER CHECK (called by receiver to get domains to clear) ====================
app.post('/api/tamper-domains', authMiddleware, (req, res) => {
  try {
    // Return all domains this receiver has active/recent sessions for
    const sessions = db.prepare('SELECT DISTINCT domain FROM sessions WHERE to_user_id = ?').all(req.user.id);
    res.json({ domains: sessions.map(s => s.domain) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== HISTORY ====================
app.get('/api/history', authMiddleware, (req, res) => {
  try {
    const items = db.prepare('SELECT action, domain, detail, created_at FROM history WHERE user_id = ? ORDER BY created_at DESC LIMIT 200').all(req.user.id);
    res.json({ history: items });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== USER MANAGEMENT (Owner) ====================
app.get('/api/receivers', authMiddleware, (req, res) => {
  try {
    if (req.user.role !== 'owner') return res.status(403).json({ error: 'Owners only' });
    const receivers = db.prepare("SELECT id, username, ip, created_at FROM users WHERE role = 'receiver' ORDER BY created_at DESC").all();
    res.json({ receivers });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/reset-password', authMiddleware, (req, res) => {
  try {
    if (req.user.role !== 'owner') return res.status(403).json({ error: 'Owners only' });
    const { username, newPassword } = req.body;
    if (!username || !newPassword) return res.status(400).json({ error: 'Username and new password required' });

    const target = db.prepare("SELECT * FROM users WHERE username = ? AND role = 'receiver'").get(username);
    if (!target) return res.status(404).json({ error: 'Receiver "' + username + '" not found' });

    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hashPass(newPassword), target.id);
    db.prepare('DELETE FROM tokens WHERE user_id = ?').run(target.id);
    addHistory(target.id, 'password_reset', null, 'Password reset by owner');

    // Close WS connections to force re-login
    if (wsClients.has(target.id)) {
      wsClients.get(target.id).forEach(ws => { try { ws.terminate(); } catch(e) {} });
      wsClients.delete(target.id);
    }

    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/user/:username', authMiddleware, (req, res) => {
  try {
    const target = db.prepare('SELECT id FROM users WHERE username = ?').get(req.params.username);
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
    const user = db.prepare('SELECT security_question FROM users WHERE username = ?').get(username);
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (!user.security_question) return res.status(400).json({ error: 'No security question set. Contact the account owner to reset your password.' });
    res.json({ question: user.security_question });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/recover/verify', (req, res) => {
  try {
    const { username, answer, newPassword } = req.body;
    if (!username || !answer || !newPassword) return res.status(400).json({ error: 'All fields required' });

    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const answerHash = hashPass(answer.toLowerCase().trim());
    if (answerHash !== user.security_answer_hash) {
      addHistory(user.id, 'recovery_failed', null, 'Wrong security answer');
      return res.status(401).json({ error: 'Wrong answer. Try again or contact the account owner.' });
    }

    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hashPass(newPassword), user.id);
    db.prepare('DELETE FROM tokens WHERE user_id = ?').run(user.id);
    addHistory(user.id, 'password_recovered', null, 'Password recovered via security question');

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
    const row = db.prepare('SELECT data FROM about_info WHERE id = 1').get();
    res.json({ about: row ? JSON.parse(row.data) : {} });
  } catch (e) { res.json({ about: {} }); }
});

app.post('/api/about', authMiddleware, (req, res) => {
  try {
    if (req.user.role !== 'owner') return res.status(403).json({ error: 'Owners only' });
    db.prepare('UPDATE about_info SET data = ? WHERE id = 1').run(JSON.stringify(req.body.about || {}));
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== HEALTH CHECK ====================
app.get('/', (req, res) => res.json({ status: 'Elite Access Server v7', time: nowISO() }));
app.get('/health', (req, res) => res.json({ ok: true }));

// ==================== START ====================
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log('Elite Access Server v7 running on port ' + PORT));
