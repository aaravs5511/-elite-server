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

const db = new Database(process.env.DB_PATH || path.join(__dirname, 'data.db'));
db.pragma('journal_mode = WAL');

// IMPORTANT: All timestamps use JS Date().toISOString() = UTC with Z suffix
// e.g. "2026-03-13T12:30:00.000Z" — parsed correctly in any timezone
function utcNow() { return new Date().toISOString(); }

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'receiver',
    ip TEXT,
    security_question TEXT,
    security_answer_hash TEXT,
    uninstall_token TEXT,
    created_at TEXT
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
    created_at TEXT
  );
  CREATE TABLE IF NOT EXISTS history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    action TEXT NOT NULL,
    domain TEXT,
    detail TEXT,
    created_at TEXT
  );
`);

// Settings table for About info (owner-controlled, receivers fetch live)
db.exec(`
  CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );
`);

try { db.exec('ALTER TABLE users ADD COLUMN security_question TEXT'); } catch(e) {}
try { db.exec('ALTER TABLE users ADD COLUMN security_answer_hash TEXT'); } catch(e) {}
try { db.exec('ALTER TABLE users ADD COLUMN uninstall_token TEXT'); } catch(e) {}

const q = {
  userByName: db.prepare('SELECT * FROM users WHERE username = ? COLLATE NOCASE'),
  userById: db.prepare('SELECT * FROM users WHERE id = ?'),
  userByIp: db.prepare('SELECT * FROM users WHERE ip = ? AND role = ?'),
  userByUninstallToken: db.prepare('SELECT * FROM users WHERE uninstall_token = ?'),
  createUser: db.prepare('INSERT INTO users (id, username, password_hash, role, ip, security_question, security_answer_hash, uninstall_token, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'),
  updatePassword: db.prepare('UPDATE users SET password_hash = ? WHERE id = ?'),
  updateUninstallToken: db.prepare('UPDATE users SET uninstall_token = ? WHERE id = ?'),
  createToken: db.prepare('INSERT INTO tokens (token, user_id, expires_at) VALUES (?, ?, ?)'),
  getToken: db.prepare('SELECT * FROM tokens WHERE token = ?'),
  deleteToken: db.prepare('DELETE FROM tokens WHERE token = ?'),
  deleteUserTokens: db.prepare('DELETE FROM tokens WHERE user_id = ?'),
  cleanTokens: db.prepare('DELETE FROM tokens WHERE expires_at < ?'),
  allReceivers: db.prepare("SELECT id, username, ip, created_at FROM users WHERE role = 'receiver' ORDER BY created_at DESC"),

  createSession: db.prepare('INSERT INTO sessions (id, from_user_id, from_username, to_user_id, to_username, domain, session_data, duration_label, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'),
  getInbox: db.prepare('SELECT id, from_username, domain, duration_label, expires_at, revoked, applied, created_at FROM sessions WHERE to_user_id = ? AND revoked = 0 AND (expires_at IS NULL OR expires_at > ?) ORDER BY created_at DESC'),
  getSent: db.prepare('SELECT id, to_username, domain, duration_label, expires_at, revoked, applied, created_at FROM sessions WHERE from_user_id = ? ORDER BY created_at DESC LIMIT 200'),
  getSession: db.prepare('SELECT * FROM sessions WHERE id = ?'),
  markDelivered: db.prepare('UPDATE sessions SET delivered = 1 WHERE id = ?'),
  markApplied: db.prepare('UPDATE sessions SET applied = 1 WHERE id = ?'),
  revokeSession: db.prepare('UPDATE sessions SET revoked = 1 WHERE id = ? AND from_user_id = ?'),
  checkReceivedDomain: db.prepare('SELECT id FROM sessions WHERE to_user_id = ? AND domain = ? AND revoked = 0 AND (expires_at IS NULL OR expires_at > ?) LIMIT 1'),
  getExpiredActive: db.prepare('SELECT * FROM sessions WHERE expires_at IS NOT NULL AND expires_at <= ? AND revoked = 0'),
  markExpiredRevoked: db.prepare('UPDATE sessions SET revoked = 1 WHERE expires_at IS NOT NULL AND expires_at <= ? AND revoked = 0'),
  getActiveForUser: db.prepare('SELECT * FROM sessions WHERE to_user_id = ? AND revoked = 0 AND (expires_at IS NULL OR expires_at > ?)'),
  revokeAllForUser: db.prepare('UPDATE sessions SET revoked = 1 WHERE to_user_id = ? AND revoked = 0'),

  addHistory: db.prepare('INSERT INTO history (user_id, action, domain, detail, created_at) VALUES (?, ?, ?, ?, ?)'),
  getHistory: db.prepare('SELECT action, domain, detail, created_at FROM history WHERE user_id = ? ORDER BY created_at DESC LIMIT 100'),

  getSetting: db.prepare('SELECT value FROM settings WHERE key = ?'),
  setSetting: db.prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = ?'),
};

// ==================== EXPIRY CHECKER (every 20s) ====================
setInterval(() => {
  const now = utcNow();
  const expired = q.getExpiredActive.all(now);
  expired.forEach(s => {
    sendWS(s.to_user_id, { type: 'force-logout', sessionId: s.id, domain: s.domain, reason: 'Your access to ' + s.domain + ' has expired' });
    q.addHistory.run(s.to_user_id, 'expired', s.domain, 'Access expired', now);
  });
  q.markExpiredRevoked.run(now);
}, 20000);

setInterval(() => { q.cleanTokens.run(utcNow()); }, 3600000);

// ==================== HELPERS ====================
function hash(pw) { const s = crypto.randomBytes(16).toString('hex'); return s + ':' + crypto.scryptSync(pw, s, 64).toString('hex'); }
function verify(pw, stored) { if (!stored) return false; const [s, h] = stored.split(':'); return h === crypto.scryptSync(pw, s, 64).toString('hex'); }
function makeToken(uid) {
  const t = crypto.randomBytes(48).toString('hex');
  q.createToken.run(t, uid, new Date(Date.now() + 90 * 86400000).toISOString());
  return t;
}
function getIP(req) { return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown'; }

function checkToken(tokenStr) {
  if (!tokenStr) return null;
  const row = q.getToken.get(tokenStr);
  if (!row) return null;
  if (new Date(row.expires_at) < new Date()) { q.deleteToken.run(tokenStr); return null; }
  return q.userById.get(row.user_id);
}

function auth(req, res, next) {
  const h = req.headers.authorization;
  if (!h?.startsWith('Bearer ')) return res.status(401).json({ error: 'Login required' });
  const user = checkToken(h.split(' ')[1]);
  if (!user) return res.status(401).json({ error: 'Session expired, please login again' });
  req.user = user;
  next();
}

function calcExpiry(label, customDateISO) {
  // customDateISO should already be in ISO/UTC format from client
  if (customDateISO) {
    const d = new Date(customDateISO);
    if (isNaN(d.getTime())) return null;
    return d.toISOString();
  }
  if (!label || label === 'unlimited') return null;
  const map = { '1h': 3600, '4h': 14400, '12h': 43200, '1d': 86400, '3d': 259200, '7d': 604800, '14d': 1209600, '30d': 2592000, '90d': 7776000 };
  const s = map[label];
  return s ? new Date(Date.now() + s * 1000).toISOString() : null;
}

// ==================== ROUTES ====================
app.use(cors());
app.use(express.json({ limit: '10mb' }));

app.get('/', (req, res) => res.json({ name: 'Elite Access Server', version: '6.0', online: clients.size, time: utcNow() }));

// ==================== REGISTER ====================
app.post('/api/register', (req, res) => {
  const { username, password, role, securityQuestion, securityAnswer } = req.body;
  if (!username) return res.status(400).json({ error: 'Username required' });
  if (!/^[a-zA-Z0-9_.]{3,20}$/.test(username)) return res.status(400).json({ error: 'Username: 3-20 chars (letters, numbers, . _)' });
  if (!password || password.length < 4) return res.status(400).json({ error: 'Password required (min 4 characters)' });
  if (q.userByName.get(username)) return res.status(409).json({ error: 'Username already taken' });

  const userRole = role === 'owner' ? 'owner' : 'receiver';
  const ip = getIP(req);
  const now = utcNow();

  if (userRole === 'receiver') {
    const existing = q.userByIp.get(ip, 'receiver');
    if (existing) return res.status(403).json({ error: 'An account already exists from this device. Your existing username is: ' + existing.username, code: 'IP_DUPLICATE', existingUsername: existing.username });
    if (!securityQuestion || !securityAnswer) return res.status(400).json({ error: 'Security question and answer required' });
  }

  const id = uuidv4();
  const uninstallToken = crypto.randomBytes(32).toString('hex');
  const sqHash = securityAnswer ? hash(securityAnswer.toLowerCase().trim()) : null;
  q.createUser.run(id, username, hash(password), userRole, ip, securityQuestion || null, sqHash, uninstallToken, now);
  q.addHistory.run(id, 'registered', null, userRole + ' account created', now);

  res.status(201).json({ id, username, role: userRole, token: makeToken(id), uninstallToken });
});

// ==================== LOGIN ====================
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  const user = q.userByName.get(username);
  if (!user) return res.status(401).json({ error: 'User not found' });
  if (!verify(password, user.password_hash)) return res.status(401).json({ error: 'Wrong password' });

  q.addHistory.run(user.id, 'login', null, 'Logged in', utcNow());
  res.json({ id: user.id, username: user.username, role: user.role, token: makeToken(user.id), uninstallToken: user.uninstall_token });
});

// ==================== SELF-RECOVERY ====================
app.post('/api/recover/question', (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: 'Enter your username' });
  const user = q.userByName.get(username);
  if (!user) return res.status(404).json({ error: 'Username not found' });
  if (!user.security_question) return res.status(400).json({ error: 'No security question set. Contact the account owner.' });
  res.json({ question: user.security_question });
});

app.post('/api/recover/verify', (req, res) => {
  const { username, answer, newPassword } = req.body;
  if (!username || !answer || !newPassword) return res.status(400).json({ error: 'All fields required' });
  if (newPassword.length < 4) return res.status(400).json({ error: 'Password too short (min 4)' });
  const user = q.userByName.get(username);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (!user.security_answer_hash) return res.status(400).json({ error: 'No security question set' });
  if (!verify(answer.toLowerCase().trim(), user.security_answer_hash)) {
    q.addHistory.run(user.id, 'recovery_failed', null, 'Wrong security answer', utcNow());
    return res.status(401).json({ error: 'Wrong answer. Try again or contact the account owner.' });
  }
  q.updatePassword.run(hash(newPassword), user.id);
  q.deleteUserTokens.run(user.id);
  q.addHistory.run(user.id, 'password_recovered', null, 'Reset via security question', utcNow());
  res.json({ success: true, message: 'Password reset! Login with your new password.' });
});

// ==================== UNINSTALL HANDLER ====================
// Extension calls setUninstallURL pointing here. When user removes extension, browser opens this URL.
// This endpoint revokes all active sessions and clears tokens.
app.get('/api/uninstall/:token', (req, res) => {
  const user = q.userByUninstallToken.get(req.params.token);
  if (!user) return res.send('<html><body><h2>Session ended.</h2></body></html>');

  const now = utcNow();
  // Force logout all active sessions
  const active = q.getActiveForUser.all(user.id, now);
  active.forEach(s => {
    sendWS(user.id, { type: 'force-logout', sessionId: s.id, domain: s.domain, reason: 'Extension removed' });
  });
  q.revokeAllForUser.run(user.id);
  q.deleteUserTokens.run(user.id);
  q.addHistory.run(user.id, 'extension_removed', null, 'Extension uninstalled — all sessions revoked', now);

  // Regenerate uninstall token so old one can't be reused
  q.updateUninstallToken.run(crypto.randomBytes(32).toString('hex'), user.id);

  res.send('<html><head><style>body{background:#0a0a0e;color:#f0ece4;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;text-align:center}h2{color:#D4AF37}p{color:#9a968e;margin-top:8px}</style></head><body><div><h2>Elite Access</h2><p>All sessions have been logged out.</p></div></body></html>');
});

// ==================== STANDARD ROUTES ====================
app.get('/api/me', auth, (req, res) => res.json({ id: req.user.id, username: req.user.username, role: req.user.role }));

app.get('/api/user/:username', auth, (req, res) => {
  const u = q.userByName.get(req.params.username);
  if (!u) return res.status(404).json({ error: 'User not found' });
  res.json({ id: u.id, username: u.username, role: u.role, online: clients.has(u.id) });
});

app.post('/api/reset-password', auth, (req, res) => {
  if (req.user.role !== 'owner') return res.status(403).json({ error: 'Owner only' });
  const { username, newPassword } = req.body;
  if (!username || !newPassword || newPassword.length < 4) return res.status(400).json({ error: 'Username and new password (min 4) required' });
  const target = q.userByName.get(username);
  if (!target) return res.status(404).json({ error: 'User not found' });
  const now = utcNow();
  q.updatePassword.run(hash(newPassword), target.id);
  q.deleteUserTokens.run(target.id);
  q.addHistory.run(target.id, 'password_reset', null, 'Reset by owner', now);
  q.addHistory.run(req.user.id, 'reset_password', null, 'Reset password for ' + username, now);
  res.json({ success: true, message: 'Password reset for ' + username });
});

app.get('/api/receivers', auth, (req, res) => {
  if (req.user.role !== 'owner') return res.status(403).json({ error: 'Owner only' });
  res.json({ receivers: q.allReceivers.all() });
});

// ==================== SEND (owner only) ====================
app.post('/api/send', auth, (req, res) => {
  if (req.user.role !== 'owner') return res.status(403).json({ error: 'Only owner can share', code: 'RECEIVER_CANNOT_SEND' });
  const { toUsername, domain, sessionData, duration, customDate } = req.body;
  if (!toUsername || !domain || !sessionData) return res.status(400).json({ error: 'Missing fields' });
  const to = q.userByName.get(toUsername);
  if (!to) return res.status(404).json({ error: 'User not found' });
  if (to.id === req.user.id) return res.status(400).json({ error: 'Cannot send to yourself' });
  const now = utcNow();
  const received = q.checkReceivedDomain.get(req.user.id, domain, now);
  if (received) return res.status(403).json({ error: 'Reshare not allowed', code: 'RESHARE_BLOCKED' });

  const id = uuidv4();
  const expiresAt = calcExpiry(duration || 'unlimited', customDate);
  const durationLabel = duration || 'unlimited';

  q.createSession.run(id, req.user.id, req.user.username, to.id, to.username, domain, JSON.stringify(sessionData), durationLabel, expiresAt, now);
  q.addHistory.run(req.user.id, 'sent', domain, 'To ' + to.username + ' (' + durationLabel + ')', now);
  q.addHistory.run(to.id, 'received', domain, 'From ' + req.user.username + ' (' + durationLabel + ')', now);

  const delivered = sendWS(to.id, { type: 'session-received', sessionId: id, from: req.user.username, domain, durationLabel, expiresAt, sessionData, timestamp: now });
  if (delivered) q.markDelivered.run(id);
  res.json({ id, delivered, message: delivered ? 'Delivered instantly!' : 'User offline — will receive later.' });
});

app.get('/api/inbox', auth, (req, res) => res.json({ sessions: q.getInbox.all(req.user.id, utcNow()) }));
app.get('/api/sent', auth, (req, res) => {
  if (req.user.role !== 'owner') return res.json({ sessions: [] });
  res.json({ sessions: q.getSent.all(req.user.id) });
});

app.get('/api/session/:id', auth, (req, res) => {
  const s = q.getSession.get(req.params.id);
  if (!s) return res.status(404).json({ error: 'Session not found' });
  if (s.to_user_id !== req.user.id) return res.status(403).json({ error: 'Not your session' });
  if (s.revoked) return res.status(410).json({ error: 'Access revoked by sender' });
  if (s.expires_at && new Date(s.expires_at) < new Date()) return res.status(410).json({ error: 'Access expired' });
  q.markApplied.run(s.id);
  q.addHistory.run(req.user.id, 'applied', s.domain, 'Logged into ' + s.domain, utcNow());
  res.json({ id: s.id, domain: s.domain, sessionData: JSON.parse(s.session_data), from: s.from_username });
});

app.post('/api/revoke/:id', auth, (req, res) => {
  if (req.user.role !== 'owner') return res.status(403).json({ error: 'Owner only' });
  const s = q.getSession.get(req.params.id);
  if (!s) return res.status(404).json({ error: 'Not found' });
  if (s.from_user_id !== req.user.id) return res.status(403).json({ error: 'Only sender can revoke' });
  const now = utcNow();
  q.revokeSession.run(req.params.id, req.user.id);
  q.addHistory.run(req.user.id, 'revoked', s.domain, 'Revoked from ' + s.to_username, now);
  q.addHistory.run(s.to_user_id, 'access_revoked', s.domain, 'Revoked by ' + req.user.username, now);
  sendWS(s.to_user_id, { type: 'force-logout', sessionId: req.params.id, domain: s.domain, reason: 'Access revoked by ' + req.user.username });
  res.json({ success: true });
});

app.get('/api/history', auth, (req, res) => res.json({ history: q.getHistory.all(req.user.id) }));

app.post('/api/tamper', auth, (req, res) => {
  const { reason, extensionName } = req.body;
  const now = utcNow();
  q.addHistory.run(req.user.id, 'tamper_detected', null, (extensionName || '') + ' — ' + (reason || 'Tamper'), now);
  const active = q.getActiveForUser.all(req.user.id, now);
  active.forEach(s => sendWS(req.user.id, { type: 'force-logout', sessionId: s.id, domain: s.domain, reason: 'Security violation' }));
  q.deleteUserTokens.run(req.user.id);
  res.json({ ok: true });
});

// ==================== SETTINGS (About info — owner sets, everyone reads) ====================
// Anyone can read (even without auth — so receiver extension can fetch on load)
app.get('/api/about', (req, res) => {
  const row = q.getSetting.get('about');
  if (!row) return res.json({ about: { developer: '', description: '', website: '', instagram: '', facebook: '', twitter: '', telegram: '', email: '' } });
  try { res.json({ about: JSON.parse(row.value) }); } catch(e) { res.json({ about: {} }); }
});

// Only owner can update
app.post('/api/about', auth, (req, res) => {
  if (req.user.role !== 'owner') return res.status(403).json({ error: 'Owner only' });
  const { about } = req.body;
  if (!about) return res.status(400).json({ error: 'About data required' });
  const json = JSON.stringify(about);
  q.setSetting.run('about', json, json);
  res.json({ success: true, message: 'About info updated for all users' });
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
        const user = checkToken(msg.token);
        if (!user) { ws.send(JSON.stringify({ type: 'error', message: 'Invalid token' })); ws.close(); return; }
        userId = user.id; clients.set(userId, ws);
        ws.send(JSON.stringify({ type: 'authenticated', username: user.username, role: user.role }));
        const now = utcNow();
        const pending = q.getInbox.all(userId, now);
        pending.forEach(p => {
          const full = q.getSession.get(p.id);
          if (full && !full.revoked && !full.delivered) {
            ws.send(JSON.stringify({ type: 'session-received', sessionId: p.id, from: p.from_username, domain: p.domain, durationLabel: p.duration_label, expiresAt: p.expires_at, sessionData: JSON.parse(full.session_data), timestamp: p.created_at }));
            q.markDelivered.run(p.id);
          }
        });
      }
      else if (msg.type === 'check-online') { const u = q.userByName.get(msg.username); ws.send(JSON.stringify({ type: 'online-status', username: msg.username, online: u ? clients.has(u.id) : false })); }
      else if (msg.type === 'ping') ws.send('{"type":"pong"}');
    } catch (e) {}
  });
  ws.on('close', () => { if (userId) clients.delete(userId); });
});

setInterval(() => { wss.clients.forEach(ws => { if (!ws.isAlive) return ws.terminate(); ws.isAlive = false; ws.ping(); }); }, 30000);
function sendWS(uid, data) { const ws = clients.get(uid); if (ws?.readyState === 1) { ws.send(JSON.stringify(data)); return true; } return false; }

server.listen(PORT, () => console.log('Elite Access Server v6 on port ' + PORT));
