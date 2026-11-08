require('dotenv').config();
const path = require('path');
const http = require('http');
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const { Server } = require('socket.io');
const fs = require('fs');

const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || 'teigo-dev-secret-change-me-in-production-32chars';
if (JWT_SECRET.length < 16) {
  console.warn('WARNING: JWT_SECRET is short. Set a strong secret in production.');
}
const DATA_DIR = process.env.DATA_DIR || __dirname;
fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new Database(path.join(DATA_DIR, 'teigo.sqlite'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  nick TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  display_name TEXT,
  bio TEXT DEFAULT '',
  emoji TEXT DEFAULT '',
  color TEXT DEFAULT '#b96f4c',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS friend_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  from_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  to_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  status TEXT NOT NULL DEFAULT 'pending',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(from_id, to_id)
);
CREATE TABLE IF NOT EXISTS friendships (
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  friend_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(user_id, friend_id)
);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  channel TEXT NOT NULL,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  text TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_messages_channel_id ON messages(channel, id);
`);

const app = express();
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginResourcePolicy: { policy: 'cross-origin' }
}));
app.use(cors({
  origin: process.env.CORS_ORIGIN
    ? process.env.CORS_ORIGIN.split(',').map(x => x.trim())
    : true
}));
app.use(express.json({ limit: '32kb' }));

const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: process.env.CORS_ORIGIN
      ? process.env.CORS_ORIGIN.split(',').map(x => x.trim())
      : true
  }
});

const publicDir = path.join(__dirname, 'public');
app.use(express.static(publicDir));

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, service: 'TEIGO', version: '1.2.0' });
});

const publicUser = (u) => ({
  nick: u.nick,
  displayName: u.display_name || u.nick,
  bio: u.bio || '',
  emoji: u.emoji || '',
  color: u.color || '#b96f4c'
});

function sign(u) {
  return jwt.sign({ id: u.id, nick: u.nick }, JWT_SECRET, { expiresIn: '30d' });
}

function auth(req, res, next) {
  const raw = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  try {
    const p = jwt.verify(raw, JWT_SECRET);
    const u = db.prepare('SELECT * FROM users WHERE id = ?').get(p.id);
    if (!u) throw new Error('user not found');
    req.user = u;
    next();
  } catch {
    res.status(401).json({ error: 'Требуется войти в аккаунт' });
  }
}

function fail(res, err) {
  if (String(err.message).includes('UNIQUE constraint failed')) {
    return res.status(409).json({ error: 'Такой ник уже занят или запрос уже отправлен' });
  }
  console.error(err);
  return res.status(500).json({ error: 'Внутренняя ошибка сервера' });
}

// ——— Helpers for private chats ———
function dmChannel(id1, id2) {
  const a = Math.min(id1, id2);
  const b = Math.max(id1, id2);
  return `dm:${a}_${b}`;
}

function isPublicChannel(channel) {
  return ['общий', 'знакомства', 'мемы'].includes(channel);
}

function isFriends(userId, otherId) {
  return !!db.prepare(
    'SELECT 1 FROM friendships WHERE user_id = ? AND friend_id = ?'
  ).get(userId, otherId);
}

function canAccessChannel(userId, channel) {
  if (isPublicChannel(channel)) return true;
  if (channel.startsWith('dm:')) {
    const parts = channel.slice(3).split('_');
    if (parts.length !== 2) return false;
    const id1 = Number(parts[0]);
    const id2 = Number(parts[1]);
    if (!id1 || !id2) return false;
    if (userId !== id1 && userId !== id2) return false;
    return isFriends(id1, id2);
  }
  return false;
}

function canPost(userId, channel) {
  return canAccessChannel(userId, channel);
}

// ——— Auth ———
app.post('/api/auth/register', async (req, res) => {
  try {
    const nick = String(req.body.nick || '').trim();
    const password = String(req.body.password || '');
    if (!/^[A-Za-z0-9_]{2,24}$/.test(nick)) {
      return res.status(400).json({ error: 'Ник: английские буквы, цифры и _ (2–24 символа)' });
    }
    if (password.length < 6 || password.length > 200) {
      return res.status(400).json({ error: 'Пароль должен содержать от 6 до 200 символов' });
    }
    const hash = await bcrypt.hash(password, 12);
    const info = db.prepare('INSERT INTO users(nick, password_hash) VALUES(?, ?)').run(nick, hash);
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(info.lastInsertRowid);
    res.status(201).json({ token: sign(user), user: publicUser(user) });
  } catch (e) {
    fail(res, e);
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const nick = String(req.body.nick || '').trim();
    const password = String(req.body.password || '');
    const user = db.prepare('SELECT * FROM users WHERE nick = ? COLLATE NOCASE').get(nick);
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: 'Неверный ник или пароль' });
    }
    res.json({ token: sign(user), user: publicUser(user) });
  } catch (e) {
    fail(res, e);
  }
});

app.get('/api/me', auth, (req, res) => {
  res.json({ user: publicUser(req.user) });
});

app.patch('/api/profile', auth, (req, res) => {
  const displayName = String(req.body.displayName || '').slice(0, 32);
  const bio = String(req.body.bio || '').slice(0, 160);
  const emoji = String(req.body.emoji || '').slice(0, 8);
  const color = /^#[0-9a-f]{6}$/i.test(req.body.color || '') ? req.body.color : '#b96f4c';
  db.prepare('UPDATE users SET display_name = ?, bio = ?, emoji = ?, color = ? WHERE id = ?')
    .run(displayName, bio, emoji, color, req.user.id);
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  res.json({ user: publicUser(user) });
});

// ——— Users ———
app.get('/api/users', auth, (req, res) => {
  const q = String(req.query.q || '').trim().slice(0, 24);
  let users;
  if (q) {
    users = db.prepare(
      "SELECT * FROM users WHERE id <> ? AND nick LIKE ? ESCAPE '\\' COLLATE NOCASE ORDER BY created_at DESC LIMIT 30"
    ).all(req.user.id, `%${q.replace(/[\\%_]/g, '\\$&')}%`);
  } else {
    users = db.prepare('SELECT * FROM users WHERE id <> ? ORDER BY created_at DESC LIMIT 30')
      .all(req.user.id);
  }
  res.json({ users: users.map(publicUser) });
});

// ——— Friends ———
app.get('/api/friends', auth, (req, res) => {
  const friends = db.prepare(
    'SELECT u.* FROM friendships f JOIN users u ON u.id = f.friend_id WHERE f.user_id = ? ORDER BY u.nick'
  ).all(req.user.id);

  const incoming = db.prepare(
    "SELECT r.id, u.nick FROM friend_requests r JOIN users u ON u.id = r.from_id WHERE r.to_id = ? AND r.status = 'pending' ORDER BY r.created_at DESC"
  ).all(req.user.id);

  const outgoing = db.prepare(
    "SELECT u.nick FROM friend_requests r JOIN users u ON u.id = r.to_id WHERE r.from_id = ? AND r.status = 'pending'"
  ).all(req.user.id);

  res.json({
    friends: friends.map(publicUser),
    incoming,
    outgoing: outgoing.map(x => x.nick)
  });
});

app.post('/api/friends/request', auth, (req, res) => {
  try {
    const target = db.prepare('SELECT * FROM users WHERE nick = ? COLLATE NOCASE')
      .get(String(req.body.nick || '').trim());
    if (!target) return res.status(404).json({ error: 'Пользователь не найден' });
    if (target.id === req.user.id) return res.status(400).json({ error: 'Нельзя добавить самого себя' });
    if (db.prepare('SELECT 1 FROM friendships WHERE user_id = ? AND friend_id = ?').get(req.user.id, target.id)) {
      return res.status(409).json({ error: 'Вы уже друзья' });
    }

    const existing = db.prepare(
      "SELECT id FROM friend_requests WHERE from_id = ? AND to_id = ? AND status = 'pending'"
    ).get(req.user.id, target.id);
    if (existing) return res.status(409).json({ error: 'Запрос уже отправлен' });

    const reverse = db.prepare(
      "SELECT id FROM friend_requests WHERE from_id = ? AND to_id = ? AND status = 'pending'"
    ).get(target.id, req.user.id);
    if (reverse) {
      acceptRequest(reverse.id, req.user.id);
      return res.json({ ok: true, accepted: true });
    }

    db.prepare('INSERT INTO friend_requests(from_id, to_id) VALUES(?, ?)').run(req.user.id, target.id);
    io.to(`user:${target.id}`).emit('friend:update');
    res.status(201).json({ ok: true });
  } catch (e) {
    fail(res, e);
  }
});

function acceptRequest(id, userId) {
  const r = db.prepare(
    "SELECT * FROM friend_requests WHERE id = ? AND to_id = ? AND status = 'pending'"
  ).get(id, userId);
  if (!r) return false;

  const tx = db.transaction(() => {
    db.prepare("UPDATE friend_requests SET status = 'accepted' WHERE id = ?").run(id);
    db.prepare('INSERT OR IGNORE INTO friendships(user_id, friend_id) VALUES(?, ?)').run(r.from_id, r.to_id);
    db.prepare('INSERT OR IGNORE INTO friendships(user_id, friend_id) VALUES(?, ?)').run(r.to_id, r.from_id);
  });
  tx();

  io.to(`user:${r.from_id}`).emit('friend:update');
  io.to(`user:${r.to_id}`).emit('friend:update');
  return true;
}

app.post('/api/friends/accept', auth, (req, res) => {
  if (!acceptRequest(Number(req.body.id), req.user.id)) {
    return res.status(404).json({ error: 'Запрос не найден' });
  }
  res.json({ ok: true });
});

app.delete('/api/friends/:nick', auth, (req, res) => {
  const other = db.prepare('SELECT id FROM users WHERE nick = ? COLLATE NOCASE').get(req.params.nick);
  if (!other) return res.status(404).json({ error: 'Пользователь не найден' });

  const tx = db.transaction(() => {
    db.prepare(
      'DELETE FROM friendships WHERE (user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)'
    ).run(req.user.id, other.id, other.id, req.user.id);
  });
  tx();

  io.to(`user:${req.user.id}`).emit('friend:update');
  io.to(`user:${other.id}`).emit('friend:update');
  res.json({ ok: true });
});

// ——— Messages (public + private DM) ———
app.get('/api/messages/:channel', auth, (req, res) => {
  const channel = String(req.params.channel || '').slice(0, 64);
  if (!canAccessChannel(req.user.id, channel)) {
    return res.status(403).json({ error: 'Нет доступа к этому чату' });
  }

  const rows = db.prepare(
    'SELECT m.id, m.text, m.created_at, u.nick FROM messages m JOIN users u ON u.id = m.user_id WHERE m.channel = ? ORDER BY m.id DESC LIMIT 100'
  ).all(channel).reverse();

  res.json({
    messages: rows.map(m => ({
      id: m.id,
      nick: m.nick,
      text: m.text,
      time: new Date(m.created_at + 'Z').toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' })
    }))
  });
});

// Helper: get DM channel with a friend
app.get('/api/dm/:nick', auth, (req, res) => {
  const other = db.prepare('SELECT id, nick FROM users WHERE nick = ? COLLATE NOCASE').get(req.params.nick);
  if (!other) return res.status(404).json({ error: 'Пользователь не найден' });
  if (!isFriends(req.user.id, other.id)) {
    return res.status(403).json({ error: 'Вы не друзья' });
  }
  res.json({ channel: dmChannel(req.user.id, other.id), nick: other.nick });
});

// ——— Socket.IO ———
const online = new Map();

io.use((socket, next) => {
  try {
    const token = socket.handshake.auth?.token;
    const p = jwt.verify(token, JWT_SECRET);
    const u = db.prepare('SELECT id, nick FROM users WHERE id = ?').get(p.id);
    if (!u) throw new Error('unauthorized');
    socket.user = u;
    next();
  } catch {
    next(new Error('unauthorized'));
  }
});

io.on('connection', (socket) => {
  const user = socket.user;
  socket.join(`user:${user.id}`);
  online.set(user.id, (online.get(user.id) || 0) + 1);

  socket.on('channel:join', (channel) => {
    channel = String(channel || '').slice(0, 64);
    if (!canAccessChannel(user.id, channel)) return;

    for (const room of socket.rooms) {
      if (isPublicChannel(room) || (typeof room === 'string' && room.startsWith('dm:'))) {
        socket.leave(room);
      }
    }
    socket.join(channel);
  });

  socket.on('message:send', (payload, ack) => {
    const channel = String(payload?.channel || '').slice(0, 64);
    const text = String(payload?.text || '').trim();

    if (!canPost(user.id, channel) || !text || text.length > 2000) {
      if (typeof ack === 'function') ack({ error: 'Некорректное сообщение' });
      return;
    }

    const info = db.prepare(
      'INSERT INTO messages(channel, user_id, text) VALUES(?, ?, ?)'
    ).run(channel, user.id, text);

    const row = db.prepare(
      'SELECT m.id, m.text, m.created_at, u.nick FROM messages m JOIN users u ON u.id = m.user_id WHERE m.id = ?'
    ).get(info.lastInsertRowid);

    const msg = {
      id: row.id,
      nick: row.nick,
      text: row.text,
      time: new Date(row.created_at + 'Z').toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' })
    };

    io.to(channel).emit('message:new', { channel, message: msg });
    if (typeof ack === 'function') ack({ ok: true, message: msg });
  });

  socket.on('disconnect', () => {
    const n = (online.get(user.id) || 1) - 1;
    if (n <= 0) online.delete(user.id);
    else online.set(user.id, n);
  });
});

app.get('*', (req, res) => {
  res.sendFile(path.join(publicDir, 'index.html'));
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`TEIGO server listening on ${PORT}`);
  console.log(`Data dir: ${DATA_DIR}`);
});
