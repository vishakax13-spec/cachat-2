const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
// fetch is built-in (Node 18+)
const multer = require('multer');

const app = express();

// ===== ANTI-SCRAPE =====
const _rateMap=new Map();
const _uaBlock=['python-requests','scrapy','curl/','wget/','httpx','aiohttp','node-fetch','go-http','java/','libwww','mechanize','phantomjs','headless','selenium','puppeteer','playwright','masscan','nikto','sqlmap'];
function antiScrape(req,res,next){
  const ua=(req.headers['user-agent']||'').toLowerCase();
  const ip=(req.headers['x-forwarded-for']||'').split(',')[0].trim()||req.socket.remoteAddress||'x';
  if(_uaBlock.some(b=>ua.includes(b))||ua.length<8)return res.status(403).json({error:'Forbidden'});
  const now=Date.now();
  if(!_rateMap.has(ip))_rateMap.set(ip,{c:0,r:now+60000});
  const e=_rateMap.get(ip);
  if(now>e.r){e.c=0;e.r=now+60000;}
  if(++e.c>180)return res.status(429).json({error:'Too many requests'});
  if(_rateMap.size>5000){for(const[k,v]of _rateMap)if(now>v.r)_rateMap.delete(k);}
  res.setHeader('X-Content-Type-Options','nosniff');
  res.setHeader('X-Frame-Options','DENY');
  res.setHeader('Cache-Control','no-store');
  next();
}
app.use(antiScrape);

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' }, maxHttpBufferSize: 10e6 });
app.set('io', io);

const JWT_SECRET = process.env.JWT_SECRET || 'cachat_v2_secret_2024';
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '';
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID || '';
const ADMIN_USER = 'aryan_x2.7';
const ADMIN_PASS = 'choti';
const PORT = process.env.PORT || 3000;
const DB_FILE = process.env.DB_PATH || path.join(__dirname, 'cachat.db');
const UPLOAD_DIR = process.env.UPLOAD_DIR || (process.env.DB_PATH ? path.join(path.dirname(process.env.DB_PATH), 'uploads') : path.join(__dirname, 'public', 'uploads'));

if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const db = new Database(DB_FILE);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = OFF');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL COLLATE NOCASE,
    name TEXT DEFAULT '',
    password TEXT NOT NULL,
    email TEXT DEFAULT '',
    bio TEXT DEFAULT '',
    avatar TEXT DEFAULT '',
    verified INTEGER DEFAULT 0,
    banned INTEGER DEFAULT 0,
    ban_reason TEXT DEFAULT '',
    suspended_until INTEGER DEFAULT 0,
    privacy_enabled INTEGER DEFAULT 0,
    privacy_pin TEXT DEFAULT NULL,
    privacy_timer INTEGER DEFAULT 30,
    privacy_password TEXT DEFAULT NULL,
    avatar_color TEXT DEFAULT '#833AB4',
    created_at INTEGER DEFAULT (strftime('%s','now')),
    last_seen INTEGER DEFAULT (strftime('%s','now')),
    phone TEXT DEFAULT '',
    gmail TEXT DEFAULT '',
    is_private INTEGER DEFAULT 0,
    hide_from_suggestions INTEGER DEFAULT 0,
    app_password TEXT DEFAULT NULL,
    app_password_attempts INTEGER DEFAULT 0,
    fake_followers INTEGER DEFAULT 0
  );
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER NOT NULL,
    receiver_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    msg_type TEXT DEFAULT 'text',
    is_edited INTEGER DEFAULT 0,
    is_unsent INTEGER DEFAULT 0,
    is_deleted_sender INTEGER DEFAULT 0,
    is_deleted_receiver INTEGER DEFAULT 0,
    reaction TEXT DEFAULT NULL,
    reply_to INTEGER DEFAULT NULL,
    is_seen INTEGER DEFAULT 0,
    created_at INTEGER DEFAULT (strftime('%s','now'))
  );
  CREATE TABLE IF NOT EXISTS groups_t (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    avatar TEXT DEFAULT '',
    avatar_color TEXT DEFAULT '#833AB4',
    creator_id INTEGER NOT NULL,
    is_public INTEGER DEFAULT 1,
    invite_link TEXT UNIQUE,
    welcome_message TEXT DEFAULT '',
    created_at INTEGER DEFAULT (strftime('%s','now'))
  );
  CREATE TABLE IF NOT EXISTS group_members (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
    role TEXT DEFAULT 'member',
    joined_at INTEGER DEFAULT (strftime('%s','now')),
    UNIQUE(group_id, user_id)
  );
  CREATE TABLE IF NOT EXISTS group_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id INTEGER NOT NULL, sender_id INTEGER NOT NULL,
    content TEXT NOT NULL, msg_type TEXT DEFAULT 'text',
    is_deleted INTEGER DEFAULT 0, reply_to INTEGER DEFAULT NULL,
    created_at INTEGER DEFAULT (strftime('%s','now'))
  );
  CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    music_url TEXT DEFAULT NULL,
    music_name TEXT DEFAULT NULL,
    music_start REAL DEFAULT 0,
    music_end REAL DEFAULT NULL,
    expires_at INTEGER DEFAULT (strftime('%s','now')+86400),
    created_at INTEGER DEFAULT (strftime('%s','now'))
  );
  CREATE TABLE IF NOT EXISTS follows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    follower_id INTEGER NOT NULL, following_id INTEGER NOT NULL,
    created_at INTEGER DEFAULT (strftime('%s','now')),
    UNIQUE(follower_id, following_id)
  );
  CREATE TABLE IF NOT EXISTS follow_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    requester_id INTEGER NOT NULL, target_id INTEGER NOT NULL,
    created_at INTEGER DEFAULT (strftime('%s','now')),
    UNIQUE(requester_id, target_id)
  );
  CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL, body TEXT NOT NULL,
    type TEXT DEFAULT 'info',
    is_read INTEGER DEFAULT 0,
    created_at INTEGER DEFAULT (strftime('%s','now'))
  );
  CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    reporter_id INTEGER NOT NULL, reported_id INTEGER NOT NULL,
    reason TEXT NOT NULL,
    created_at INTEGER DEFAULT (strftime('%s','now'))
  );
  CREATE TABLE IF NOT EXISTS blocks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    blocker_id INTEGER NOT NULL, blocked_id INTEGER NOT NULL,
    UNIQUE(blocker_id, blocked_id)
  );
  CREATE TABLE IF NOT EXISTS group_bans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    reason TEXT DEFAULT '',
    banned_by INTEGER NOT NULL,
    created_at INTEGER DEFAULT (strftime('%s','now')),
    UNIQUE(group_id, user_id)
  );
  CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    media TEXT NOT NULL,
    media_type TEXT DEFAULT 'image',
    caption TEXT DEFAULT '',
    likes TEXT DEFAULT '[]',
    music_url TEXT DEFAULT NULL,
    music_start REAL DEFAULT 0,
    music_end REAL DEFAULT NULL,
    music_name TEXT DEFAULT NULL,
    created_at INTEGER DEFAULT (strftime('%s','now'))
  );
  CREATE TABLE IF NOT EXISTS chat_themes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL, peer_id INTEGER NOT NULL,
    theme TEXT DEFAULT 'default',
    UNIQUE(user_id, peer_id)
  );
  CREATE TABLE IF NOT EXISTS story_likes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    story_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
    UNIQUE(story_id, user_id)
  );
  CREATE TABLE IF NOT EXISTS nicknames (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    giver_id INTEGER NOT NULL,
    target_id INTEGER NOT NULL,
    nickname TEXT NOT NULL,
    created_at INTEGER DEFAULT (strftime('%s','now')),
    UNIQUE(giver_id, target_id)
  );
  CREATE TABLE IF NOT EXISTS post_media (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER NOT NULL,
    media TEXT NOT NULL,
    media_type TEXT DEFAULT 'image',
    position INTEGER DEFAULT 0
  );
  CREATE TABLE IF NOT EXISTS note_replies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    note_owner_id INTEGER NOT NULL,
    replier_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    created_at INTEGER DEFAULT (strftime('%s','now'))
  );
`);

// Safe migrations
[
  'ALTER TABLE users ADD COLUMN fake_followers INTEGER DEFAULT 0',
  'ALTER TABLE users ADD COLUMN privacy_password TEXT DEFAULT NULL',
  'ALTER TABLE messages ADD COLUMN is_deleted_sender INTEGER DEFAULT 0',
  'ALTER TABLE messages ADD COLUMN is_deleted_receiver INTEGER DEFAULT 0',
  'ALTER TABLE messages ADD COLUMN reaction TEXT DEFAULT NULL',
  'ALTER TABLE messages ADD COLUMN is_seen INTEGER DEFAULT 0',
  'ALTER TABLE posts ADD COLUMN music_url TEXT DEFAULT NULL',
  'ALTER TABLE posts ADD COLUMN music_start REAL DEFAULT 0',
  'ALTER TABLE posts ADD COLUMN music_end REAL DEFAULT NULL',
  'ALTER TABLE posts ADD COLUMN music_name TEXT DEFAULT NULL',
  'ALTER TABLE notes ADD COLUMN music_url TEXT DEFAULT NULL',
  'ALTER TABLE notes ADD COLUMN music_name TEXT DEFAULT NULL',
  'ALTER TABLE notes ADD COLUMN music_start REAL DEFAULT 0',
  'ALTER TABLE notes ADD COLUMN music_end REAL DEFAULT NULL',
  'ALTER TABLE groups_t ADD COLUMN welcome_message TEXT DEFAULT ""',
  'ALTER TABLE group_bans ADD COLUMN id INTEGER PRIMARY KEY AUTOINCREMENT',
  'ALTER TABLE posts ADD COLUMN is_multi INTEGER DEFAULT 0',
  'ALTER TABLE users ADD COLUMN hide_from_suggestions INTEGER DEFAULT 0',
].forEach(s => { try { db.exec(s); } catch {} });

app.use(cors());
app.use(express.json({ limit: '100mb' }));
app.use('/uploads', express.static(UPLOAD_DIR));
app.use('/uploads', express.static(path.join(__dirname, 'public', 'uploads')));
app.use(express.static(path.join(__dirname, 'public')));

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname) || '.jpg';
    cb(null, `${Date.now()}_${Math.random().toString(36).slice(2)}${ext}`);
  }
});
const upload = multer({ storage, limits: { fileSize: 500 * 1024 * 1024 } });
const uploadFields = upload.fields([{name:'photo',maxCount:1},{name:'music',maxCount:1},{name:'avatar',maxCount:1}]);

const onlineUsers = new Map();

async function sendTelegram(msg) {
  if (!TELEGRAM_BOT_TOKEN || !TELEGRAM_CHAT_ID) return;
  try {
    await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: TELEGRAM_CHAT_ID, text: msg, parse_mode: 'HTML' })
    });
  } catch {}
}

function pushNotif(userId, title, body, type='info', action_id=null, action_type=null) {
  try {
    db.prepare('INSERT INTO notifications (user_id,title,body,type) VALUES (?,?,?,?)').run(parseInt(userId), title, body, type);
    const sid = onlineUsers.get(parseInt(userId));
    if (sid) io.to(sid).emit('new_notification', { title, body, type, action_id, action_type });
  } catch(e) {}
}

function getDbSizeMB() { try { return fs.statSync(DB_FILE).size / (1024 * 1024); } catch { return 0; } }

// Auto cleanup: delete non-verified messages older than 2 days, expired notes
setInterval(async () => {
  const twoDaysAgo = Math.floor(Date.now() / 1000) - 172800;
  db.prepare(`DELETE FROM messages WHERE created_at < ? AND sender_id IN (SELECT id FROM users WHERE verified=0)`).run(twoDaysAgo);
  db.prepare('DELETE FROM notes WHERE expires_at < ?').run(Math.floor(Date.now() / 1000));
  const mb = getDbSizeMB();
  if (mb >= 370) {
    db.prepare(`DELETE FROM messages WHERE id IN (SELECT m.id FROM messages m JOIN users s ON s.id=m.sender_id JOIN users r ON r.id=m.receiver_id WHERE s.verified=0 AND r.verified=0)`).run();
    await sendTelegram(`🚨 DB ${mb.toFixed(1)}MB — auto-cleaned.`);
  } else if (mb >= 300) {
    await sendTelegram(`⚠️ DB Warning: ${mb.toFixed(1)}MB`);
  }
}, 3600000);

function auth(req, res, next) {
  const t = (req.headers.authorization || '').replace('Bearer ', '');
  if (!t) return res.status(401).json({ error: 'Unauthorized' });
  try { req.user = jwt.verify(t, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid token' }); }
}
function adminAuth(req, res, next) {
  if (req.headers['x-admin-user'] === ADMIN_USER && req.headers['x-admin-pass'] === ADMIN_PASS) return next();
  res.status(403).json({ error: 'Forbidden' });
}

// ── AUTH ─────────────────────────────────────
app.post('/api/register', async (req, res) => {
  try {
    const { username, password, name, phone, gmail } = req.body;
    if (!username?.trim() || !password) return res.status(400).json({ error: 'Username and password required' });
    if (username.trim().length < 3) return res.status(400).json({ error: 'Username min 3 chars' });
    if (password.length < 6) return res.status(400).json({ error: 'Password min 6 chars' });
    if (!/^[a-zA-Z0-9_.]+$/.test(username.trim())) return res.status(400).json({ error: 'Username: letters, numbers, _ and . only' });
    if (db.prepare('SELECT id FROM users WHERE username=?').get(username.trim())) return res.status(409).json({ error: 'Username already taken' });
    const hash = await bcrypt.hash(password, 10);
    const colors = ['#833AB4','#E1306C','#F56040','#FCAF45','#405DE6','#5B51D8','#C13584'];
    const color = colors[Math.floor(Math.random() * colors.length)];
    const r = db.prepare('INSERT INTO users (username,name,password,avatar_color,phone,gmail) VALUES (?,?,?,?,?,?)').run(username.trim(), (name?.trim()) || username.trim(), hash, color, phone||'', gmail||'');
    await sendTelegram(`🆕 New: <code>${username.trim()}</code> (ID:${r.lastInsertRowid})`);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Registration failed' }); }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE username=?').get(username?.trim());
    if (!user) return res.status(401).json({ error: 'Invalid username or password' });
    if (user.banned) return res.status(403).json({ error: `Banned: ${user.ban_reason || 'Policy violation'}` });
    if (!await bcrypt.compare(password, user.password)) return res.status(401).json({ error: 'Invalid username or password' });
    db.prepare('UPDATE users SET last_seen=? WHERE id=?').run(Math.floor(Date.now() / 1000), user.id);
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { id: user.id, username: user.username, name: user.name||user.username, verified: user.verified, avatar: user.avatar, avatar_color: user.avatar_color, bio: user.bio||'', privacy_enabled: user.privacy_enabled||0, privacy_timer: user.privacy_timer||30, suspended_until: user.suspended_until||0, phone: user.phone||'', gmail: user.gmail||'', is_private: user.is_private||0, has_app_password: !!user.app_password, fake_followers: user.fake_followers||0 } });
  } catch { res.status(500).json({ error: 'Login failed' }); }
});

app.post('/api/forgot-password', async (req, res) => {
  try {
    const { contact } = req.body;
    const user = db.prepare('SELECT id,username FROM users WHERE phone=? OR gmail=?').get(contact?.trim(), contact?.trim());
    if (!user) return res.status(404).json({ error: 'No account found' });
    res.json({ success: true, message: `Your username is: ${user.username}. Contact admin to reset password.`, username: user.username });
  } catch { res.status(500).json({ error: 'Failed' }); }
});

// ── USER ─────────────────────────────────────
app.get('/api/me', auth, (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE id=?').get(req.user.id);
  if (!u) return res.status(404).json({ error: 'Not found' });
  res.json({ id:u.id, username:u.username, name:u.name, verified:u.verified, avatar:u.avatar, avatar_color:u.avatar_color, bio:u.bio||'', privacy_enabled:u.privacy_enabled||0, privacy_timer:u.privacy_timer||30, suspended_until:u.suspended_until||0, phone:u.phone||'', gmail:u.gmail||'', is_private:u.is_private||0, has_app_password:!!u.app_password, fake_followers:u.fake_followers||0 });
});

// Change password
app.post('/api/change-password', auth, async (req,res)=>{
  try{
    const{old_password,new_password}=req.body;
    if(!old_password||!new_password)return res.status(400).json({error:'Both passwords required'});
    if(new_password.length<6)return res.status(400).json({error:'New password min 6 chars'});
    const u=db.prepare('SELECT password FROM users WHERE id=?').get(req.user.id);
    if(!await bcrypt.compare(old_password,u.password))return res.status(401).json({error:'Current password is wrong'});
    const hash=await bcrypt.hash(new_password,10);
    db.prepare('UPDATE users SET password=? WHERE id=?').run(hash,req.user.id);
    res.json({success:true});
  }catch(e){res.status(500).json({error:e.message});}
});

app.put('/api/me', auth, async (req, res) => {
  try {
    const { name, bio, username, phone, gmail, is_private } = req.body;
    if (name !== undefined) db.prepare('UPDATE users SET name=? WHERE id=?').run((name||'').slice(0,50), req.user.id);
    if (bio !== undefined) db.prepare('UPDATE users SET bio=? WHERE id=?').run((bio||'').slice(0,150), req.user.id);
    if (phone !== undefined) db.prepare('UPDATE users SET phone=? WHERE id=?').run((phone||'').slice(0,20), req.user.id);
    if (gmail !== undefined) db.prepare('UPDATE users SET gmail=? WHERE id=?').run((gmail||'').slice(0,100), req.user.id);
    if (is_private !== undefined) db.prepare('UPDATE users SET is_private=? WHERE id=?').run(is_private?1:0, req.user.id);
    if (username !== undefined) {
      const u = db.prepare('SELECT verified FROM users WHERE id=?').get(req.user.id);
      if (u?.verified) {
        if (!/^[a-zA-Z0-9_.]+$/.test(username.trim()) || username.trim().length < 3) return res.status(400).json({ error: 'Invalid username' });
        if (db.prepare('SELECT id FROM users WHERE username=? AND id!=?').get(username.trim(), req.user.id)) return res.status(409).json({ error: 'Username taken' });
        db.prepare('UPDATE users SET username=? WHERE id=?').run(username.trim(), req.user.id);
      }
    }
    const u = db.prepare('SELECT * FROM users WHERE id=?').get(req.user.id);
    res.json({ id:u.id, username:u.username, name:u.name, verified:u.verified, avatar:u.avatar, avatar_color:u.avatar_color, bio:u.bio||'', privacy_enabled:u.privacy_enabled||0, privacy_timer:u.privacy_timer||30, suspended_until:u.suspended_until||0, phone:u.phone||'', gmail:u.gmail||'', is_private:u.is_private||0, has_app_password:!!u.app_password, fake_followers:u.fake_followers||0 });
  } catch (e) { res.status(500).json({ error: 'Update failed' }); }
});

app.post('/api/me/avatar', auth, upload.single('avatar'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file' });
    if (req.file.size > 5*1024*1024) { fs.unlink(req.file.path,()=>{}); return res.status(400).json({ error: 'Max 5MB' }); }
    db.prepare('UPDATE users SET avatar=? WHERE id=?').run(`/uploads/${req.file.filename}`, req.user.id);
    res.json({ success: true, avatar: `/uploads/${req.file.filename}` });
  } catch { res.status(500).json({ error: 'Failed' }); }
});

// block_privacy_added
// ===== BLOCK PRIVACY =====
app.get('/api/user/:id', auth, (req,res)=>{
  const blocked = db.prepare('SELECT id FROM blocks WHERE (blocker_id=? AND blocked_id=?) OR (blocker_id=? AND blocked_id=?)').get(req.user.id,req.params.id,req.params.id,req.user.id);
  if(blocked) return res.status(403).json({error:'User not found'});
  const u=db.prepare('SELECT id,username,name,bio,avatar,avatar_color,verified,is_private,fake_followers,last_seen,privacy_enabled,has_app_password,suspended_until FROM users WHERE id=?').get(req.params.id);
  if(!u)return res.status(404).json({error:'Not found'});
  res.json(u);
});

app.get('/api/search', auth, (req, res) => {
  const q = req.query.q?.trim();
  if (!q) {
    const s = db.prepare(`SELECT id,username,name,avatar,avatar_color,verified,is_private FROM users WHERE banned=0 AND id!=? AND is_private=0 AND id NOT IN (SELECT blocked_id FROM blocks WHERE blocker_id=?) ORDER BY RANDOM() LIMIT 10`).all(req.user.id, req.user.id);
    return res.json(s);
  }
  const r = db.prepare(`SELECT id,username,name,avatar,avatar_color,verified,is_private FROM users WHERE banned=0 AND (username LIKE ? OR name LIKE ?) AND id!=? ORDER BY verified DESC LIMIT 20`).all(`%${q}%`,`%${q}%`, req.user.id);
  res.json(r);
});

// ── APP PASSWORD ──────────────────────────────
app.post('/api/app-password/set', auth, async (req, res) => {
  try {
    const { password } = req.body;
    if (!password || password.length < 4) return res.status(400).json({ error: 'Min 4 characters' });
    db.prepare('UPDATE users SET app_password=?,app_password_attempts=0 WHERE id=?').run(await bcrypt.hash(password, 10), req.user.id);
    res.json({ success: true });
  } catch { res.status(500).json({ error: 'Failed' }); }
});
app.post('/api/app-password/remove', auth, async (req, res) => {
  try {
    const { password } = req.body;
    const u = db.prepare('SELECT app_password FROM users WHERE id=?').get(req.user.id);
    if (!u?.app_password) return res.json({ success: true });
    if (!await bcrypt.compare(password, u.app_password)) return res.status(401).json({ error: 'Wrong password' });
    db.prepare('UPDATE users SET app_password=NULL,app_password_attempts=0 WHERE id=?').run(req.user.id);
    res.json({ success: true });
  } catch { res.status(500).json({ error: 'Failed' }); }
});
app.post('/api/app-password/verify', auth, async (req, res) => {
  try {
    const { password } = req.body;
    const u = db.prepare('SELECT app_password,app_password_attempts FROM users WHERE id=?').get(req.user.id);
    if (!u?.app_password) return res.json({ success: true });
    if (u.app_password_attempts >= 4) { db.prepare('UPDATE users SET app_password_attempts=0 WHERE id=?').run(req.user.id); return res.status(401).json({ error: 'Too many attempts', logout: true }); }
    if (!await bcrypt.compare(password, u.app_password)) { db.prepare('UPDATE users SET app_password_attempts=app_password_attempts+1 WHERE id=?').run(req.user.id); const rem=3-u.app_password_attempts; return res.status(401).json({ error: `Wrong password. ${rem} attempt${rem!==1?'s':''} left` }); }
    db.prepare('UPDATE users SET app_password_attempts=0 WHERE id=?').run(req.user.id);
    res.json({ success: true });
  } catch { res.status(500).json({ error: 'Failed' }); }
});

// ── PRIVACY ───────────────────────────────────
app.post('/api/privacy/setup', auth, async (req, res) => {
  try {
    const { enabled, pin, timer, password } = req.body;
    if (enabled) {
      if (!pin || !/^\d{6}$/.test(String(pin))) return res.status(400).json({ error: 'PIN must be 6 digits' });
      const pinHash = await bcrypt.hash(String(pin), 10);
      const passHash = password ? await bcrypt.hash(password, 10) : null;
      db.prepare('UPDATE users SET privacy_enabled=1,privacy_pin=?,privacy_timer=?,privacy_password=? WHERE id=?').run(pinHash, timer||30, passHash, req.user.id);
    } else {
      db.prepare('UPDATE users SET privacy_enabled=0,privacy_pin=NULL,privacy_password=NULL WHERE id=?').run(req.user.id);
    }
    res.json({ success: true });
  } catch { res.status(500).json({ error: 'Failed' }); }
});
app.post('/api/privacy/verify', auth, async (req, res) => {
  try {
    const u = db.prepare('SELECT privacy_pin,privacy_timer FROM users WHERE id=?').get(req.user.id);
    if (!u?.privacy_pin) return res.status(400).json({ error: 'Privacy not set up' });
    if (!await bcrypt.compare(String(req.body.pin), u.privacy_pin)) return res.status(401).json({ error: 'Wrong PIN' });
    res.json({ success: true, timer: u.privacy_timer });
  } catch { res.status(500).json({ error: 'Failed' }); }
});

// ── MESSAGES ──────────────────────────────────
app.get('/api/conversations', auth, (req, res) => {
  try {
    const rows = db.prepare(`
      SELECT CASE WHEN m.sender_id=? THEN m.receiver_id ELSE m.sender_id END AS peer_id,
        u.username,u.name,u.verified,u.avatar,u.avatar_color,u.last_seen,
        m.content AS last_content, m.is_unsent, m.msg_type,
        m.created_at AS last_at, m.sender_id AS last_sender_id
      FROM messages m
      JOIN users u ON u.id=CASE WHEN m.sender_id=? THEN m.receiver_id ELSE m.sender_id END
      WHERE (m.sender_id=? OR m.receiver_id=?) AND u.banned=0
        AND NOT (m.sender_id=? AND m.is_deleted_sender=1)
        AND NOT (m.receiver_id=? AND m.is_deleted_receiver=1)
      GROUP BY peer_id ORDER BY last_at DESC
    `).all(req.user.id,req.user.id,req.user.id,req.user.id,req.user.id,req.user.id);
    res.json(rows);
  } catch { res.status(500).json({ error: 'Failed' }); }
});

app.get('/api/messages/:peerId', auth, (req, res) => {
  try {
    const uid = req.user.id, pid = parseInt(req.params.peerId);
    const msgs = db.prepare(`
      SELECT m.*,s.username AS sender_name,s.name AS sender_display,s.verified AS sender_verified,s.avatar AS sender_avatar,s.avatar_color AS sender_color
      FROM messages m JOIN users s ON s.id=m.sender_id
      WHERE ((m.sender_id=? AND m.receiver_id=? AND m.is_deleted_sender=0) OR (m.sender_id=? AND m.receiver_id=? AND m.is_deleted_receiver=0))
      ORDER BY m.created_at ASC LIMIT 200
    `).all(uid,pid,pid,uid);
    res.json(msgs);
  } catch { res.status(500).json({ error: 'Failed' }); }
});

app.post('/api/messages/seen/:peerId', auth, (req, res) => {
  try {
    db.prepare('UPDATE messages SET is_seen=1 WHERE receiver_id=? AND sender_id=? AND is_seen=0').run(req.user.id, req.params.peerId);
    const recvSock = onlineUsers.get(parseInt(req.params.peerId));
    if (recvSock) io.to(recvSock).emit('messages_seen', { peerId: req.user.id });
    res.json({ success: true });
  } catch { res.status(500).json({ error: 'Failed' }); }
});

app.put('/api/messages/:id/edit', auth, (req, res) => {
  try {
    const { content } = req.body;
    if (!content?.trim()) return res.status(400).json({ error: 'Content required' });
    const msg = db.prepare('SELECT * FROM messages WHERE id=? AND sender_id=?').get(req.params.id, req.user.id);
    if (!msg || msg.is_unsent) return res.status(404).json({ error: 'Not found' });
    db.prepare('UPDATE messages SET content=?,is_edited=1 WHERE id=?').run(content.trim(), req.params.id);
    const updated = db.prepare('SELECT * FROM messages WHERE id=?').get(req.params.id);
    const recvSock = onlineUsers.get(msg.receiver_id);
    if (recvSock) io.to(recvSock).emit('message_updated', updated);
    res.json({ success: true });
  } catch { res.status(500).json({ error: 'Failed' }); }
});

app.put('/api/messages/:id/unsend', auth, (req, res) => {
  try {
    const msg = db.prepare('SELECT * FROM messages WHERE id=? AND sender_id=?').get(req.params.id, req.user.id);
    if (!msg) return res.status(404).json({ error: 'Not found' });
    db.prepare('UPDATE messages SET is_unsent=1,content=? WHERE id=?').run('[Message unsent]', req.params.id);
    const recvSock = onlineUsers.get(msg.receiver_id);
    if (recvSock) io.to(recvSock).emit('message_updated', { id: msg.id, is_unsent: 1, content: '[Message unsent]' });
    res.json({ success: true });
  } catch { res.status(500).json({ error: 'Failed' }); }
});

// Clear history — only delete from my side
app.delete('/api/messages/clear/:peerId', auth, (req, res) => {
  try {
    const uid = req.user.id, pid = parseInt(req.params.peerId);
    db.prepare('UPDATE messages SET is_deleted_sender=1 WHERE sender_id=? AND receiver_id=?').run(uid, pid);
    db.prepare('UPDATE messages SET is_deleted_receiver=1 WHERE sender_id=? AND receiver_id=?').run(pid, uid);
    res.json({ success: true });
  } catch { res.status(500).json({ error: 'Failed' }); }
});

// Delete chat — full delete from DB
app.delete('/api/messages/delete-chat/:peerId', auth, (req, res) => {
  try {
    const uid = req.user.id, pid = parseInt(req.params.peerId);
    db.prepare('DELETE FROM messages WHERE (sender_id=? AND receiver_id=?) OR (sender_id=? AND receiver_id=?)').run(uid,pid,pid,uid);
    res.json({ success: true });
  } catch { res.status(500).json({ error: 'Failed' }); }
});

app.delete('/api/messages/:id', auth, (req, res) => {
  const msg = db.prepare('SELECT * FROM messages WHERE id=?').get(req.params.id);
  if (!msg || msg.sender_id !== req.user.id) return res.status(403).json({ error: 'No permission' });
  db.prepare('DELETE FROM messages WHERE id=?').run(req.params.id);
  const recvSock = onlineUsers.get(msg.receiver_id);
  if (recvSock) io.to(recvSock).emit('message_deleted', { id: parseInt(req.params.id) });
  res.json({ success: true });
});

app.post('/api/messages/:id/react', auth, (req, res) => {
  try {
    const { emoji } = req.body;
    const msg = db.prepare('SELECT * FROM messages WHERE id=?').get(req.params.id);
    if (!msg) return res.status(404).json({ error: 'Not found' });
    let reaction = null;
    try { reaction = msg.reaction ? JSON.parse(msg.reaction) : null; } catch {}
    if (reaction && reaction.user_id === req.user.id && reaction.emoji === emoji) reaction = null;
    else reaction = { emoji, user_id: req.user.id };
    db.prepare('UPDATE messages SET reaction=? WHERE id=?').run(reaction ? JSON.stringify(reaction) : null, req.params.id);
    const other = msg.sender_id === req.user.id ? msg.receiver_id : msg.sender_id;
    const sock = onlineUsers.get(other);
    if (sock) io.to(sock).emit('message_reaction', { id: msg.id, reaction });
    res.json({ success: true, reaction });
  } catch { res.status(500).json({ error: 'Failed' }); }
});

app.post('/api/messages/upload', auth, upload.single('photo'), (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file' });
    if (req.file.size > 8*1024*1024) { fs.unlink(req.file.path,()=>{}); return res.status(400).json({ error: 'Max 8MB' }); }
    res.json({ url: `/uploads/${req.file.filename}` });
  } catch { res.status(500).json({ error: 'Failed' }); }
});

// ── GROUPS ────────────────────────────────────
app.post('/api/groups', auth, (req, res) => {
  try {
    const u = db.prepare('SELECT verified FROM users WHERE id=?').get(req.user.id);
    if (!u?.verified) return res.status(403).json({ error: 'Only verified users can create groups' });
    const { name, description, is_public } = req.body;
    if (!name?.trim()) return res.status(400).json({ error: 'Name required' });
    const link = Math.random().toString(36).slice(2,10)+Math.random().toString(36).slice(2,10);
    const r = db.prepare('INSERT INTO groups_t (name,description,creator_id,is_public,invite_link) VALUES (?,?,?,?,?)').run(name.trim().slice(0,50), description?.slice(0,200)||'', req.user.id, is_public?1:1, link);
    db.prepare('INSERT INTO group_members (group_id,user_id,role) VALUES (?,?,?)').run(r.lastInsertRowid, req.user.id, 'admin');
    res.json({ success: true, id: r.lastInsertRowid });
  } catch { res.status(500).json({ error: 'Failed' }); }
});
app.get('/api/groups', auth, (req, res) => {
  const gs = db.prepare(`SELECT g.*,gm.role AS my_role,(SELECT COUNT(*) FROM group_members WHERE group_id=g.id) AS member_count FROM groups_t g JOIN group_members gm ON gm.group_id=g.id AND gm.user_id=? ORDER BY g.created_at DESC`).all(req.user.id);
  res.json(gs);
});
app.get('/api/groups/:id', auth, (req, res) => {
  const g = db.prepare(`SELECT g.*,gm.role AS my_role,(SELECT COUNT(*) FROM group_members WHERE group_id=g.id) AS member_count FROM groups_t g LEFT JOIN group_members gm ON gm.group_id=g.id AND gm.user_id=? WHERE g.id=?`).get(req.user.id, req.params.id);
  if (!g) return res.status(404).json({ error: 'Not found' });
  res.json(g);
});
app.get('/api/groups/:id/members', auth, (req, res) => {
  res.json(db.prepare(`SELECT u.id,u.username,u.name,u.verified,u.avatar,u.avatar_color,gm.role FROM group_members gm JOIN users u ON u.id=gm.user_id WHERE gm.group_id=? AND u.banned=0 ORDER BY CASE gm.role WHEN 'admin' THEN 0 WHEN 'mod' THEN 1 ELSE 2 END`).all(req.params.id));
});
// join route defined below with welcome support
// join-link route defined below with welcome support
app.post('/api/groups/:id/leave', auth, (req, res) => {
  try { const g=db.prepare('SELECT creator_id FROM groups_t WHERE id=?').get(req.params.id); if(g?.creator_id===req.user.id) return res.status(400).json({error:'Creator cannot leave. Delete group instead.'}); db.prepare('DELETE FROM group_members WHERE group_id=? AND user_id=?').run(req.params.id,req.user.id); res.json({success:true}); } catch { res.status(500).json({error:'Failed'}); }
});
app.delete('/api/groups/:id', auth, (req, res) => {
  try { const m=db.prepare('SELECT role FROM group_members WHERE group_id=? AND user_id=?').get(req.params.id,req.user.id); if(!m||!['admin','mod'].includes(m.role)) return res.status(403).json({error:'No permission'}); db.prepare('DELETE FROM group_messages WHERE group_id=?').run(req.params.id); db.prepare('DELETE FROM group_members WHERE group_id=?').run(req.params.id); db.prepare('DELETE FROM groups_t WHERE id=?').run(req.params.id); res.json({success:true}); } catch { res.status(500).json({error:'Failed'}); }
});
app.put('/api/groups/:id', auth, (req, res) => {
  try { const m=db.prepare('SELECT role FROM group_members WHERE group_id=? AND user_id=?').get(req.params.id,req.user.id); if(!m||!['admin','mod'].includes(m.role)) return res.status(403).json({error:'No permission'}); const{name,description,is_public}=req.body; if(name)db.prepare('UPDATE groups_t SET name=? WHERE id=?').run(name.slice(0,50),req.params.id); if(description!==undefined)db.prepare('UPDATE groups_t SET description=? WHERE id=?').run(description.slice(0,200),req.params.id); if(is_public!==undefined)db.prepare('UPDATE groups_t SET is_public=? WHERE id=?').run(is_public?1:0,req.params.id); res.json({success:true}); } catch { res.status(500).json({error:'Failed'}); }
});
app.post('/api/groups/:id/kick/:uid', auth, (req, res) => {
  try { const m=db.prepare('SELECT role FROM group_members WHERE group_id=? AND user_id=?').get(req.params.id,req.user.id); if(!m||!['admin','mod'].includes(m.role)) return res.status(403).json({error:'No permission'}); db.prepare('DELETE FROM group_members WHERE group_id=? AND user_id=?').run(req.params.id,req.params.uid); res.json({success:true}); } catch { res.status(500).json({error:'Failed'}); }
});
app.get('/api/groups/:id/messages', auth, (req, res) => {
  const m=db.prepare('SELECT id FROM group_members WHERE group_id=? AND user_id=?').get(req.params.id,req.user.id); if(!m) return res.status(403).json({error:'Not a member'});
  res.json(db.prepare(`SELECT gm.*,u.username AS sender_name,u.name AS sender_display,u.verified AS sender_verified,u.avatar AS sender_avatar,u.avatar_color AS sender_color FROM group_messages gm JOIN users u ON u.id=gm.sender_id WHERE gm.group_id=? ORDER BY gm.created_at ASC LIMIT 200`).all(req.params.id));
});
app.delete('/api/groups/:id/messages/:mid', auth, (req, res) => {
  try { const msg=db.prepare('SELECT * FROM group_messages WHERE id=? AND group_id=?').get(req.params.mid,req.params.id); if(!msg) return res.status(404).json({error:'Not found'}); const m=db.prepare('SELECT role FROM group_members WHERE group_id=? AND user_id=?').get(req.params.id,req.user.id); if(msg.sender_id!==req.user.id&&!['admin','mod'].includes(m?.role)) return res.status(403).json({error:'No permission'}); db.prepare("UPDATE group_messages SET is_deleted=1,content='[Message deleted]' WHERE id=?").run(req.params.mid); io.to(`group_${req.params.id}`).emit('group_message_deleted',{id:parseInt(req.params.mid),group_id:parseInt(req.params.id)}); res.json({success:true}); } catch { res.status(500).json({error:'Failed'}); }
});

// ── POSTS (multi-photo support) ──────────────────
app.post('/api/posts', auth, upload.array('photos', 10), async (req, res) => {
  try {
    const user = db.prepare('SELECT verified FROM users WHERE id=?').get(req.user.id);
    if (!user?.verified) return res.status(403).json({ error: 'Only verified users can post' });
    const files = req.files;
    if (!files || !files.length) return res.status(400).json({ error: 'No files' });
    for(const f of files){ if(f.size>20*1024*1024){fs.unlink(f.path,()=>{});return res.status(400).json({error:'Max 20MB per file'});} }
    const { caption } = req.body;
    const firstFile = files[0];
    const isVideo = firstFile.mimetype.startsWith('video');
    const firstUrl = '/uploads/'+firstFile.filename;
    const isMulti = files.length > 1;
    // Insert main post with first media
    const r = db.prepare('INSERT INTO posts (user_id,media,caption,media_type,is_multi) VALUES (?,?,?,?,?)').run(
      req.user.id, firstUrl, caption||'', isVideo?'video':'image', isMulti?1:0
    );
    const postId = r.lastInsertRowid;
    // Insert all media into post_media table
    files.forEach((f,i)=>{
      const isV=f.mimetype.startsWith('video');
      db.prepare('INSERT INTO post_media(post_id,media,media_type,position)VALUES(?,?,?,?)').run(postId,'/uploads/'+f.filename,isV?'video':'image',i);
    });
    res.json({ success: true, id: postId });
  } catch(e) { res.status(500).json({ error: 'Failed: '+e.message }); }
});


app.get('/api/posts', auth, (req, res) => {
  const posts = db.prepare(`SELECT p.*,u.username,u.name,u.avatar,u.avatar_color,u.verified,u.is_private,u.fake_followers FROM posts p JOIN users u ON u.id=p.user_id WHERE u.banned=0 AND (u.is_private=0 OR u.id=? OR EXISTS(SELECT 1 FROM follows f WHERE f.follower_id=? AND f.following_id=u.id)) ORDER BY p.created_at DESC LIMIT 50`).all(req.user.id,req.user.id);
  // Attach all media for multi-photo posts
  posts.forEach(p=>{
    if(p.is_multi){
      p.all_media=db.prepare('SELECT media,media_type FROM post_media WHERE post_id=? ORDER BY position ASC').all(p.id);
    }else{
      p.all_media=[{media:p.media,media_type:p.media_type}];
    }
  });
  res.json(posts);
});
app.get('/api/posts/user/:uid', auth, (req, res) => {
  res.json(db.prepare('SELECT * FROM posts WHERE user_id=? ORDER BY created_at DESC').all(req.params.uid));
});
app.post('/api/posts/:id/like', auth, (req, res) => {
  try {
    const p=db.prepare('SELECT * FROM posts WHERE id=?').get(req.params.id);
    if(!p) return res.status(404).json({error:'Not found'});
    let likes=[];try{likes=JSON.parse(p.likes||'[]');}catch{}
    const i=likes.indexOf(req.user.id);
    if(i===-1){
      likes.push(req.user.id);
      // Notify post owner (not self)
      if(p.user_id!==req.user.id){
        const liker=db.prepare('SELECT username,name FROM users WHERE id=?').get(req.user.id);
        pushNotif(p.user_id,'❤️ New Like','@'+(liker?.username||'Someone')+' liked your post','info',req.user.id,'chat');
      }
    } else {
      likes.splice(i,1);
    }
    db.prepare('UPDATE posts SET likes=? WHERE id=?').run(JSON.stringify(likes),req.params.id);
    res.json({likes:likes.length,liked:i===-1});
  } catch(e) { res.status(500).json({error:'Failed'}); }
});
app.delete('/api/posts/:id', auth, (req, res) => {
  const p=db.prepare('SELECT * FROM posts WHERE id=? AND user_id=?').get(req.params.id,req.user.id);
  if(!p) return res.status(403).json({error:'No permission'});
  if(p.music_url){const mp=path.join(UPLOAD_DIR,path.basename(p.music_url));if(fs.existsSync(mp))fs.unlink(mp,()=>{});}
  const fp=path.join(UPLOAD_DIR,path.basename(p.media));if(fs.existsSync(fp))fs.unlink(fp,()=>{});
  db.prepare('DELETE FROM posts WHERE id=?').run(req.params.id);
  res.json({ success: true });
});

// ── NOTES (verified only) ─────────────────────
app.post('/api/notes', auth, upload.single('music'), (req, res) => {
  try {
    const u = db.prepare('SELECT verified FROM users WHERE id=?').get(req.user.id);
    if (!u?.verified) return res.status(403).json({ error: 'Only verified users can post notes' });
    const { content, music_name, music_start, music_end } = req.body;
    if (!content?.trim() || content.trim().length > 60) return res.status(400).json({ error: 'Max 60 chars' });
    // Delete old note (and old music file if exists)
    const oldNote = db.prepare('SELECT music_url FROM notes WHERE user_id=?').get(req.user.id);
    if (oldNote?.music_url) {
      const oldPath = path.join(UPLOAD_DIR, path.basename(oldNote.music_url));
      fs.unlink(oldPath, ()=>{});
    }
    db.prepare('DELETE FROM notes WHERE user_id=?').run(req.user.id);
    const musicUrl = req.file ? `/uploads/${req.file.filename}` : null;
    // Max 30 sec enforced via music_end - music_start check
    const mStart = parseFloat(music_start)||0;
    let mEnd = parseFloat(music_end)||null;
    if(mEnd && (mEnd - mStart) > 30) mEnd = mStart + 30;
    db.prepare('INSERT INTO notes (user_id,content,music_url,music_name,music_start,music_end) VALUES (?,?,?,?,?,?)').run(
      req.user.id, content.trim(), musicUrl, music_name||null, mStart, mEnd
    );
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: 'Failed: '+e.message }); }
});
app.delete('/api/notes', auth, (req, res) => {
  const note = db.prepare('SELECT music_url FROM notes WHERE user_id=?').get(req.user.id);
  if(note?.music_url){const p=path.join(UPLOAD_DIR,path.basename(note.music_url));fs.unlink(p,()=>{});}
  db.prepare('DELETE FROM notes WHERE user_id=?').run(req.user.id);
  res.json({ success: true });
});
app.get('/api/notes', auth, (req, res) => {
  const now = Math.floor(Date.now() / 1000);
  const notes = db.prepare(`SELECT n.*,u.username,u.name,u.avatar,u.avatar_color FROM notes n JOIN users u ON u.id=n.user_id WHERE n.expires_at>? AND (n.user_id=? OR EXISTS(SELECT 1 FROM follows f1 WHERE f1.follower_id=? AND f1.following_id=n.user_id) AND EXISTS(SELECT 1 FROM follows f2 WHERE f2.follower_id=n.user_id AND f2.following_id=?)) ORDER BY n.created_at DESC`).all(now, req.user.id, req.user.id, req.user.id);
  res.json(notes);
});

// ── FOLLOW ────────────────────────────────────
app.post('/api/follow/:id', auth, async (req, res) => {
  try {
    const target = db.prepare('SELECT id,username,is_private FROM users WHERE id=?').get(req.params.id);
    if (!target) return res.status(404).json({ error: 'Not found' });
    const existing = db.prepare('SELECT id FROM follows WHERE follower_id=? AND following_id=?').get(req.user.id, req.params.id);
    if (existing) { db.prepare('DELETE FROM follows WHERE follower_id=? AND following_id=?').run(req.user.id, req.params.id); return res.json({ following: false }); }
    if (target.is_private) { db.prepare('INSERT OR IGNORE INTO follow_requests (requester_id,target_id) VALUES (?,?)').run(req.user.id, req.params.id); pushNotif(req.params.id, '👤 Follow Request', 'Someone wants to follow you.','info',req.user.id,'chat'); return res.json({ following: false, requested: true }); }
    db.prepare('INSERT OR IGNORE INTO follows (follower_id,following_id) VALUES (?,?)').run(req.user.id, req.params.id);
    res.json({ following: true });
  } catch { res.status(500).json({ error: 'Failed' }); }
});
app.get('/api/follow-status/:id', auth, (req, res) => {
  const following=!!db.prepare('SELECT id FROM follows WHERE follower_id=? AND following_id=?').get(req.user.id,req.params.id);
  const requested=!!db.prepare('SELECT id FROM follow_requests WHERE requester_id=? AND target_id=?').get(req.user.id,req.params.id);
  const followers=db.prepare('SELECT COUNT(*) as c FROM follows WHERE following_id=?').get(req.params.id).c;
  const following_count=db.prepare('SELECT COUNT(*) as c FROM follows WHERE follower_id=?').get(req.params.id).c;
  const follows_me=!!db.prepare('SELECT id FROM follows WHERE follower_id=? AND following_id=?').get(req.params.id,req.user.id);
  const fakeF=db.prepare('SELECT fake_followers FROM users WHERE id=?').get(req.params.id)?.fake_followers||0;
  res.json({ following, requested, followers:followers+fakeF, following_count, follows_me });
});
app.get('/api/followers/:id', auth, (req, res) => {
  const t=db.prepare('SELECT is_private FROM users WHERE id=?').get(req.params.id); if(!t) return res.status(404).json({error:'Not found'});
  const isSelf=parseInt(req.params.id)===req.user.id; const isF=!!db.prepare('SELECT id FROM follows WHERE follower_id=? AND following_id=?').get(req.user.id,req.params.id);
  if(t.is_private&&!isSelf&&!isF) return res.status(403).json({error:'Private account'});
  res.json(db.prepare(`SELECT u.id,u.username,u.name,u.verified,u.avatar,u.avatar_color FROM follows f JOIN users u ON u.id=f.follower_id WHERE f.following_id=? AND u.banned=0 ORDER BY f.created_at DESC`).all(req.params.id));
});
app.get('/api/following/:id', auth, (req, res) => {
  const t=db.prepare('SELECT is_private FROM users WHERE id=?').get(req.params.id); if(!t) return res.status(404).json({error:'Not found'});
  const isSelf=parseInt(req.params.id)===req.user.id; const isF=!!db.prepare('SELECT id FROM follows WHERE follower_id=? AND following_id=?').get(req.user.id,req.params.id);
  if(t.is_private&&!isSelf&&!isF) return res.status(403).json({error:'Private account'});
  res.json(db.prepare(`SELECT u.id,u.username,u.name,u.verified,u.avatar,u.avatar_color FROM follows f JOIN users u ON u.id=f.following_id WHERE f.follower_id=? AND u.banned=0 ORDER BY f.created_at DESC`).all(req.params.id));
});
app.get('/api/follow-requests', auth, (req, res) => { res.json(db.prepare(`SELECT fr.*,u.username,u.name,u.avatar,u.avatar_color FROM follow_requests fr JOIN users u ON u.id=fr.requester_id WHERE fr.target_id=?`).all(req.user.id)); });
app.post('/api/follow-requests/:id/accept', auth, (req, res) => { const r=db.prepare('SELECT * FROM follow_requests WHERE id=? AND target_id=?').get(req.params.id,req.user.id); if(!r) return res.status(404).json({error:'Not found'}); db.prepare('INSERT OR IGNORE INTO follows (follower_id,following_id) VALUES (?,?)').run(r.requester_id,req.user.id); db.prepare('DELETE FROM follow_requests WHERE id=?').run(req.params.id); res.json({success:true}); });
app.post('/api/follow-requests/:id/decline', auth, (req, res) => { db.prepare('DELETE FROM follow_requests WHERE id=? AND target_id=?').run(req.params.id,req.user.id); res.json({success:true}); });

// ── BLOCKS & REPORTS ──────────────────────────
app.post('/api/block/:id', auth, (req, res) => { db.prepare('INSERT OR IGNORE INTO blocks (blocker_id,blocked_id) VALUES (?,?)').run(req.user.id,req.params.id); res.json({success:true}); });
app.delete('/api/block/:id', auth, (req, res) => { db.prepare('DELETE FROM blocks WHERE blocker_id=? AND blocked_id=?').run(req.user.id,req.params.id); res.json({success:true}); });
app.get('/api/blocks', auth, (req, res) => { res.json(db.prepare(`SELECT u.id,u.username,u.name,u.avatar,u.avatar_color FROM blocks b JOIN users u ON u.id=b.blocked_id WHERE b.blocker_id=?`).all(req.user.id)); });
app.post('/api/report', auth, (req, res) => { const{reported_id,reason}=req.body; if(!reported_id||!reason) return res.status(400).json({error:'Missing fields'}); db.prepare('INSERT INTO reports (reporter_id,reported_id,reason) VALUES (?,?,?)').run(req.user.id,reported_id,reason); res.json({success:true}); });

// ── NOTIFICATIONS ─────────────────────────────
app.get('/api/notifications', auth, (req, res) => { res.json(db.prepare('SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 50').all(req.user.id)); });
app.put('/api/notifications/:id/read', auth, (req, res) => { db.prepare('UPDATE notifications SET is_read=1 WHERE id=? AND user_id=?').run(req.params.id,req.user.id); res.json({success:true}); });
app.put('/api/notifications/read-all', auth, (req, res) => { db.prepare('UPDATE notifications SET is_read=1 WHERE user_id=?').run(req.user.id); res.json({success:true}); });

// ── CHAT THEME ────────────────────────────────
app.get('/api/chat-theme/:peerId', auth, (req, res) => { const t=db.prepare('SELECT theme FROM chat_themes WHERE user_id=? AND peer_id=?').get(req.user.id,req.params.peerId); res.json({theme:t?.theme||'default'}); });
app.post('/api/chat-theme/:peerId', auth, (req, res) => { const{theme}=req.body; db.prepare('INSERT OR REPLACE INTO chat_themes (user_id,peer_id,theme) VALUES (?,?,?)').run(req.user.id,req.params.peerId,theme||'default'); res.json({success:true}); });

// ── DELETE ACCOUNT ────────────────────────────
app.delete('/api/me', auth, async (req, res) => {
  try {
    const uid = req.user.id;
    const user = db.prepare('SELECT username FROM users WHERE id=?').get(uid);
    db.prepare('DELETE FROM messages WHERE sender_id=? OR receiver_id=?').run(uid,uid);
    db.prepare('DELETE FROM follows WHERE follower_id=? OR following_id=?').run(uid,uid);
    db.prepare('DELETE FROM follow_requests WHERE requester_id=? OR target_id=?').run(uid,uid);
    db.prepare('DELETE FROM blocks WHERE blocker_id=? OR blocked_id=?').run(uid,uid);
    db.prepare('DELETE FROM notifications WHERE user_id=?').run(uid);
    db.prepare('DELETE FROM posts WHERE user_id=?').run(uid);
    db.prepare('DELETE FROM notes WHERE user_id=?').run(uid);
    db.prepare('DELETE FROM reports WHERE reporter_id=? OR reported_id=?').run(uid,uid);
    db.prepare('DELETE FROM users WHERE id=?').run(uid);
    await sendTelegram(`🗑️ Account deleted: <code>${user?.username}</code>`);
    res.json({ success: true });
  } catch { res.status(500).json({ error: 'Failed' }); }
});

// ── ADMIN ─────────────────────────────────────
app.get('/api/admin/stats', adminAuth, (req, res) => {
  res.json({
    totalUsers: db.prepare('SELECT COUNT(*) as c FROM users').get().c,
    totalMessages: db.prepare('SELECT COUNT(*) as c FROM messages').get().c,
    totalPosts: db.prepare('SELECT COUNT(*) as c FROM posts').get().c,
    totalGroups: db.prepare('SELECT COUNT(*) as c FROM groups_t').get().c,
    totalReports: db.prepare('SELECT COUNT(*) as c FROM reports').get().c,
    dbSizeMB: getDbSizeMB().toFixed(2)
  });
});
app.get('/api/admin/users', adminAuth, (req, res) => {
  // Admin can see all passwords and privacy pins
  res.json(db.prepare('SELECT id,username,name,password,verified,banned,ban_reason,suspended_until,created_at,last_seen,phone,gmail,avatar,avatar_color,app_password,privacy_pin,privacy_password,fake_followers FROM users ORDER BY created_at DESC').all());
});
app.post('/api/admin/verify/:id', adminAuth, (req, res) => { db.prepare('UPDATE users SET verified=? WHERE id=?').run(req.body.verified?1:0,req.params.id); res.json({success:true}); });
app.post('/api/admin/ban/:id', adminAuth, async (req, res) => {
  const{ban,reason}=req.body; const u=db.prepare('SELECT username FROM users WHERE id=?').get(req.params.id); if(!u) return res.status(404).json({error:'Not found'});
  db.prepare('UPDATE users SET banned=?,ban_reason=? WHERE id=?').run(ban?1:0,reason||'',req.params.id);
  if(ban)pushNotif(req.params.id,'🔨 Banned',`Reason: ${reason||'Policy violation'}`,'warning');
  else pushNotif(req.params.id,'✅ Unbanned','Your account has been restored.','success');
  await sendTelegram(ban?`🔨 Banned: <code>${u.username}</code>`:`✅ Unbanned: <code>${u.username}</code>`);
  res.json({success:true});
});
app.post('/api/admin/suspend/:id', adminAuth, async (req, res) => {
  const{days,reason}=req.body; const u=db.prepare('SELECT username FROM users WHERE id=?').get(req.params.id); if(!u) return res.status(404).json({error:'Not found'});
  const d=parseInt(days)||0; db.prepare('UPDATE users SET suspended_until=? WHERE id=?').run(d>0?Math.floor(Date.now()/1000)+d*86400:0,req.params.id);
  if(d>0)pushNotif(req.params.id,`⏸️ Suspended ${d}d`,`Reason: ${reason||'Policy violation'}`,'warning');
  else pushNotif(req.params.id,'✅ Unsuspended','Suspension removed.','success');
  res.json({success:true});
});
app.post('/api/admin/notify/:id', adminAuth, (req, res) => { const{title,body,type}=req.body; if(!title||!body) return res.status(400).json({error:'Missing'}); pushNotif(req.params.id,title,body,type||'info'); res.json({success:true}); });
app.post('/api/admin/broadcast', adminAuth, async (req, res) => {
  const{title,body,type}=req.body; if(!title||!body) return res.status(400).json({error:'Missing'});
  const users=db.prepare('SELECT id FROM users WHERE banned=0').all();
  const stmt=db.prepare('INSERT INTO notifications (user_id,title,body,type) VALUES (?,?,?,?)');
  users.forEach(u=>stmt.run(u.id,title,body,type||'broadcast'));
  io.emit('new_notification',{title,body,type:type||'broadcast'});
  await sendTelegram(`📢 Broadcast: ${title}\n${body}`);
  res.json({success:true,sent:users.length});
});
app.delete('/api/admin/user/:id', adminAuth, async (req, res) => {
  const u=db.prepare('SELECT username FROM users WHERE id=?').get(req.params.id); if(!u) return res.status(404).json({error:'Not found'});
  const uid=req.params.id;
  db.prepare('DELETE FROM messages WHERE sender_id=? OR receiver_id=?').run(uid,uid);
  db.prepare('DELETE FROM follows WHERE follower_id=? OR following_id=?').run(uid,uid);
  db.prepare('DELETE FROM blocks WHERE blocker_id=? OR blocked_id=?').run(uid,uid);
  db.prepare('DELETE FROM reports WHERE reporter_id=? OR reported_id=?').run(uid,uid);
  db.prepare('DELETE FROM notifications WHERE user_id=?').run(uid);
  db.prepare('DELETE FROM posts WHERE user_id=?').run(uid);
  db.prepare('DELETE FROM notes WHERE user_id=?').run(uid);
  db.prepare('DELETE FROM users WHERE id=?').run(uid);
  await sendTelegram(`🗑️ Admin deleted: <code>${u.username}</code>`);
  res.json({success:true});
});
app.post('/api/admin/reset-app-password/:id', adminAuth, (req, res) => { db.prepare('UPDATE users SET app_password=NULL,app_password_attempts=0 WHERE id=?').run(req.params.id); res.json({success:true}); });
app.post('/api/admin/set-fake-followers/:id', adminAuth, (req, res) => { const{count}=req.body; db.prepare('UPDATE users SET fake_followers=? WHERE id=?').run(parseInt(count)||0,req.params.id); res.json({success:true}); });
app.get('/api/admin/reports', adminAuth, (req, res) => { res.json(db.prepare('SELECT rp.*,u1.username AS reporter,u2.username AS reported FROM reports rp JOIN users u1 ON u1.id=rp.reporter_id JOIN users u2 ON u2.id=rp.reported_id ORDER BY rp.created_at DESC').all()); });
// Generate fake account
app.post('/api/admin/generate-fake', adminAuth, async (req, res) => {
  try {
    const{username,name,password,verified}=req.body;
    if(!username||!password) return res.status(400).json({error:'Username and password required'});
    if(db.prepare('SELECT id FROM users WHERE username=?').get(username)) return res.status(409).json({error:'Username taken'});
    const hash=await bcrypt.hash(password,10);
    const colors=['#833AB4','#E1306C','#F56040','#FCAF45','#405DE6'];
    const r=db.prepare('INSERT INTO users (username,name,password,avatar_color,verified) VALUES (?,?,?,?,?)').run(username,name||username,hash,colors[Math.floor(Math.random()*colors.length)],verified?1:0);
    res.json({success:true,id:r.lastInsertRowid});
  } catch { res.status(500).json({error:'Failed'}); }
});
app.delete('/api/admin/messages/:uid', adminAuth, (req, res) => { db.prepare('DELETE FROM messages WHERE sender_id=? OR receiver_id=?').run(req.params.uid,req.params.uid); res.json({success:true}); });
app.post('/api/admin/clean', adminAuth, (req, res) => { const t=Math.floor(Date.now()/1000)-172800; db.prepare(`DELETE FROM messages WHERE created_at<? AND sender_id IN(SELECT id FROM users WHERE verified=0)`).run(t); res.json({success:true}); });

// Delete own account
app.delete('/api/me', auth, async (req,res)=>{
  try{
    const uid=req.user.id;
    const u=db.prepare('SELECT username FROM users WHERE id=?').get(uid);
    db.prepare('DELETE FROM messages WHERE sender_id=? OR receiver_id=?').run(uid,uid);
    db.prepare('DELETE FROM follows WHERE follower_id=? OR following_id=?').run(uid,uid);
    db.prepare('DELETE FROM blocks WHERE blocker_id=? OR blocked_id=?').run(uid,uid);
    db.prepare('DELETE FROM notifications WHERE user_id=?').run(uid);
    db.prepare('DELETE FROM posts WHERE user_id=?').run(uid);
    db.prepare('DELETE FROM notes WHERE user_id=?').run(uid);
    db.prepare('DELETE FROM reports WHERE reporter_id=? OR reported_id=?').run(uid,uid);
    db.prepare('DELETE FROM users WHERE id=?').run(uid);
    await sendTelegram(`🗑️ Self-deleted: <code>${u?.username}</code>`);
    res.json({success:true});
  }catch{res.status(500).json({error:'Failed'});}
});

// Admin: get all passwords (plain text stored for app/privacy, bcrypt for account)
app.get('/api/admin/passwords', adminAuth, (req,res)=>{
  const users=db.prepare('SELECT id,username,password,app_password,privacy_pin,privacy_password FROM users ORDER BY id DESC').all();
  res.json(users.map(u=>({
    id:u.id, username:u.username,
    account_password_hash:u.password,
    app_password_set:!!u.app_password,
    privacy_pin_set:!!u.privacy_pin,
    privacy_password_set:!!u.privacy_password
  })));
});

// Admin: add fake followers to user
app.post('/api/admin/fake-followers/:id', adminAuth, (req,res)=>{
  const{count}=req.body;
  db.prepare('UPDATE users SET fake_followers=? WHERE id=?').run(parseInt(count)||0, req.params.id);
  res.json({success:true});
});

// ── GROUP ADMIN FEATURES ─────────────────────────

// Make member admin/mod
app.post('/api/groups/:id/role/:uid', auth, (req,res)=>{
  try{
    const m=db.prepare('SELECT role FROM group_members WHERE group_id=? AND user_id=?').get(req.params.id, req.user.id);
    const g=db.prepare('SELECT creator_id FROM groups_t WHERE id=?').get(req.params.id);
    if(!m||!['admin'].includes(m.role)&&g?.creator_id!==req.user.id) return res.status(403).json({error:'No permission'});
    const{role}=req.body;
    if(!['admin','mod','member'].includes(role)) return res.status(400).json({error:'Invalid role'});
    db.prepare('UPDATE group_members SET role=? WHERE group_id=? AND user_id=?').run(role, req.params.id, req.params.uid);
    res.json({success:true});
  }catch(e){res.status(500).json({error:e.message});}
});

// Ban member from group
app.post('/api/groups/:id/ban/:uid', auth, (req,res)=>{
  try{
    const m=db.prepare('SELECT role FROM group_members WHERE group_id=? AND user_id=?').get(req.params.id, req.user.id);
    if(!m||!['admin','mod'].includes(m.role)) return res.status(403).json({error:'No permission'});
    const{reason}=req.body;
    // Remove from members
    db.prepare('DELETE FROM group_members WHERE group_id=? AND user_id=?').run(req.params.id, req.params.uid);
    // Add to bans
    db.prepare('INSERT OR REPLACE INTO group_bans(group_id,user_id,reason,banned_by)VALUES(?,?,?,?)').run(req.params.id, req.params.uid, reason||'', req.user.id);
    // Notify
    const g=db.prepare('SELECT name FROM groups_t WHERE id=?').get(req.params.id);
    const sid=onlineUsers.get(parseInt(req.params.uid));
    if(sid) io.to(sid).emit('group_banned',{group_id:parseInt(req.params.id),group_name:g?.name});
    res.json({success:true});
  }catch(e){res.status(500).json({error:e.message});}
});

// Unban member from group
app.delete('/api/groups/:id/ban/:uid', auth, (req,res)=>{
  try{
    const m=db.prepare('SELECT role FROM group_members WHERE group_id=? AND user_id=?').get(req.params.id, req.user.id);
    if(!m||!['admin','mod'].includes(m.role)) return res.status(403).json({error:'No permission'});
    db.prepare('DELETE FROM group_bans WHERE group_id=? AND user_id=?').run(req.params.id, req.params.uid);
    res.json({success:true});
  }catch(e){res.status(500).json({error:e.message});}
});

// Get banned list
app.get('/api/groups/:id/bans', auth, (req,res)=>{
  const m=db.prepare('SELECT role FROM group_members WHERE group_id=? AND user_id=?').get(req.params.id, req.user.id);
  if(!m||!['admin','mod'].includes(m.role)) return res.status(403).json({error:'No permission'});
  res.json(db.prepare('SELECT gb.*,u.username,u.name,u.avatar,u.avatar_color FROM group_bans gb JOIN users u ON u.id=gb.user_id WHERE gb.group_id=?').all(req.params.id));
});

// Set welcome message
app.put('/api/groups/:id/welcome', auth, (req,res)=>{
  try{
    const m=db.prepare('SELECT role FROM group_members WHERE group_id=? AND user_id=?').get(req.params.id, req.user.id);
    if(!m||!['admin','mod'].includes(m.role)) return res.status(403).json({error:'No permission'});
    const{message}=req.body;
    db.prepare('UPDATE groups_t SET welcome_message=? WHERE id=?').run((message||'').slice(0,200), req.params.id);
    res.json({success:true});
  }catch(e){res.status(500).json({error:e.message});}
});

// Override join to check ban + send welcome message
app.post('/api/groups/:id/join', auth, (req,res)=>{
  try{
    const g=db.prepare('SELECT * FROM groups_t WHERE id=?').get(req.params.id);
    if(!g) return res.status(404).json({error:'Not found'});
    if(!g.is_public) return res.status(403).json({error:'Private group — need invite link'});
    const banned=db.prepare('SELECT id FROM group_bans WHERE group_id=? AND user_id=?').get(req.params.id, req.user.id);
    if(banned) return res.status(403).json({error:'You are banned from this group'});
    const already=db.prepare('SELECT id FROM group_members WHERE group_id=? AND user_id=?').get(req.params.id, req.user.id);
    if(already) return res.json({success:true,already:true});
    db.prepare('INSERT OR IGNORE INTO group_members(group_id,user_id)VALUES(?,?)').run(req.params.id, req.user.id);
    // Send welcome message if set
    if(g.welcome_message?.trim()){
      const joiner=db.prepare('SELECT username,name FROM users WHERE id=?').get(req.user.id);
      const wMsg=g.welcome_message.replace('{name}',joiner?.name||joiner?.username||'Member').replace('{username}','@'+(joiner?.username||''));
      const r=db.prepare('INSERT INTO group_messages(group_id,sender_id,content,msg_type)VALUES(?,?,?,?)').run(req.params.id, req.user.id, wMsg, 'system');
      const msg=db.prepare('SELECT gm.*,u.username AS sender_name,u.name AS sender_display,u.verified AS sender_verified,u.avatar AS sender_avatar,u.avatar_color AS sender_color FROM group_messages gm JOIN users u ON u.id=gm.sender_id WHERE gm.id=?').get(r.lastInsertRowid);
      io.to(`group_${req.params.id}`).emit('new_group_message', msg);
    }
    res.json({success:true});
  }catch(e){res.status(500).json({error:e.message});}
});

// Same for join by link
app.post('/api/groups/join-link/:link', auth, (req,res)=>{
  try{
    const g=db.prepare('SELECT * FROM groups_t WHERE invite_link=?').get(req.params.link);
    if(!g) return res.status(404).json({error:'Invalid link'});
    const banned=db.prepare('SELECT id FROM group_bans WHERE group_id=? AND user_id=?').get(g.id, req.user.id);
    if(banned) return res.status(403).json({error:'You are banned from this group'});
    const already=db.prepare('SELECT id FROM group_members WHERE group_id=? AND user_id=?').get(g.id, req.user.id);
    if(already) return res.json({success:true,group_id:g.id,already:true});
    db.prepare('INSERT OR IGNORE INTO group_members(group_id,user_id)VALUES(?,?)').run(g.id, req.user.id);
    if(g.welcome_message?.trim()){
      const joiner=db.prepare('SELECT username,name FROM users WHERE id=?').get(req.user.id);
      const wMsg=g.welcome_message.replace('{name}',joiner?.name||joiner?.username||'Member').replace('{username}','@'+(joiner?.username||''));
      const r=db.prepare('INSERT INTO group_messages(group_id,sender_id,content,msg_type)VALUES(?,?,?,?)').run(g.id, req.user.id, wMsg, 'system');
      const msg=db.prepare('SELECT gm.*,u.username AS sender_name,u.name AS sender_display,u.verified AS sender_verified,u.avatar AS sender_avatar,u.avatar_color AS sender_color FROM group_messages gm JOIN users u ON u.id=gm.sender_id WHERE gm.id=?').get(r.lastInsertRowid);
      io.to(`group_${g.id}`).emit('new_group_message', msg);
    }
    res.json({success:true,group_id:g.id});
  }catch(e){res.status(500).json({error:e.message});}
});

// Admin: ping user (update last_seen to keep them active)
app.post('/api/admin/ping-user/:id', adminAuth, (req,res)=>{
  db.prepare('UPDATE users SET last_seen=? WHERE id=?').run(Math.floor(Date.now()/1000), req.params.id);
  res.json({success:true});
});
// Admin: add user to group directly
app.post('/api/admin/add-group-member', adminAuth, (req,res)=>{
  try{
    const{group_id,user_id}=req.body;
    if(!group_id||!user_id)return res.status(400).json({error:'group_id and user_id required'});
    db.prepare('INSERT OR IGNORE INTO group_members(group_id,user_id,role)VALUES(?,?,?)').run(group_id,user_id,'member');
    res.json({success:true});
  }catch(e){res.status(500).json({error:e.message});}
});

// ── NICKNAMES (verified only) ────────────────────
app.post('/api/nickname/:targetId', auth, (req,res)=>{
  const u=db.prepare('SELECT id,username,name FROM users WHERE id=?').get(req.user.id);
  // all users can set nicknames
  const{nickname}=req.body;
  if(!nickname?.trim()||nickname.trim().length>30)return res.status(400).json({error:'Nickname max 30 chars'});
  db.prepare('INSERT OR REPLACE INTO nicknames(giver_id,target_id,nickname)VALUES(?,?,?)').run(req.user.id,req.params.targetId,nickname.trim());
  // Notify target that a nickname was set (they just know someone updated it - not what)
  pushNotif(req.params.targetId,'🏷️ Nickname','@'+(u?.username||'Someone')+' gave you a nickname!','info',req.user.id,'chat');
  res.json({success:true});
});
app.delete('/api/nickname/:targetId', auth, (req,res)=>{
  db.prepare('DELETE FROM nicknames WHERE giver_id=? AND target_id=?').run(req.user.id,req.params.targetId);
  res.json({success:true});
});
app.get('/api/nickname/:targetId', auth, (req,res)=>{
  const n=db.prepare('SELECT nickname FROM nicknames WHERE giver_id=? AND target_id=?').get(req.user.id,req.params.targetId);
  res.json({nickname:n?.nickname||null});
});

// ── NOTE REPLIES ─────────────────────────────────
app.post('/api/notes/:ownerId/reply', auth, (req,res)=>{
  try{
    const{content}=req.body;
    if(!content?.trim()||content.trim().length>200)return res.status(400).json({error:'Max 200 chars'});
    const note=db.prepare('SELECT * FROM notes WHERE user_id=? AND expires_at>?').get(req.params.ownerId,Math.floor(Date.now()/1000));
    if(!note)return res.status(404).json({error:'Note not found or expired'});
    db.prepare('INSERT INTO note_replies(note_owner_id,replier_id,content)VALUES(?,?,?)').run(req.params.ownerId,req.user.id,content.trim());
    // Notify note owner
    const replier=db.prepare('SELECT username,name FROM users WHERE id=?').get(req.user.id);
    pushNotif(req.params.ownerId,'💬 Note Reply','@'+(replier?.username||'Someone')+' replied to your note: '+content.trim().slice(0,40),'info',req.user.id,'chat');
    res.json({success:true});
  }catch(e){res.status(500).json({error:e.message});}
});

// ── SUGGESTIONS ──────────────────────────────────
app.get('/api/suggested', auth, (req,res)=>{
  const users=db.prepare(`SELECT id,username,name,avatar,avatar_color,verified,fake_followers FROM users WHERE banned=0 AND is_private=0 AND id!=? AND id NOT IN(SELECT following_id FROM follows WHERE follower_id=?) ORDER BY RANDOM() LIMIT 12`).all(req.user.id,req.user.id);
  res.json(users);
});

// ── TOP PUBLIC GROUPS ─────────────────────────────
app.get('/api/groups/top/public', auth, (req,res)=>{
  const groups=db.prepare(`SELECT g.*,(SELECT COUNT(*) FROM group_members WHERE group_id=g.id) AS member_count FROM groups_t g WHERE g.is_public=1 ORDER BY member_count DESC LIMIT 8`).all();
  res.json(groups);
});

// ── ONLINE FOLLOWING ─────────────────────────────
app.get('/api/online-following', auth, (req,res)=>{
  const following=db.prepare('SELECT u.id,u.username,u.name,u.avatar,u.avatar_color,u.verified,u.last_seen FROM follows f JOIN users u ON u.id=f.following_id WHERE f.follower_id=? AND u.banned=0 ORDER BY u.last_seen DESC').all(req.user.id);
  res.json(following);
});

app.get('/adminx', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ── SOCKET ────────────────────────────────────
io.on('connection', (socket) => {
  socket.on('user_online', (userId) => {
    const uid = parseInt(userId);
    onlineUsers.set(uid, socket.id);
    io.emit('online_status', { userId: uid, online: true });
    db.prepare('UPDATE users SET last_seen=? WHERE id=?').run(Math.floor(Date.now() / 1000), uid);
  });
  socket.on('send_message', (data, cb) => {
    try {
      const { token, receiver_id, content, msg_type, reply_to } = data;
      let sender; try { sender = jwt.verify(token, JWT_SECRET); } catch { return cb?.({ error: 'Unauthorized' }); }
      if (!content?.trim()) return cb?.({ error: 'Empty message' });
      const sr = db.prepare('SELECT suspended_until FROM users WHERE id=?').get(sender.id);
      if (sr?.suspended_until > Math.floor(Date.now()/1000)) return cb?.({ error: 'You are suspended' });
      const receiver = db.prepare('SELECT id FROM users WHERE id=? AND banned=0').get(receiver_id);
      if (!receiver) return cb?.({ error: 'User not found' });
      const blocked = db.prepare('SELECT id FROM blocks WHERE (blocker_id=? AND blocked_id=?) OR (blocker_id=? AND blocked_id=?)').get(receiver_id,sender.id,sender.id,receiver_id);
      if (blocked) return cb?.({ error: 'Cannot message this user' });
      const r = db.prepare('INSERT INTO messages (sender_id,receiver_id,content,msg_type,reply_to) VALUES (?,?,?,?,?)').run(sender.id, receiver_id, content.trim(), msg_type||'text', reply_to||null);
      const msg = db.prepare('SELECT m.*,s.username AS sender_name,s.name AS sender_display,s.verified AS sender_verified,s.avatar AS sender_avatar,s.avatar_color AS sender_color FROM messages m JOIN users s ON s.id=m.sender_id WHERE m.id=?').get(r.lastInsertRowid);
      const recvSock = onlineUsers.get(parseInt(receiver_id));
      if (recvSock) io.to(recvSock).emit('new_message', msg);
      cb?.({ success: true, message: msg });
    } catch (e) { cb?.({ error: e.message }); }
  });
  socket.on('join_group', (gid) => socket.join(`group_${gid}`));
  socket.on('leave_group', (gid) => socket.leave(`group_${gid}`));
  socket.on('send_group_message', (data, cb) => {
    try {
      const { token, group_id, content, msg_type, reply_to } = data;
      let sender; try { sender = jwt.verify(token, JWT_SECRET); } catch { return cb?.({ error: 'Unauthorized' }); }
      if (!content?.trim()) return cb?.({ error: 'Empty' });
      const member = db.prepare('SELECT id FROM group_members WHERE group_id=? AND user_id=?').get(group_id, sender.id);
      if (!member) return cb?.({ error: 'Not a member' });
      const r = db.prepare('INSERT INTO group_messages (group_id,sender_id,content,msg_type,reply_to) VALUES (?,?,?,?,?)').run(group_id, sender.id, content.trim(), msg_type||'text', reply_to||null);
      const msg = db.prepare('SELECT gm.*,u.username AS sender_name,u.name AS sender_display,u.verified AS sender_verified,u.avatar AS sender_avatar,u.avatar_color AS sender_color FROM group_messages gm JOIN users u ON u.id=gm.sender_id WHERE gm.id=?').get(r.lastInsertRowid);
      io.to(`group_${group_id}`).emit('new_group_message', msg);
      cb?.({ success: true, message: msg });
    } catch(e) { cb?.({ error: e.message }); }
  });
  socket.on('typing', (d) => { const s=onlineUsers.get(parseInt(d.receiver_id)); if(s)io.to(s).emit('typing',{sender_id:d.sender_id,typing:d.typing}); });
  socket.on('group_typing', (d) => { socket.to(`group_${d.group_id}`).emit('group_typing',{sender_id:d.sender_id,typing:d.typing,group_id:d.group_id}); });
  socket.on('disconnect', () => {
    for (const [uid, sid] of onlineUsers.entries()) {
      if (sid === socket.id) { onlineUsers.delete(uid); io.emit('online_status',{userId:uid,online:false}); db.prepare('UPDATE users SET last_seen=? WHERE id=?').run(Math.floor(Date.now()/1000),uid); break; }
    }
  });

  // ── GAME SOCKET EVENTS ──────────────────────────
  socket.on('game_join_room', ({ token, room_id }) => {
    let user; try { user = jwt.verify(token, JWT_SECRET); } catch { return; }
    socket.join(`game_${room_id}`);
    socket.gameUserId = user.id;
    socket.gameRoomId = room_id;
    socket.to(`game_${room_id}`).emit('game_partner_joined', { userId: user.id });
  });

  socket.on('game_move', ({ token, room_id, move, board, turn, scores }) => {
    let user; try { user = jwt.verify(token, JWT_SECRET); } catch { return; }
    socket.to(`game_${room_id}`).emit('game_move', { userId: user.id, move, board, turn, scores });
  });

  socket.on('game_reset', ({ token, room_id }) => {
    let user; try { user = jwt.verify(token, JWT_SECRET); } catch { return; }
    socket.to(`game_${room_id}`).emit('game_reset', { userId: user.id });
  });

  socket.on('game_chat', ({ token, room_id, message }) => {
    let user; try { user = jwt.verify(token, JWT_SECRET); } catch { return; }
    const u = db.prepare('SELECT username,name,avatar,avatar_color FROM users WHERE id=?').get(user.id);
    socket.to(`game_${room_id}`).emit('game_chat', {
      userId: user.id,
      username: u?.username || 'Unknown',
      name: u?.name || u?.username || 'Unknown',
      avatar: u?.avatar || null,
      avatar_color: u?.avatar_color || '#833AB4',
      message,
      ts: Date.now()
    });
  });

  socket.on('game_exit', ({ token, room_id }) => {
    let user; try { user = jwt.verify(token, JWT_SECRET); } catch { return; }
    socket.to(`game_${room_id}`).emit('game_partner_left', { userId: user.id });
    socket.leave(`game_${room_id}`);
  });

  socket.on('game_invite_response', ({ token, invite_id, accepted, target_id, room_id, is_invite }) => {
    let user; try { user = jwt.verify(token, JWT_SECRET); } catch { return; }
    const targetSock = onlineUsers.get(parseInt(target_id));
    if (targetSock) {
      const u = db.prepare('SELECT username,name,avatar,avatar_color FROM users WHERE id=?').get(user.id);
      io.to(targetSock).emit('game_invite_response', {
        accepted: is_invite ? null : accepted,
        is_invite: !!is_invite,
        invite_id,
        room_id,
        userId: user.id,
        username: u?.username,
        name: u?.name || u?.username,
        avatar: u?.avatar,
        avatar_color: u?.avatar_color
      });
    }
  });
});


// ===== GAME ROUTES =====
app.post('/api/game/invite', auth, (req,res)=>{
  const {target_id, game_type} = req.body;
  if(!target_id||!game_type) return res.status(400).json({error:'Missing fields'});
  const inv_id = Date.now().toString(36)+Math.random().toString(36).slice(2,6);
  // Send as message with special type
  const msg = db.prepare('INSERT INTO messages (sender_id,receiver_id,content,msg_type,created_at) VALUES (?,?,?,?,?)').run(
    req.user.id, target_id,
    JSON.stringify({invite_id:inv_id,game:game_type,status:'pending'}),
    'game_invite', Math.floor(Date.now()/1000)
  );
  const sender = db.prepare('SELECT id,username,name,avatar,avatar_color,verified FROM users WHERE id=?').get(req.user.id);
  const fullMsg = {id:msg.lastInsertRowid,sender_id:req.user.id,receiver_id:parseInt(target_id),content:JSON.stringify({invite_id:inv_id,game:game_type,status:'pending'}),msg_type:'game_invite',created_at:Math.floor(Date.now()/1000),sender_display:sender.name||sender.username,sender_name:sender.name||sender.username,sender_avatar:sender.avatar,sender_color:sender.avatar_color};
  const io = req.app.get('io');
  if(io){const ts=onlineUsers.get(parseInt(target_id));if(ts)io.to(ts).emit('new_message',fullMsg);}
  res.json({success:true,invite_id:inv_id,message:fullMsg});
});

app.post('/api/game/respond', auth, (req,res)=>{
  const {msg_id, accept} = req.body;
  const msg = db.prepare('SELECT * FROM messages WHERE id=?').get(msg_id);
  if(!msg) return res.status(404).json({error:'Not found'});
  let data = {};
  try{data=JSON.parse(msg.content);}catch(e){}
  data.status = accept ? 'accepted' : 'declined';
  db.prepare('UPDATE messages SET content=? WHERE id=?').run(JSON.stringify(data), msg_id);
  res.json({success:true, accepted:!!accept, game_data:data});
});


// Dashboard redirect
app.get('/dashboard', (req,res)=>{
  res.redirect('/adminx');
});
app.get('/game.html', (req,res)=>{
  res.sendFile('game.html', {root: path.join(__dirname,'public')});
});

server.listen(PORT, () => console.log(`CaChat on port ${PORT}`));
