// ShortLink backend with user auth (user + admin), URL shortening, and analytics
// Updates in this version:
// - حذف واجهة الادمن من الفرونت اند (لكن الادمن موجود في الباك اند للتحكم العام إذا احتجت).
/// - إضافة حقل must_change_password لإجبار المستخدم على تغيير كلمة المرور بعد أول تسجيل دخول.
// - إنشاء مستخدم ادمن افتراضي واحد بإيميل وكلمة مرور ثابتة يمكن تغييرها من المتغيرات البيئية.
//
// Endpoints:
//   POST   /api/auth/register        { email, password } -> { token, user }
//   POST   /api/auth/login           { email, password } -> { token, user }
//   POST   /api/auth/admin/login     { email, password } -> { token, user (role=admin) }
//   POST   /api/auth/change-password { oldPassword, newPassword } -> { token, user }
//   GET    /api/me                   -> { user }
//   POST   /api/shorten              { url } -> { code, short, original }
//   GET    /api/links                -> { links: [...] }      (links for current user)
//   GET    /api/admin/links          -> { links: [...] }      (admin: all links + user email)
//   GET    /api/analytics/:code      -> { code, original, total, byCountry, byDevice, byBrowser }
//   GET    /:code                    -> 302 redirect and record analytics
//
// Admin default credentials (if you did not set env vars):
//   email:    admin@shortlink.local
//   password: Admin123!
//
// You can override them with environment variables ADMIN_EMAIL and ADMIN_PASSWORD.

const express = require('express');
const bodyParser = require('body-parser');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const UAParser = require('ua-parser-js');
const cors = require('cors');
const path = require('path');

const app = express();

app.use(cors());
app.use(bodyParser.json());

const db = new Database(path.join(__dirname, 'shortlink.db'));

// ----- DB schema -----
db.exec(`
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user',
  must_change_password INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS links (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  code TEXT NOT NULL UNIQUE,
  original TEXT NOT NULL,
  hits INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS analytics (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  link_id INTEGER NOT NULL,
  ts TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  country TEXT,
  device TEXT,
  browser TEXT,
  ip TEXT,
  FOREIGN KEY (link_id) REFERENCES links(id) ON DELETE CASCADE
);
`);

// Migration: ensure must_change_password column exists for older DBs
try {
  const info = db.prepare("PRAGMA table_info(users)").all();
  const hasCol = info.some(col => col.name === "must_change_password");
  if (!hasCol) {
    db.prepare("ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 1").run();
    // اجعل الحسابات القديمة لا تحتاج تغيير كلمة المرور إلا إذا عدلتها يدويًا
    db.prepare("UPDATE users SET must_change_password = 0 WHERE must_change_password IS NULL OR must_change_password = ''").run();
  }
} catch (err) {
  console.error("Error running users table migration:", err);
}

// ----- Helper: password hashing -----
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto
    .pbkdf2Sync(password, salt, 100000, 64, 'sha512')
    .toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  const [salt, hash] = stored.split(':');
  if (!salt || !hash) return false;
  const calc = crypto
    .pbkdf2Sync(password, salt, 100000, 64, 'sha512')
    .toString('hex');
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(calc, 'hex'));
}

// ----- Helper: simple token (HMAC-signed JSON) -----
const TOKEN_SECRET = process.env.TOKEN_SECRET || 'dev-secret-change';

function createToken(payload) {
  const body = {
    ...payload,
    iat: Math.floor(Date.now() / 1000)
  };
  const base = Buffer.from(JSON.stringify(body)).toString('base64url');
  const sig = crypto
    .createHmac('sha256', TOKEN_SECRET)
    .update(base)
    .digest('base64url');
  return `${base}.${sig}`;
}

function verifyToken(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [base, sig] = parts;
  const expectedSig = crypto
    .createHmac('sha256', TOKEN_SECRET)
    .update(base)
    .digest('base64url');
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expectedSig))) {
    return null;
  }
  try {
    const payload = JSON.parse(Buffer.from(base, 'base64url').toString('utf8'));
    return payload;
  } catch (_) {
    return null;
  }
}

// ----- Helper: auth middleware -----
function authOptional(req, _res, next) {
  const header = req.header('Authorization') || '';
  const [, token] = header.split(' ');
  if (token) {
    const payload = verifyToken(token);
    if (payload && payload.id && payload.email) {
      req.user = {
        id: payload.id,
        email: payload.email,
        role: payload.role || 'user'
      };
    }
  }
  next();
}

function authRequired(req, res, next) {
  authOptional(req, res, () => {
    if (!req.user) {
      return res.status(401).json({ error: 'unauthorized' });
    }
    next();
  });
}

function adminRequired(req, res, next) {
  authOptional(req, res, () => {
    if (!req.user || req.user.role !== 'admin') {
      return res.status(401).json({ error: 'admin_only' });
    }
    next();
  });
}

app.use(authOptional);

// ----- Bootstrap admin user -----
function ensureAdminUser() {
  const adminEmail = process.env.ADMIN_EMAIL || 'admin@shortlink.local';
  const adminPassword = process.env.ADMIN_PASSWORD || 'Admin123!';

  const getUser = db.prepare('SELECT id, email, role FROM users WHERE email = ?');
  const existing = getUser.get(adminEmail);
  if (existing) {
    if (existing.role !== 'admin') {
      db.prepare('UPDATE users SET role = ?, must_change_password = 1 WHERE id = ?').run('admin', existing.id);
      console.log('[ShortLink] Existing user promoted to admin:', adminEmail);
    }
    return;
  }
  const insert = db.prepare('INSERT INTO users (email, password_hash, role, must_change_password) VALUES (?, ?, ?, ?)');
  const hash = hashPassword(adminPassword);
  const info = insert.run(adminEmail, hash, 'admin', 1);
  console.log('[ShortLink] Admin user created:', adminEmail, '(id=' + info.lastInsertRowid + ')');
}

ensureAdminUser();

// ----- User auth endpoints -----

app.post('/api/auth/register', (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: 'email_and_password_required' });
  }

  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (existing) {
    return res.status(409).json({ error: 'email_already_exists' });
  }

  const hash = hashPassword(password);
  const insert = db.prepare('INSERT INTO users (email, password_hash, role, must_change_password) VALUES (?, ?, ?, ?)');
  const info = insert.run(email, hash, 'user', 1); // أول تسجيل دخول يطلب تغيير كلمة المرور

  const user = { id: info.lastInsertRowid, email, role: 'user', must_change_password: 1 };
  const token = createToken(user);

  res.json({ token, user });
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: 'email_and_password_required' });
  }

  const row = db
    .prepare('SELECT id, email, password_hash, role, must_change_password FROM users WHERE email = ?')
    .get(email);
  if (!row || !verifyPassword(password, row.password_hash)) {
    return res.status(401).json({ error: 'invalid_credentials' });
  }

  const user = { id: row.id, email: row.email, role: row.role, must_change_password: row.must_change_password ? 1 : 0 };
  const token = createToken(user);
  res.json({ token, user });
});

app.post('/api/auth/admin/login', (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: 'email_and_password_required' });
  }

  const row = db
    .prepare('SELECT id, email, password_hash, role, must_change_password FROM users WHERE email = ?')
    .get(email);
  if (!row || row.role !== 'admin') {
    return res.status(401).json({ error: 'not_admin' });
  }
  if (!verifyPassword(password, row.password_hash)) {
    return res.status(401).json({ error: 'invalid_credentials' });
  }

  const user = { id: row.id, email: row.email, role: row.role, must_change_password: row.must_change_password ? 1 : 0 };
  const token = createToken(user);
  res.json({ token, user });
});

app.post('/api/auth/change-password', authRequired, (req, res) => {
  const { oldPassword, newPassword } = req.body || {};
  if (!oldPassword || !newPassword) {
    return res.status(400).json({ error: 'old_and_new_required' });
  }

  const row = db
    .prepare('SELECT id, email, password_hash, role, must_change_password FROM users WHERE id = ?')
    .get(req.user.id);
  if (!row) {
    return res.status(404).json({ error: 'user_not_found' });
  }
  if (!verifyPassword(oldPassword, row.password_hash)) {
    return res.status(401).json({ error: 'invalid_old_password' });
  }

  const hash = hashPassword(newPassword);
  db.prepare('UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?').run(hash, row.id);

  const updatedUser = { id: row.id, email: row.email, role: row.role, must_change_password: 0 };
  const token = createToken(updatedUser);
  res.json({ token, user: updatedUser });
});

app.get('/api/me', authRequired, (req, res) => {
  const row = db
    .prepare('SELECT id, email, role, must_change_password FROM users WHERE id = ?')
    .get(req.user.id);
  if (!row) {
    return res.status(404).json({ error: 'user_not_found' });
  }
  const user = { id: row.id, email: row.email, role: row.role, must_change_password: row.must_change_password ? 1 : 0 };
  res.json({ user });
});

// ----- Helper: generate short code -----
function generateCode() {
  const buf = crypto.randomBytes(4).toString('hex');
  const base = parseInt(buf, 16).toString(36);
  return base.slice(0, 7);
}

// ----- API: shorten -----
app.post('/api/shorten', (req, res) => {
  const { url } = req.body || {};
  if (!url || typeof url !== 'string') {
    return res.status(400).json({ error: 'url_required' });
  }

  // Basic normalization
  let normalized = url.trim();
  if (!/^https?:\/\//i.test(normalized)) {
    normalized = 'https://' + normalized;
  }

  let code;
  const insert = db.prepare('INSERT INTO links (user_id, code, original) VALUES (?, ?, ?)');
  for (let i = 0; i < 5; i++) {
    code = generateCode();
    try {
      const userId = req.user ? req.user.id : null;
      insert.run(userId, code, normalized);
      break;
    } catch (err) {
      if (err && err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
        continue;
      }
      console.error('Error inserting link', err);
      return res.status(500).json({ error: 'db_error' });
    }
  }

  if (!code) {
    return res.status(500).json({ error: 'could_not_generate_code' });
  }

  const publicUrl = process.env.PUBLIC_URL || '';
  const short = publicUrl
    ? `${publicUrl.replace(/\/+$/, '')}/${code}`
    : `/${code}`;

  res.json({ code, short, original: normalized });
});

// ----- API: links for current user -----
app.get('/api/links', authRequired, (req, res) => {
  const stmt = db.prepare(
    'SELECT id, code, original, hits, created_at FROM links WHERE user_id = ? ORDER BY created_at DESC'
  );
  const rows = stmt.all(req.user.id);
  res.json({ links: rows });
});

// ----- API: admin - all links with user email -----
app.get('/api/admin/links', adminRequired, (req, res) => {
  const stmt = db.prepare(
    `SELECT l.id,
            l.code,
            l.original,
            l.hits,
            l.created_at,
            u.email AS user_email
       FROM links l
       LEFT JOIN users u ON l.user_id = u.id
      ORDER BY l.created_at DESC`
  );
  const rows = stmt.all();
  res.json({ links: rows });
});

// ----- API: analytics for a link -----
app.get('/api/analytics/:code', authRequired, (req, res) => {
  const code = (req.params.code || '').trim();
  if (!code) {
    return res.status(400).json({ error: 'code_required' });
  }

  const linkRow = db
    .prepare('SELECT id, user_id, original, hits FROM links WHERE code = ?')
    .get(code);
  if (!linkRow) {
    return res.status(404).json({ error: 'link_not_found' });
  }

  // السماح للادمن أو لصاحب الرابط فقط
  if (req.user.role !== 'admin' && linkRow.user_id && linkRow.user_id !== req.user.id) {
    return res.status(403).json({ error: 'forbidden' });
  }

  const analyticsRows = db
    .prepare('SELECT country, device, browser FROM analytics WHERE link_id = ?')
    .all(linkRow.id);

  const total = analyticsRows.length;

  function aggregate(field) {
    const map = new Map();
    for (const row of analyticsRows) {
      const key = row[field] || 'غير معروف';
      map.set(key, (map.get(key) || 0) + 1);
    }
    return Array.from(map.entries()).map(([label, count]) => ({ label, count }));
  }

  const byCountry = aggregate('country');
  const byDevice = aggregate('device');
  const byBrowser = aggregate('browser');

  res.json({
    code,
    original: linkRow.original,
    total,
    byCountry,
    byDevice,
    byBrowser
  });
});

// ----- Redirect + analytics -----
app.get('/:code', (req, res, next) => {
  const code = (req.params.code || '').trim();
  if (!code || code === 'api') {
    return next();
  }

  const linkRow = db
    .prepare('SELECT id, original FROM links WHERE code = ?')
    .get(code);
  if (!linkRow) {
    return res.status(404).send('Link not found');
  }

  // update hits
  db.prepare('UPDATE links SET hits = hits + 1 WHERE id = ?').run(linkRow.id);

  // collect basic analytics
  try {
    const uaHeader = req.headers['user-agent'] || '';
    const parser = new UAParser(uaHeader);
    const result = parser.getResult();

    const deviceType = result.device.type || 'desktop';
    const browserName = result.browser.name || 'unknown';

    const ip =
      req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
      req.connection.remoteAddress ||
      null;

    const country =
      req.headers['cf-ipcountry'] ||
      req.headers['x-vercel-ip-country'] ||
      null;

    db.prepare(
      'INSERT INTO analytics (link_id, country, device, browser, ip) VALUES (?, ?, ?, ?, ?)'
    ).run(linkRow.id, country, deviceType, browserName, ip);
  } catch (err) {
    console.error('Error recording analytics', err);
  }

  res.redirect(linkRow.original);
});

// ----- Static frontend -----
const frontendPath = path.join(__dirname, '..', 'frontend');
app.use(express.static(frontendPath));

app.get('/', (_req, res) => {
  res.sendFile(path.join(frontendPath, 'index.html'));
});

// ----- Start server -----
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log('[ShortLink] Backend listening on port', PORT);
});
