// Simple Express + better-sqlite3 URL shortener backend
// Endpoints:
//  - POST /api/shorten  { url } -> { code, short, original }
//  - GET  /:code        -> 302 redirect to original and record analytics
//  - GET  /api/analytics/:code -> { code, original, total, byCountry, byDevice, byBrowser }
//  - GET  /api/links    -> latest links with hit counts (optionally protected by ADMIN_KEY)

const express = require('express');
const bodyParser = require('body-parser');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const UAParser = require('ua-parser-js');
const cors = require('cors');
const path = require('path');

const app = express();

// ----- Basic middleware -----
app.use(cors());
app.use(bodyParser.json());

// ----- Database setup -----
const dbPath = process.env.DB_PATH || path.join(__dirname, 'shortlink.db');
const db = new Database(dbPath);

db.exec(`
CREATE TABLE IF NOT EXISTS links (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code TEXT UNIQUE,
  original TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  hits INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS hits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  link_id INTEGER NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  ip TEXT,
  country TEXT,
  device TEXT,
  browser TEXT,
  FOREIGN KEY(link_id) REFERENCES links(id)
);
`);

// ----- Helpers -----
function genCode(length = 6) {
  // Base62
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let code = '';
  for (let i = 0; i < length; i++) {
    code += chars[Math.floor(Math.random() * chars.length)];
  }
  return code;
}

function getBaseUrl(req) {
  if (process.env.PUBLIC_BASE_URL) return process.env.PUBLIC_BASE_URL;
  return req.protocol + '://' + req.get('host');
}

function summarizeHits(rows, field) {
  const map = {};
  for (const r of rows) {
    const key = (r[field] || 'Unknown');
    map[key] = (map[key] || 0) + 1;
  }
  return map;
}

// ----- API: shorten URL -----
app.post('/api/shorten', (req, res) => {
  const url = (req.body && req.body.url || '').trim();
  if (!url) {
    return res.status(400).json({ error: 'Missing url' });
  }

  // Reuse existing link if same original
  let row = db.prepare('SELECT * FROM links WHERE original = ? ORDER BY id DESC LIMIT 1').get(url);
  if (!row) {
    // generate unique code
    let code;
    while (true) {
      code = genCode(6);
      const exists = db.prepare('SELECT id FROM links WHERE code = ?').get(code);
      if (!exists) break;
    }
    const info = db.prepare('INSERT INTO links (code, original) VALUES (?, ?)').run(code, url);
    row = { id: info.lastInsertRowid, code, original: url, hits: 0 };
  }

  const base = getBaseUrl(req);
  const short = base + '/' + row.code;
  return res.json({ code: row.code, short, original: row.original, hits: row.hits });
});

// ----- API: analytics -----
app.get('/api/analytics/:code', (req, res) => {
  const code = req.params.code;
  const link = db.prepare('SELECT * FROM links WHERE code = ?').get(code);
  if (!link) {
    return res.status(404).json({ error: 'Not found' });
  }

  const hitRows = db.prepare('SELECT * FROM hits WHERE link_id = ?').all(link.id);
  const total = hitRows.length;
  const byCountry = summarizeHits(hitRows, 'country');
  const byDevice = summarizeHits(hitRows, 'device');
  const byBrowser = summarizeHits(hitRows, 'browser');

  return res.json({
    code: link.code,
    original: link.original,
    total,
    byCountry,
    byDevice,
    byBrowser
  });
});

// ----- API: latest links (optionally protected by ADMIN_KEY) -----
app.get('/api/links', (req, res) => {
  const adminKey = process.env.ADMIN_KEY;
  if (adminKey) {
    const clientKey = req.header('x-admin-key');
    if (!clientKey || clientKey !== adminKey) {
      return res.status(401).json({ error: 'unauthorized' });
    }
  }

  const rows = db.prepare(
    'SELECT id, code, original, hits, created_at FROM links ORDER BY created_at DESC LIMIT 50'
  ).all();

  const base = req.protocol + '://' + req.get('host');
  const payload = rows.map(r => ({
    id: r.id,
    code: r.code,
    original: r.original,
    hits: r.hits,
    created_at: r.created_at,
    short: base + '/' + r.code
  }));

  return res.json(payload);
});

// ----- Redirect route -----
app.get('/:code', (req, res, next) => {
  const code = req.params.code;

  // ignore paths that look like assets, e.g. .css, .js, etc
  if (code.includes('.')) return next();

  const link = db.prepare('SELECT * FROM links WHERE code = ?').get(code);
  if (!link) {
    return res.status(404).send('Link not found');
  }

  // analytics: parse UA
  const ua = req.headers['user-agent'] || '';
  const parser = new UAParser(ua);
  const deviceType = parser.getDevice().type || 'desktop';
  const browserName = parser.getBrowser().name || 'Unknown';

  const ip =
    (req.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
    req.socket.remoteAddress ||
    null;

  // Here we store country as "Unknown" to keep it simple;
  // you can plug an IP geolocation service later if you like.
  const country = 'Unknown';

  const tx = db.transaction(() => {
    db.prepare(
      'INSERT INTO hits (link_id, ip, country, device, browser) VALUES (?, ?, ?, ?, ?)'
    ).run(link.id, ip, country, deviceType, browserName);

    db.prepare('UPDATE links SET hits = hits + 1 WHERE id = ?').run(link.id);
  });
  tx();

  return res.redirect(link.original);
});

// ----- Static frontend -----
// Serve frontend static files (index.html, styles.css, app.js)
const frontendPath = path.join(__dirname, '..', 'frontend');
app.use(express.static(frontendPath));

app.get('/', (req, res) => {
  res.sendFile(path.join(frontendPath, 'index.html'));
});

// ----- Start server -----
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log('Shortlink backend listening on port', PORT);
});
