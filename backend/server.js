// ShortLink backend - Express + better-sqlite3
// Endpoints:
//  POST /api/shorten { url }          -> { code, short }
//  GET  /:code                        -> 302 redirect + record hit
//  GET  /api/analytics/:code         -> { total, byCountry, byDevice, byBrowser }
//  GET  /api/links                   -> latest links with hits count

const express = require('express');
const bodyParser = require('body-parser');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const UAParser = require('ua-parser-js');
const path = require('path');

const app = express();

// --- Middleware ---
app.use(bodyParser.json());

// --- Database setup ---
const db = new Database('shortlink.db');

db.exec(`
  CREATE TABLE IF NOT EXISTS links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT UNIQUE NOT NULL,
    original TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    hits INTEGER NOT NULL DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS hits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    link_id INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    country TEXT,
    device TEXT,
    browser TEXT,
    FOREIGN KEY (link_id) REFERENCES links(id) ON DELETE CASCADE
  );
`);

// Helper: generate random short code
function genCode(length = 6) {
  // base64url then trim to desired length
  return crypto.randomBytes(8).toString('base64url').slice(0, length);
}

// Helper: normalize URL (add http if missing)
function normalizeUrl(u) {
  if (!/^https?:\/\//i.test(u)) {
    return 'https://' + u;
  }
  return u;
}

// --- API: shorten URL ---
app.post('/api/shorten', (req, res) => {
  let { url } = req.body || {};
  if (!url || typeof url !== 'string') {
    return res.status(400).json({ error: 'missing_url' });
  }

  url = normalizeUrl(url.trim());

  // generate unique code
  let code = genCode();
  let exists = db.prepare('SELECT id FROM links WHERE code = ?').get(code);
  while (exists) {
    code = genCode();
    exists = db.prepare('SELECT id FROM links WHERE code = ?').get(code);
  }

  const insert = db.prepare('INSERT INTO links (code, original) VALUES (?, ?)');
  const info = insert.run(code, url);

  const base = process.env.PUBLIC_BASE_URL || ''; // optional override
  const short = base
    ? base.replace(/\/+$/, '') + '/' + code
    : '/' + code;

  res.json({ code, short, id: info.lastInsertRowid });
});

// --- API: latest links ---
app.get('/api/links', (req, res) => {
  // simple: last 50 links with hit count
  const rows = db.prepare(`
    SELECT 
      l.id,
      l.code,
      l.original,
      l.created_at,
      l.hits as hits
    FROM links l
    ORDER BY l.created_at DESC
    LIMIT 50
  `).all();

  res.json(rows);
});

// --- API: analytics for code ---
app.get('/api/analytics/:code', (req, res) => {
  const { code } = req.params;
  const link = db.prepare('SELECT id, code, original, hits FROM links WHERE code = ?').get(code);
  if (!link) {
    return res.status(404).json({ error: 'not_found' });
  }

  const aggCountry = db.prepare(`
    SELECT IFNULL(country, 'Unknown') AS key, COUNT(*) AS count
    FROM hits WHERE link_id = ?
    GROUP BY key
  `).all(link.id);

  const aggDevice = db.prepare(`
    SELECT IFNULL(device, 'Unknown') AS key, COUNT(*) AS count
    FROM hits WHERE link_id = ?
    GROUP BY key
  `).all(link.id);

  const aggBrowser = db.prepare(`
    SELECT IFNULL(browser, 'Unknown') AS key, COUNT(*) AS count
    FROM hits WHERE link_id = ?
    GROUP BY key
  `).all(link.id);

  const toObj = rows =>
    rows.reduce((acc, row) => {
      acc[row.key] = row.count;
      return acc;
    }, {});

  res.json({
    code: link.code,
    original: link.original,
    total: link.hits,
    byCountry: toObj(aggCountry),
    byDevice: toObj(aggDevice),
    byBrowser: toObj(aggBrowser),
  });
});

// --- Redirect handler ---
app.get('/:code', (req, res, next) => {
  const code = req.params.code;

  // ignore requests to /api/*
  if (code === 'api') return next();

  const link = db.prepare('SELECT id, original FROM links WHERE code = ?').get(code);
  if (!link) {
    return res.status(404).send('الرابط المختصر غير موجود');
  }

  // record hit
  try {
    const ua = req.headers['user-agent'] || '';
    const parser = new UAParser(ua);
    const deviceInfo = parser.getDevice();
    const browserInfo = parser.getBrowser();

    const device =
      deviceInfo.type ||
      deviceInfo.model ||
      parser.getOS().name ||
      'Desktop';

    const browser = browserInfo.name || 'Unknown';

    const insertHit = db.prepare(
      'INSERT INTO hits (link_id, country, device, browser) VALUES (?, ?, ?, ?)'
    );
    insertHit.run(link.id, 'Unknown', device, browser);

    db.prepare('UPDATE links SET hits = hits + 1 WHERE id = ?').run(link.id);
  } catch (e) {
    console.error('hit record error', e);
  }

  res.redirect(link.original);
});

// --- Serve frontend static files ---
const frontendPath = path.join(__dirname, '..', 'frontend');
app.use(express.static(frontendPath));

app.get('/', (req, res) => {
  res.sendFile(path.join(frontendPath, 'index.html'));
});

// --- Start server ---
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log('Server running on port', PORT);
});
