
// Express + better-sqlite3 backend
// Features:
// - POST /api/shorten { url } -> { short, code }
// - GET /:code -> redirect to original + record analytics
// - GET /api/analytics/:code -> aggregated stats
// - GET /api/links -> latest public links (for frontend listing)

const express = require('express');
const bodyParser = require('body-parser');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const fetch = require('node-fetch');
const UAParser = require('ua-parser-js');

const app = express();
app.use(bodyParser.json());
app.use(require('cors')());

const db = new Database('./shortlink.db');

// init tables
db.exec(`
CREATE TABLE IF NOT EXISTS links (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code TEXT UNIQUE,
  original TEXT,
  short TEXT,
  created DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS hits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  link_id INTEGER,
  ts DATETIME DEFAULT CURRENT_TIMESTAMP,
  ip TEXT,
  country TEXT,
  city TEXT,
  ua TEXT,
  device TEXT,
  browser TEXT,
  referrer TEXT,
  FOREIGN KEY(link_id) REFERENCES links(id)
);
`);

// Function to generate a unique code
function genCode() { return crypto.randomBytes(3).toString('base64url'); }

// API route for shortening URLs
app.post('/api/shorten', async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).send({ error: 'no url' });
  // create short code
  let code = genCode();
  // ensure unique
  let exists = db.prepare('SELECT id FROM links WHERE code=?').get(code);
  while (exists) {
    code = genCode();
    exists = db.prepare('SELECT id FROM links WHERE code=?').get(code);
  }
  // use your own domain or return path /:code
  const short = (process.env.PUBLIC_URL || '') + '/' + code;
  const info = db.prepare('INSERT INTO links(code,original,short) VALUES(?,?,?)').run(code, url, short);
  res.json({ code, short });
});

// API route for fetching latest links
app.get('/api/links', (req, res) => {
  const rows = db.prepare('SELECT code, original, short, created FROM links ORDER BY id DESC LIMIT 50').all();
  res.json(rows.map(r => ({ code: r.code, original: r.original, short: (process.env.PUBLIC_URL || '') + '/' + r.code, created: r.created })));
});

// API route for analytics on a specific link
app.get('/api/analytics/:code', async (req, res) => {
  const code = req.params.code;
  const link = db.prepare('SELECT id FROM links WHERE code=?').get(code);
  if (!link) return res.status(404).send({ error: 'not found' });
  const hits = db.prepare('SELECT country, device, browser, ts FROM hits WHERE link_id=?').all(link.id);
  const total = hits.length;
  const byCountry = {}; const byDevice = {}; const byBrowser = {};
  hits.forEach(h => { 
    byCountry[h.country || 'Unknown'] = (byCountry[h.country || 'Unknown'] || 0) + 1; 
    byDevice[h.device || 'Unknown'] = (byDevice[h.device || 'Unknown'] || 0) + 1; 
    byBrowser[h.browser || 'Unknown'] = (byBrowser[h.browser || 'Unknown'] || 0) + 1; 
  });
  res.json({ total, byCountry, byDevice, byBrowser });
});

// Redirect route
app.get('/:code', async (req, res) => {
  const code = req.params.code;
  const link = db.prepare('SELECT id, original FROM links WHERE code=?').get(code);
  if (!link) return res.status(404).send('Not found');

  // Record hit (async non-blocking)
  (async () => {
    try {
      const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress;
      // Geolocation using ip-api.com (no key) - check rate limits before heavy use
      let country = 'Unknown', city = '';
      try {
        const geo = await fetch('http://ip-api.com/json/' + ip + '?fields=country,city,status').then(r => r.json());
        if (geo && geo.status === 'success') { country = geo.country; city = geo.city; }
      } catch (e) { }
      const ua = req.headers['user-agent'] || '';
      const parser = new UAParser(ua);
      const device = parser.getDevice().type || parser.getOS().name || 'Desktop';
      const browser = parser.getBrowser().name || 'Unknown';
      const ref = req.get('referer') || '';
      db.prepare('INSERT INTO hits(link_id, ip, country, city, ua, device, browser, referrer) VALUES(?,?,?,?,?,?,?,?)')
        .run(link.id, ip, country, city, ua, device, browser, ref);
    } catch (e) { console.error('hit record error', e); }
  })();

  res.redirect(link.original);
});

// Handle root route '/'
app.get('/', (req, res) => {
  res.send('Welcome to the Shortlink API!');
});

// Start server
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log('Server running on', PORT));
