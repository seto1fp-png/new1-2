# ShortLink — URL Shortener with Analytics

This project contains a frontend and backend for a URL shortener with analytics (country, device, browser).

## Structure
- `frontend/` — static HTML/CSS/JS
- `backend/` — Node.js + Express + better-sqlite3

## Quick start (backend)
1. `cd backend`
2. `npm install`
3. `node server.js`

Set `PUBLIC_URL` environment variable to your domain (e.g. https://short.example.com) to get full short URLs.

## Notes
- GeoIP lookups use ip-api.com (free, limited). For production, consider MaxMind or a paid provider.
- Add HTTPS and proper CORS settings for deployment.
