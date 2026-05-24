/**
 * Tiny Express server for Railway (or any Node host).
 *
 * Reads three env vars and exposes them to the browser at /config.json:
 *   META_CSV_URL  — published Google Sheet CSV for Meta ads data
 *   LINKS_CSV_URL — published Google Sheet CSV for ad-name → Drive link
 *   DRIVE_API_KEY — Google Drive API key (used for folder resolution)
 *
 * Everything else is served as a static file from this directory.
 */

const express = require('express');
const path = require('path');

const app = express();

// Runtime config — the browser fetches this on page load.
// No caching so env-var changes take effect on the next request.
app.get('/config.json', (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.json({
    metaCsvUrl:  process.env.META_CSV_URL  || '',
    linksCsvUrl: process.env.LINKS_CSV_URL || '',
    driveApiKey: process.env.DRIVE_API_KEY || ''
  });
});

// Static files — index.html and the .gs scripts.
app.use(express.static(__dirname, {
  extensions: ['html'],
  setHeaders(res, filePath) {
    // index.html should never be cached so a redeploy is picked up immediately.
    if (filePath.endsWith('index.html')) res.set('Cache-Control', 'no-store');
  }
}));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Dashboard listening on http://localhost:${PORT}`);
});
