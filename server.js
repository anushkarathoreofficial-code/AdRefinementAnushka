/**
 * Tiny Express server for Railway (or any Node host).
 *
 * Env vars:
 *   DASHBOARD_PASSWORD_HASH  — bcrypt hash of the shared access password.
 *                              Preferred over DASHBOARD_PASSWORD. Cost factor
 *                              must be ≥ 10 (the server refuses to start
 *                              otherwise). Generate with: npm run hash-password.
 *   DASHBOARD_PASSWORD       — plaintext fallback. Used only when no _HASH is
 *                              set. If both are unset, server runs in OPEN
 *                              mode. Never deploy without one of them.
 *   META_CSV_URL             — (legacy) published Google Sheet CSV for Meta ads
 *   LINKS_CSV_URL            — published Google Sheet CSV for ad-name → Drive link
 *   DRIVE_API_KEY            — Google Drive API key (used for anonymous folder resolution)
 *   GOOGLE_CREDENTIALS_JSON  — service account JSON (string). When set, the dashboard
 *                              proxies Drive thumbnails + video bytes through the
 *                              server using this account, which lets it serve files
 *                              that are restricted to "sign-in required" sharing.
 *   META_TOKEN               — Meta Marketing API long-lived access token
 *   META_AD_ACCOUNT          — Meta ad account, e.g. "act_123456789"
 *   META_DATE_PRESET         — optional, defaults to "last_7d"
 *   META_CAMPAIGN_IDS        — optional, comma-separated campaign ids to limit to
 *   GEMINI_API_KEY           — optional. When set, every signed-in dashboard
 *                              user gets the Gemini AI analysis features
 *                              wired up automatically without pasting their
 *                              own key. Exposed via /config.json (auth-gated).
 *   ANALYSIS_SHEET_ID        — optional. ID of a Google Sheet (shared with
 *                              the service account as Editor) that the
 *                              dashboard appends every completed analysis
 *                              into. Enables "what worked in past" context
 *                              for new analyses. Requires GOOGLE_CREDENTIALS_JSON.
 *
 * Security model:
 *   - The Meta token never leaves the server. The browser only sees the
 *     proxy path (/api/meta-insights.csv).
 *   - All data endpoints require a signed auth cookie. The cookie is set
 *     by POST /api/login after a constant-time password check.
 *   - Static file serving is locked down to index.html only (no source
 *     code, env example, package.json, or apps-script files leak).
 */

const express = require('express');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');

const app = express();
// Railway terminates TLS at the edge — trust exactly one proxy hop so
// req.ip reflects the real client IP for the rate limiter. Using `true`
// (any hops) would let a client spoof X-Forwarded-For and bypass per-IP
// limits; `1` only trusts the hop closest to us (Railway's edge router).
app.set('trust proxy', 1);
app.disable('x-powered-by');

// AbortController-based fetch with a hard wall-clock timeout. Wraps every
// outbound call to Meta / Google so a stuck remote can't hold server
// resources indefinitely.
function fetchWithTimeout(url, init = {}, timeoutMs = 30000) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(new Error('fetch timeout after ' + timeoutMs + 'ms')), timeoutMs);
  // Combine our timeout with any caller-provided signal.
  if (init.signal) {
    init.signal.addEventListener('abort', () => ctrl.abort(init.signal.reason), { once: true });
  }
  return fetch(url, { ...init, signal: ctrl.signal }).finally(() => clearTimeout(timer));
}

// ---------------- CONFIG ----------------
const DASHBOARD_PASSWORD_HASH = process.env.DASHBOARD_PASSWORD_HASH || '';
const DASHBOARD_PASSWORD      = process.env.DASHBOARD_PASSWORD || '';
const AUTH_COOKIE_NAME        = 'dashauth';
const AUTH_COOKIE_MAX_AGE_MS  = 7 * 24 * 60 * 60 * 1000;
const BCRYPT_MIN_COST         = 10;

// Strict bcrypt format: $2[ayb]$<2-digit cost>$<22 salt chars><31 hash chars>
function isValidBcryptHash(h) {
  const m = String(h || '').match(/^\$2[ayb]\$(\d{2})\$[./A-Za-z0-9]{53}$/);
  return m ? parseInt(m[1], 10) >= BCRYPT_MIN_COST : false;
}

if (DASHBOARD_PASSWORD_HASH) {
  if (!isValidBcryptHash(DASHBOARD_PASSWORD_HASH)) {
    console.error(
      '\n  ✗  DASHBOARD_PASSWORD_HASH is invalid or has cost factor < ' + BCRYPT_MIN_COST + '.\n' +
      '     Generate a fresh one with:  npm run hash-password\n'
    );
    process.exit(1);
  }
  if (DASHBOARD_PASSWORD) {
    console.warn(
      '\n  ⚠  Both DASHBOARD_PASSWORD_HASH and DASHBOARD_PASSWORD are set.\n' +
      '     Using the hash; the plaintext value is ignored. Remove\n' +
      '     DASHBOARD_PASSWORD from Railway → Variables to silence this.\n'
    );
  }
} else if (DASHBOARD_PASSWORD) {
  console.warn(
    '\n  ⚠  Using plaintext DASHBOARD_PASSWORD. For better protection, switch\n' +
    '     to DASHBOARD_PASSWORD_HASH (generate with: npm run hash-password).\n'
  );
  if (DASHBOARD_PASSWORD.length < 12) {
    console.warn(
      '  ⚠  DASHBOARD_PASSWORD is shorter than 12 characters. Pick a longer\n' +
      '     value or move to a hash — this is the only barrier between the\n' +
      '     public internet and your Meta ad data.\n'
    );
  }
} else {
  console.warn(
    '\n  ⚠  Neither DASHBOARD_PASSWORD_HASH nor DASHBOARD_PASSWORD is set —\n' +
    '     running in OPEN mode. All data endpoints are publicly reachable.\n' +
    '     Set one of them in Railway → Variables before exposing this deployment.\n'
  );
}

// Single accessor for "is auth on?" — covers both hash and plaintext modes.
function authEnabled() {
  return !!(DASHBOARD_PASSWORD_HASH || DASHBOARD_PASSWORD);
}

// Cookie HMAC secret. Stable across restarts (same env var → same secret),
// so cookies survive deploys without forcing everyone to re-login.
function authSecret() {
  return DASHBOARD_PASSWORD_HASH || DASHBOARD_PASSWORD;
}

// Verify a submitted password. Async because bcrypt.compare is, but the
// plaintext branch resolves synchronously via Promise.resolve.
async function verifyPassword(input) {
  if (DASHBOARD_PASSWORD_HASH) {
    try { return await bcrypt.compare(String(input || ''), DASHBOARD_PASSWORD_HASH); }
    catch { return false; }
  }
  return safeEq(input, DASHBOARD_PASSWORD);
}

// ---------------- SECURITY HEADERS ----------------
app.use((req, res, next) => {
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('X-Frame-Options', 'DENY');
  res.set('Referrer-Policy', 'no-referrer');
  res.set('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  res.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  next();
});

// Per-route JSON body limits. /api/login takes a tiny credential payload
// (~few hundred bytes max) so we keep that strict to make body-flood DoS
// useless. /api/save-analysis carries a Gemini snapshot which can run
// 2-5KB of markdown — its dedicated parser allows up to 100KB. Every
// other route gets the strict 1KB default; routes that don't read
// bodies (most GETs) pay nothing because the parser is a no-op when
// there's no Content-Type: application/json header.
const jsonStrict = express.json({ limit: '1kb' });
const jsonLarge  = express.json({ limit: '100kb' });
app.use((req, res, next) => {
  if (req.path === '/api/save-analysis') return jsonLarge(req, res, next);
  return jsonStrict(req, res, next);
});

// ---------------- AUTH HELPERS ----------------
function safeEq(a, b) {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  // crypto.timingSafeEqual requires equal-length buffers; pad-compare against
  // a same-length buffer so timing doesn't depend on which input was shorter.
  if (ab.length !== bb.length) {
    crypto.timingSafeEqual(ab, ab);
    return false;
  }
  return crypto.timingSafeEqual(ab, bb);
}

function makeAuthCookie() {
  const ts = String(Date.now());
  const sig = crypto.createHmac('sha256', authSecret()).update(ts).digest('hex');
  return `${ts}.${sig}`;
}

function verifyAuthCookie(value) {
  if (!authEnabled()) return false;
  if (!value || typeof value !== 'string') return false;
  const dot = value.indexOf('.');
  if (dot <= 0) return false;
  const ts = value.slice(0, dot);
  const sig = value.slice(dot + 1);
  if (!/^\d+$/.test(ts) || !/^[a-f0-9]+$/i.test(sig)) return false;
  const expected = crypto.createHmac('sha256', authSecret()).update(ts).digest('hex');
  if (!safeEq(sig, expected)) return false;
  const age = Date.now() - parseInt(ts, 10);
  return age >= 0 && age <= AUTH_COOKIE_MAX_AGE_MS;
}

function readCookie(req, name) {
  const header = req.headers.cookie || '';
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    if (part.slice(0, eq).trim() !== name) continue;
    try { return decodeURIComponent(part.slice(eq + 1).trim()); }
    catch { return ''; }
  }
  return '';
}

function setAuthCookie(req, res, value) {
  const flags = [
    `${AUTH_COOKIE_NAME}=${encodeURIComponent(value)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Strict',
    `Max-Age=${Math.floor(AUTH_COOKIE_MAX_AGE_MS / 1000)}`
  ];
  if (req.secure || req.headers['x-forwarded-proto'] === 'https') flags.push('Secure');
  res.set('Set-Cookie', flags.join('; '));
}

// ---------------- LOGIN RATE LIMITING ----------------
const loginAttempts = new Map();
const LOGIN_WINDOW_MS = 60 * 1000;
const LOGIN_MAX = 5;

function loginAllowed(req) {
  const ip = String(req.ip || 'unknown');
  const now = Date.now();
  const recent = (loginAttempts.get(ip) || []).filter(t => now - t < LOGIN_WINDOW_MS);
  recent.push(now);
  loginAttempts.set(ip, recent);
  return recent.length <= LOGIN_MAX;
}

setInterval(() => {
  const now = Date.now();
  for (const [ip, arr] of loginAttempts) {
    const fresh = arr.filter(t => now - t < LOGIN_WINDOW_MS);
    if (fresh.length === 0) loginAttempts.delete(ip);
    else loginAttempts.set(ip, fresh);
  }
}, 5 * 60 * 1000).unref();

// ---------------- PUBLIC AUTH ENDPOINTS ----------------
app.get('/api/auth-status', (req, res) => {
  res.set('Cache-Control', 'no-store');
  if (!authEnabled()) return res.json({ required: false, authenticated: true });
  res.json({
    required: true,
    authenticated: verifyAuthCookie(readCookie(req, AUTH_COOKIE_NAME))
  });
});

app.post('/api/login', async (req, res) => {
  res.set('Cache-Control', 'no-store');
  if (!authEnabled()) {
    return res.status(503).json({ error: 'login disabled (no password configured)' });
  }
  if (!loginAllowed(req)) {
    return res.status(429).json({ error: 'Too many attempts. Try again in a minute.' });
  }
  const password = (req.body && typeof req.body.password === 'string') ? req.body.password : '';
  const ok = await verifyPassword(password);
  if (!ok) return res.status(401).json({ error: 'Invalid password.' });
  setAuthCookie(req, res, makeAuthCookie());
  res.json({ ok: true });
});

app.post('/api/logout', (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.set('Set-Cookie', `${AUTH_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`);
  res.json({ ok: true });
});

// ---------------- AUTH GATE (everything below requires login) ----------------
function requireAuth(req, res, next) {
  if (!authEnabled()) return next(); // OPEN mode, warned at boot
  if (verifyAuthCookie(readCookie(req, AUTH_COOKIE_NAME))) return next();
  res.set('Cache-Control', 'no-store');
  res.status(401).json({ error: 'auth required' });
}

app.use('/config.json', requireAuth);
app.use('/api', requireAuth);

// ---------------- /config.json (browser runtime config) ----------------
app.get('/config.json', (req, res) => {
  const hasMetaApi = !!(process.env.META_TOKEN && process.env.META_AD_ACCOUNT);
  res.set('Cache-Control', 'no-store');
  res.json({
    metaCsvUrl:        process.env.META_CSV_URL  || '',
    linksCsvUrl:       process.env.LINKS_CSV_URL || '',
    driveApiKey:       process.env.DRIVE_API_KEY || '',
    metaApiUrl:        hasMetaApi ? '/api/meta-insights.csv' : '',
    // When true, the dashboard routes Drive thumbnails + video playback
    // through the server (service-account-backed) instead of hitting the
    // public Drive endpoints. Required for files behind a "sign-in
    // required" sharing policy.
    driveProxyEnabled: !!process.env.GOOGLE_CREDENTIALS_JSON,
    // When set, the dashboard auto-fills the Gemini AI key on every
    // load so users don't have to paste it individually. Only sent
    // over the authed /config.json — never reachable anonymously.
    geminiApiKey:      process.env.GEMINI_API_KEY || '',
    // When true, the dashboard saves every analysis to the configured
    // sheet and pulls past winners' patterns as prompt context.
    analysisHistoryEnabled: !!(process.env.ANALYSIS_SHEET_ID && process.env.GOOGLE_CREDENTIALS_JSON)
  });
});

// ---------------- Drive proxy (service-account backed) ----------------
// Used when files live in a Shared Drive whose Workspace policy enforces
// "sign-in required" on every link share — the public Drive API key can't
// reach them, but the service account (a Manager on the Shared Drive) can.
// All three endpoints sit behind the same requireAuth gate as the rest of
// /api/*, so video bytes never leak out of the signed-in dashboard.
let _googleLib = null;
function getGoogle() {
  if (!_googleLib) _googleLib = require('googleapis').google;
  return _googleLib;
}
function hasDriveSA() {
  return !!process.env.GOOGLE_CREDENTIALS_JSON;
}
let _driveAuth = null;
function getDriveAuth() {
  if (_driveAuth) return _driveAuth;
  const credentials = JSON.parse(process.env.GOOGLE_CREDENTIALS_JSON);
  _driveAuth = new (getGoogle().auth.GoogleAuth)({
    credentials,
    scopes: ['https://www.googleapis.com/auth/drive.readonly']
  });
  return _driveAuth;
}
async function getDriveAccessToken() {
  const client = await getDriveAuth().getClient();
  const tokenResp = await client.getAccessToken();
  return tokenResp.token;
}
const VALID_ID = /^[A-Za-z0-9_-]{10,}$/;

// Resolve a folder id to its first video file. Returns metadata the client
// uses to render the modal preview.
app.get('/api/drive-resolve', async (req, res) => {
  res.set('Cache-Control', 'no-store');
  if (!hasDriveSA()) return res.status(503).json({ error: 'GOOGLE_CREDENTIALS_JSON not set' });
  const folderId = String(req.query.folder_id || '').trim();
  if (!VALID_ID.test(folderId)) return res.status(400).json({ error: 'invalid folder_id' });
  try {
    const drive = getGoogle().drive({ version: 'v3', auth: getDriveAuth() });
    const list = await drive.files.list({
      q: `'${folderId}' in parents and trashed = false`,
      fields: 'files(id,name,mimeType,hasThumbnail)',
      pageSize: 20,
      supportsAllDrives: true,
      includeItemsFromAllDrives: true
    });
    const files = list.data.files || [];
    const pick = files.find(f => (f.mimeType || '').startsWith('video/')) || files[0];
    if (!pick) return res.status(404).json({ error: 'folder is empty' });
    res.json({ file_id: pick.id, name: pick.name, mime_type: pick.mimeType, has_thumbnail: !!pick.hasThumbnail });
  } catch (err) {
    const msg = (err.errors && err.errors[0] && err.errors[0].message) || err.message || 'unknown';
    res.status(502).json({ error: 'Drive error: ' + msg });
  }
});

// Stream a Drive video through the server. Forwards the browser's Range
// header so scrubbing/seeking works without buffering the whole file.
app.get('/api/drive-stream', async (req, res) => {
  if (!hasDriveSA()) return res.status(503).type('text/plain').send('GOOGLE_CREDENTIALS_JSON not set');
  const fileId = String(req.query.file_id || '').trim();
  if (!VALID_ID.test(fileId)) return res.status(400).type('text/plain').send('invalid file_id');
  try {
    const token = await getDriveAccessToken();
    const headers = { Authorization: `Bearer ${token}` };
    if (req.headers.range) headers.Range = req.headers.range;
    const driveUrl = `https://www.googleapis.com/drive/v3/files/${encodeURIComponent(fileId)}?alt=media&supportsAllDrives=true`;
    // Longer timeout — videos can take a while to stream. The timeout
    // governs the time-to-first-byte, not the full body transfer.
    const driveRes = await fetchWithTimeout(driveUrl, { headers }, 60000);
    res.status(driveRes.status);
    for (const h of ['content-type', 'content-length', 'content-range', 'accept-ranges']) {
      const v = driveRes.headers.get(h);
      if (v) res.set(h, v);
    }
    res.set('Cache-Control', 'no-store');
    if (!driveRes.body) return res.end();
    const { Readable } = require('node:stream');
    const nodeStream = Readable.fromWeb(driveRes.body);
    // Without these handlers, a mid-stream error from Drive (network blip,
    // quota cutoff) crashes the Node process with an unhandled exception.
    nodeStream.on('error', () => { try { res.end(); } catch (_) {} });
    res.on('close', () => { try { nodeStream.destroy(); } catch (_) {} });
    nodeStream.pipe(res);
  } catch (err) {
    res.status(502).type('text/plain').send('Drive stream failed.');
  }
});

// Thumbnail proxy. Uses drive.files.get to read the signed thumbnailLink,
// then bumps the size param. Cached client-side for an hour.
app.get('/api/drive-thumbnail', async (req, res) => {
  if (!hasDriveSA()) return res.status(503).end();
  const fileId = String(req.query.file_id || '').trim();
  if (!VALID_ID.test(fileId)) return res.status(400).end();
  try {
    const drive = getGoogle().drive({ version: 'v3', auth: getDriveAuth() });
    const meta = await drive.files.get({
      fileId, fields: 'thumbnailLink', supportsAllDrives: true
    });
    const link = meta.data.thumbnailLink;
    if (!link) return res.status(404).end();
    const finalUrl = link.replace(/=s\d+$/, '=s400');
    const r = await fetchWithTimeout(finalUrl, {}, 15000);
    res.status(r.status);
    res.set('content-type', r.headers.get('content-type') || 'image/jpeg');
    res.set('Cache-Control', 'private, max-age=3600');
    if (!r.body) return res.end();
    const { Readable } = require('node:stream');
    const nodeStream = Readable.fromWeb(r.body);
    nodeStream.on('error', () => { try { res.end(); } catch (_) {} });
    res.on('close', () => { try { nodeStream.destroy(); } catch (_) {} });
    nodeStream.pipe(res);
  } catch (err) {
    res.status(502).end();
  }
});

// ---------------- Analysis history (Google Sheets persistence) ----------------
// Every completed AI analysis is appended to a "Analysis Log" tab on the
// configured sheet. The tab is created lazily on first write. Used by the
// client to (a) render instantly when re-opening a previously analyzed ad
// and (b) inject "past winners' patterns" into new analysis prompts.
const ANALYSIS_TAB = 'Analysis Log';
const ANALYSIS_HEADERS = [
  'created_at', 'ad_id', 'ad_name', 'normalized_name',
  'score', 'metrics_json', 'snapshot', 'provider', 'model'
];
let _analysisTabReady = false; // module-level cache — only do the existence check once

function hasAnalysisHistory() {
  return !!(process.env.ANALYSIS_SHEET_ID && hasDriveSA());
}

let _sheetsAuth = null;
function getSheetsAuth() {
  if (_sheetsAuth) return _sheetsAuth;
  const credentials = JSON.parse(process.env.GOOGLE_CREDENTIALS_JSON);
  _sheetsAuth = new (getGoogle().auth.GoogleAuth)({
    credentials,
    scopes: ['https://www.googleapis.com/auth/spreadsheets']
  });
  return _sheetsAuth;
}

async function ensureAnalysisTab() {
  if (_analysisTabReady) return;
  const sheets = getGoogle().sheets({ version: 'v4', auth: getSheetsAuth() });
  const sheetId = process.env.ANALYSIS_SHEET_ID;
  const meta = await sheets.spreadsheets.get({ spreadsheetId: sheetId, fields: 'sheets.properties' });
  const exists = (meta.data.sheets || []).some(s => s.properties && s.properties.title === ANALYSIS_TAB);
  if (!exists) {
    await sheets.spreadsheets.batchUpdate({
      spreadsheetId: sheetId,
      requestBody: { requests: [{ addSheet: { properties: { title: ANALYSIS_TAB } } }] }
    });
    await sheets.spreadsheets.values.update({
      spreadsheetId: sheetId,
      range: `${ANALYSIS_TAB}!A1:I1`,
      valueInputOption: 'RAW',
      requestBody: { values: [ANALYSIS_HEADERS] }
    });
  }
  _analysisTabReady = true;
}

// Same emoji/copy stripping as the client uses, so saved rows are matchable
// later via the normalized_name column.
function _stripEmojiServer(s) {
  try { return s.replace(/[\p{Extended_Pictographic}️‍]/gu, ''); }
  catch { return s.replace(/[\u{1F300}-\u{1F9FF}\u{2600}-\u{27BF}️]/gu, ''); }
}
function normalizeAdNameServer(s) {
  let n = String(s || '').toLowerCase();
  n = _stripEmojiServer(n);
  n = n.replace(/[–—]/g, '-');
  while (true) {
    const before = n;
    n = n.replace(/\s*-\s*copy(\s*\d+)?\s*$/i, '');
    if (n === before) break;
  }
  return n.replace(/_/g, ' ').replace(/\s+/g, ' ').trim();
}

// History only collects winners (CPI < ₹300). Mirrors the client gate so a
// bad request can't pollute the shared "past winners" pool.
const ANALYSIS_HISTORY_CPI_MAX = 300;

app.post('/api/save-analysis', async (req, res) => {
  res.set('Cache-Control', 'no-store');
  if (!hasAnalysisHistory()) {
    return res.status(503).json({ error: 'Set ANALYSIS_SHEET_ID + GOOGLE_CREDENTIALS_JSON to enable history.' });
  }
  const b = req.body || {};
  const adId = String(b.ad_id || '').trim();
  const snapshot = String(b.snapshot || '').trim();
  if (!adId || !snapshot) return res.status(400).json({ error: 'ad_id and snapshot are required' });
  if (snapshot.length > 50000) return res.status(413).json({ error: 'snapshot too large (50k max)' });
  // Winners-only gate.
  const cpi = parseFloat((b.metrics && b.metrics.cpi) ?? '');
  if (isNaN(cpi) || cpi >= ANALYSIS_HISTORY_CPI_MAX) {
    return res.status(200).json({ ok: true, skipped: true, reason: `CPI ${isNaN(cpi) ? 'missing' : '≥ ₹' + ANALYSIS_HISTORY_CPI_MAX} — winners-only history` });
  }
  try {
    await ensureAnalysisTab();
    const sheets = getGoogle().sheets({ version: 'v4', auth: getSheetsAuth() });
    const row = [
      new Date().toISOString(),
      adId,
      String(b.ad_name || ''),
      normalizeAdNameServer(b.ad_name || ''),
      b.score == null ? '' : String(b.score),
      JSON.stringify(b.metrics || {}),
      snapshot,
      String(b.provider || ''),
      String(b.model || '')
    ];
    await sheets.spreadsheets.values.append({
      spreadsheetId: process.env.ANALYSIS_SHEET_ID,
      range: `${ANALYSIS_TAB}!A:I`,
      valueInputOption: 'RAW',
      insertDataOption: 'INSERT_ROWS',
      requestBody: { values: [row] }
    });
    res.json({ ok: true });
  } catch (err) {
    const msg = (err.errors && err.errors[0] && err.errors[0].message) || err.message || 'unknown';
    res.status(502).json({ error: 'sheet write failed: ' + msg });
  }
});

// Return the most recent stored analysis for a given ad_id. Used to
// short-circuit the Gemini upload when re-opening an analyzed ad.
app.get('/api/analysis-for-ad', async (req, res) => {
  res.set('Cache-Control', 'no-store');
  if (!hasAnalysisHistory()) return res.json({ found: false });
  const adId = String(req.query.ad_id || '').trim();
  if (!adId) return res.status(400).json({ error: 'ad_id required' });
  try {
    await ensureAnalysisTab();
    const sheets = getGoogle().sheets({ version: 'v4', auth: getSheetsAuth() });
    const result = await sheets.spreadsheets.values.get({
      spreadsheetId: process.env.ANALYSIS_SHEET_ID,
      range: `${ANALYSIS_TAB}!A:I`
    });
    const rows = result.data.values || [];
    for (let i = rows.length - 1; i >= 1; i--) {
      if (rows[i] && rows[i][1] === adId) {
        return res.json({
          found: true,
          created_at: rows[i][0] || '',
          ad_name: rows[i][2] || '',
          score: rows[i][4] || '',
          metrics: tryParseJSON(rows[i][5]) || {},
          snapshot: rows[i][6] || '',
          provider: rows[i][7] || '',
          model: rows[i][8] || ''
        });
      }
    }
    res.json({ found: false });
  } catch (err) {
    res.status(502).json({ error: 'sheet read failed' });
  }
});

// Return the N most recent winners (score >= 4) so the client can include
// their snapshots in new analysis prompts as "what worked in past" context.
app.get('/api/recent-winners', async (req, res) => {
  res.set('Cache-Control', 'no-store');
  if (!hasAnalysisHistory()) return res.json({ winners: [] });
  const limit = Math.min(parseInt(req.query.limit, 10) || 3, 10);
  try {
    await ensureAnalysisTab();
    const sheets = getGoogle().sheets({ version: 'v4', auth: getSheetsAuth() });
    const result = await sheets.spreadsheets.values.get({
      spreadsheetId: process.env.ANALYSIS_SHEET_ID,
      range: `${ANALYSIS_TAB}!A:I`
    });
    const rows = result.data.values || [];
    const winners = [];
    for (let i = rows.length - 1; i >= 1 && winners.length < limit * 4; i--) {
      const metrics = tryParseJSON(rows[i][5]) || {};
      const cpi = parseFloat(metrics.cpi);
      // CPI gate: only proven low-cost ads count as "winners" worth
      // referencing in future analyses. Defends against legacy rows that
      // landed in the sheet before the gate existed.
      if (isNaN(cpi) || cpi >= ANALYSIS_HISTORY_CPI_MAX) continue;
      winners.push({
        created_at: rows[i][0] || '',
        ad_name: rows[i][2] || '',
        score: parseInt(rows[i][4], 10) || 0,
        metrics,
        snapshot: rows[i][6] || ''
      });
    }
    res.json({ winners: winners.slice(0, limit) });
  } catch (err) {
    res.status(502).json({ error: 'sheet read failed' });
  }
});

function tryParseJSON(s) {
  try { return JSON.parse(s); } catch { return null; }
}

// ---------------- Meta API: connection test ----------------
app.get('/api/ad-metrics', async (req, res) => {
  const token = process.env.META_TOKEN;
  const account = process.env.META_AD_ACCOUNT;
  if (!token || !account) {
    return res.status(503).json({ error: 'Set META_TOKEN and META_AD_ACCOUNT env vars.' });
  }
  const datePreset = sanitizeDatePreset(req.query.date_preset || process.env.META_DATE_PRESET);
  const url = `https://graph.facebook.com/v21.0/${encodeURIComponent(account)}/insights` +
              `?fields=spend,impressions,clicks,ctr` +
              `&date_preset=${encodeURIComponent(datePreset)}` +
              `&access_token=${encodeURIComponent(token)}`;
  try {
    const r = await fetchWithTimeout(url);
    const data = await r.json();
    res.set('Cache-Control', 'no-store');
    // Forward the Graph response verbatim — it contains metrics on success
    // and an error object on failure. Neither includes the access token.
    res.status(r.ok ? 200 : 502).json(data);
  } catch (err) {
    res.status(502).json({ error: 'Meta API fetch failed.' });
  }
});

// ---------------- Meta API: ad creative (video URL + thumbnail) ----------------
// Resolves an ad_id → { video_url, thumbnail_url, image_url }. Two Graph
// calls per ad (ad → creative.video_id → video.source), cached in memory
// because Meta's signed video URLs only live ~1h.
const creativeCache = new Map();
const CREATIVE_TTL_MS = 50 * 60 * 1000;

setInterval(() => {
  const now = Date.now();
  for (const [k, v] of creativeCache) if (v.expiresAt <= now) creativeCache.delete(k);
}, 10 * 60 * 1000).unref();

app.get('/api/ad-creative', async (req, res) => {
  const token = process.env.META_TOKEN;
  if (!token) return res.status(503).json({ error: 'META_TOKEN not set' });

  const adId = String(req.query.ad_id || '').trim();
  if (!/^\d{1,30}$/.test(adId)) return res.status(400).json({ error: 'invalid ad_id' });

  res.set('Cache-Control', 'no-store');
  const cached = creativeCache.get(adId);
  if (cached && cached.expiresAt > Date.now()) return res.json(cached.data);

  try {
    // Meta stores video creative in several places depending on ad type.
    // Pull every plausible location in one shot so we don't have to guess.
    const creativeFields = [
      'video_id','thumbnail_url','image_url',
      'object_story_spec{video_data{video_id,image_url}}',
      'asset_feed_spec{videos{video_id,thumbnail_url},images{url}}',
      'effective_object_story_id'
    ].join(',');
    const adUrl = `https://graph.facebook.com/v21.0/${encodeURIComponent(adId)}` +
                  `?fields=creative{${creativeFields}}` +
                  `&access_token=${encodeURIComponent(token)}`;
    const adRes = await fetchWithTimeout(adUrl);
    const adData = await adRes.json();
    if (!adRes.ok || adData.error) {
      const msg = adData.error ? `${adData.error.message} (code ${adData.error.code})` : `HTTP ${adRes.status}`;
      return res.status(502).json({ error: 'Meta API error: ' + msg });
    }

    const creative = adData.creative || {};
    const videoId = extractVideoId(creative);
    let thumb     = extractThumbnail(creative);

    let videoUrl = '';
    if (videoId) {
      const vidUrl = `https://graph.facebook.com/v21.0/${encodeURIComponent(videoId)}` +
                     `?fields=source&access_token=${encodeURIComponent(token)}`;
      const vidRes = await fetchWithTimeout(vidUrl);
      const vidData = await vidRes.json();
      if (vidRes.ok && !vidData.error && vidData.source) videoUrl = vidData.source;
    }

    // Many promoted-post-style video ads don't expose video_id anywhere on
    // the creative — the video lives on the underlying Page post. Pull it
    // from the post's attachments as a last resort. media.source IS the
    // playable URL, so no second lookup needed.
    if (!videoUrl && creative.effective_object_story_id) {
      try {
        const postUrl = `https://graph.facebook.com/v21.0/${encodeURIComponent(creative.effective_object_story_id)}` +
                        `?fields=attachments{media,media_type,subattachments}` +
                        `&access_token=${encodeURIComponent(token)}`;
        const postRes = await fetchWithTimeout(postUrl);
        const postData = await postRes.json();
        if (postRes.ok && !postData.error) {
          const found = extractFromPostAttachments(postData.attachments);
          if (found.video_url) videoUrl = found.video_url;
          if (!thumb && found.thumb) thumb = found.thumb;
        }
      } catch (_) { /* non-fatal: thumbnail-only fallback still works */ }
    }

    const data = {
      video_url: videoUrl,
      thumbnail_url: thumb,
      image_url: creative.image_url || ''
    };
    creativeCache.set(adId, { data, expiresAt: Date.now() + CREATIVE_TTL_MS });
    res.json(data);
  } catch (err) {
    res.status(502).json({ error: 'Meta API fetch failed.' });
  }
});

// Meta wraps the video id in a different node for each ad type. Walk every
// known location and return the first one that exists.
function extractVideoId(creative) {
  if (!creative) return '';
  if (creative.video_id) return String(creative.video_id);
  const ossv = creative.object_story_spec && creative.object_story_spec.video_data;
  if (ossv && ossv.video_id) return String(ossv.video_id);
  const afsv = creative.asset_feed_spec && creative.asset_feed_spec.videos;
  if (Array.isArray(afsv)) {
    for (const v of afsv) if (v && v.video_id) return String(v.video_id);
  }
  return '';
}

// Walks a post's attachments tree to find the first video source + thumbnail.
// Used as a last-resort fallback when the ad creative didn't expose video_id
// (typical for promoted Page posts).
function extractFromPostAttachments(attachments) {
  const out = { video_url: '', thumb: '' };
  if (!attachments || !Array.isArray(attachments.data)) return out;
  const walk = (nodes) => {
    for (const node of nodes) {
      if (!node) continue;
      const media = node.media || {};
      if (!out.video_url && media.source) out.video_url = media.source;
      if (!out.thumb && media.image && media.image.src) out.thumb = media.image.src;
      if (node.subattachments && Array.isArray(node.subattachments.data)) {
        walk(node.subattachments.data);
      }
      if (out.video_url && out.thumb) return;
    }
  };
  walk(attachments.data);
  return out;
}

function extractThumbnail(creative) {
  if (!creative) return '';
  if (creative.thumbnail_url) return creative.thumbnail_url;
  const afsv = creative.asset_feed_spec && creative.asset_feed_spec.videos;
  if (Array.isArray(afsv)) {
    for (const v of afsv) if (v && v.thumbnail_url) return v.thumbnail_url;
  }
  const ossv = creative.object_story_spec && creative.object_story_spec.video_data;
  if (ossv && ossv.image_url) return ossv.image_url;
  if (creative.image_url) return creative.image_url;
  const afsi = creative.asset_feed_spec && creative.asset_feed_spec.images;
  if (Array.isArray(afsi)) {
    for (const i of afsi) if (i && i.url) return i.url;
  }
  return '';
}

// ---------------- Meta API: full ad-level insights as CSV ----------------
app.get('/api/meta-insights.csv', async (req, res) => {
  const token = process.env.META_TOKEN;
  const account = process.env.META_AD_ACCOUNT;
  if (!token || !account) {
    return res.status(503).type('text/plain')
      .send('Meta API not configured: set META_TOKEN and META_AD_ACCOUNT env vars.');
  }
  const datePreset = sanitizeDatePreset(req.query.date_preset || process.env.META_DATE_PRESET);
  const fields = [
    'ad_id','ad_name','adset_name','campaign_id','campaign_name',
    'spend','impressions','reach','frequency',
    'clicks','inline_link_clicks','ctr','cpm','cpc',
    'actions','cost_per_action_type',
    'video_thruplay_watched_actions',
    'date_start','date_stop'
  ].join(',');

  const campaignIdsRaw = (req.query.campaign_ids || process.env.META_CAMPAIGN_IDS || '').trim();
  const campaignIds = campaignIdsRaw
    ? campaignIdsRaw.split(',').map(s => s.trim()).filter(s => /^\d{1,30}$/.test(s))
    : [];
  let filteringParam = '';
  if (campaignIds.length) {
    const filter = [{ field: 'campaign.id', operator: 'IN', value: campaignIds }];
    filteringParam = `&filtering=${encodeURIComponent(JSON.stringify(filter))}`;
  }

  const firstUrl =
    `https://graph.facebook.com/v21.0/${encodeURIComponent(account)}/insights` +
    `?level=ad&fields=${fields}` +
    `&date_preset=${encodeURIComponent(datePreset)}` +
    filteringParam +
    `&limit=500&access_token=${encodeURIComponent(token)}`;

  try {
    const rows = [];
    let nextUrl = firstUrl;
    for (let page = 0; nextUrl && page < 50; page++) {
      const r = await fetchWithTimeout(nextUrl, {}, 30000);
      const data = await r.json();
      if (!r.ok || data.error) {
        const msg = data.error
          ? `${data.error.message} (code ${data.error.code})`
          : `HTTP ${r.status}`;
        return res.status(502).type('text/plain').send('Meta API error: ' + msg);
      }
      if (Array.isArray(data.data)) rows.push(...data.data);
      // Validate paging.next: it must point at the real Graph API host before
      // we re-use it. The URL contains our access token in the query string —
      // following an attacker-controlled URL would leak the token to them.
      // Belt-and-braces: TLS to Meta already prevents tampering, but a
      // surprise Meta-side redirect or response anomaly shouldn't bleed us.
      const rawNext = data.paging && data.paging.next ? data.paging.next : null;
      nextUrl = isSafeMetaUrl(rawNext) ? rawNext : null;
    }
    // Resolve each ad's real created_time (the date it was actually
    // launched) so the dashboard's date sort is meaningful. Insights'
    // own date_start is the start of the query window, which is
    // identical across rows for any preset other than per-day breakdowns.
    const adIds = Array.from(new Set(rows.map(r => r.ad_id).filter(Boolean)));
    const createdTimes = await fetchCreatedTimes(adIds, token);

    res.set('Cache-Control', 'no-store');
    res.type('text/csv').send(buildInsightsCSV(rows, createdTimes));
  } catch (err) {
    res.status(502).type('text/plain').send('Meta API fetch failed.');
  }
});

// ad_id → created_time (ISO 8601). Cached for an hour because ads' creation
// timestamps don't change after they're created.
const _createdTimesCache = new Map();
const CREATED_TIMES_TTL_MS = 60 * 60 * 1000;

async function fetchCreatedTimes(adIds, token) {
  const result = new Map();
  const missing = [];
  const now = Date.now();
  for (const id of adIds) {
    const c = _createdTimesCache.get(id);
    if (c && c.expiresAt > now) result.set(id, c.value);
    else missing.push(id);
  }
  if (!missing.length) return result;
  // Meta's ?ids=a,b,c batch read tops out at 50 per call. Bigger accounts
  // would otherwise need one /ad request per ad.
  const BATCH = 50;
  for (let i = 0; i < missing.length; i += BATCH) {
    const batch = missing.slice(i, i + BATCH);
    const url = `https://graph.facebook.com/v21.0/?ids=${encodeURIComponent(batch.join(','))}` +
                `&fields=created_time&access_token=${encodeURIComponent(token)}`;
    try {
      const r = await fetchWithTimeout(url);
      const data = await r.json();
      if (!r.ok || data.error) continue; // non-fatal: row will fall back to date_start
      for (const id of batch) {
        const v = data[id] && data[id].created_time;
        if (v) {
          result.set(id, v);
          _createdTimesCache.set(id, { value: v, expiresAt: now + CREATED_TIMES_TTL_MS });
        }
      }
    } catch (_) { /* skip this batch, others may still succeed */ }
  }
  return result;
}

// ---------------- Helpers ----------------
// SSRF defense: only follow URLs that point at the Graph API. Used for
// paging.next, which arrives over the wire with our access token in the
// query string — we must never forward that to anywhere else.
function isSafeMetaUrl(u) {
  if (!u || typeof u !== 'string') return false;
  try {
    const parsed = new URL(u);
    return parsed.protocol === 'https:' && parsed.hostname === 'graph.facebook.com';
  } catch { return false; }
}

function sanitizeDatePreset(raw) {
  const v = String(raw || '').trim().toLowerCase();
  // Whitelist Graph API's documented date_preset values. Anything else falls
  // back to last_7d, so a malicious query string can't probe other endpoints.
  const allowed = new Set([
    'today','yesterday','this_month','last_month',
    'this_quarter','maximum',
    'last_3d','last_7d','last_14d','last_28d','last_30d','last_90d',
    'last_week_mon_sun','last_week_sun_sat','last_quarter','last_year',
    'this_week_mon_today','this_week_sun_today','this_year'
  ]);
  return allowed.has(v) ? v : 'last_7d';
}

function buildInsightsCSV(rows, createdTimes) {
  const header = [
    'Ad ID','Ad Name','Campaign','Campaign ID','Ad Set','Date',
    'Spend','Impressions','Reach','Frequency',
    'Clicks','CTR','CPM','CPC',
    'Installs','CPI','Hook Rate','Hold Rate','CTI'
  ];
  const lines = [header.join(',')];

  for (const row of rows) {
    const actions    = actionsToMap(row.actions);
    const costPer    = actionsToMap(row.cost_per_action_type);
    const thruplay   = actionsToMap(row.video_thruplay_watched_actions);

    const spend       = num(row.spend);
    const impressions = num(row.impressions);
    const installs    = num(actions.mobile_app_install)
                      || num(actions.app_install)
                      || num(actions.omni_app_install);
    const clicks      = num(row.inline_link_clicks) || num(row.clicks);
    // 3-second video plays moved out of the dedicated field in v21+ — they
    // now live in the standard actions array as action_type=video_view.
    const threeSecV   = num(actions.video_view);
    const thruplayV   = num(thruplay.video_view);

    let cpi = '';
    if (installs > 0 && spend > 0) cpi = (spend / installs).toFixed(2);
    else if (costPer.mobile_app_install) cpi = num(costPer.mobile_app_install).toFixed(2);

    const hookRate = impressions > 0 && threeSecV > 0
      ? ((threeSecV / impressions) * 100).toFixed(2) : '';
    const holdRate = threeSecV > 0 && thruplayV > 0
      ? ((thruplayV / threeSecV) * 100).toFixed(2) : '';
    const cti = clicks > 0 && installs > 0
      ? ((installs / clicks) * 100).toFixed(2) : '';

    lines.push([
      csvField(row.ad_id || ''),
      csvField(row.ad_name || ''),
      csvField(row.campaign_name || ''),
      csvField(row.campaign_id || ''),
      csvField(row.adset_name || ''),
      // Real launch date (created_time) when available, falling back to
      // the insights window start. The dashboard's date sort keys off this.
      csvField((createdTimes && createdTimes.get(row.ad_id)) || row.date_start || ''),
      row.spend || '',
      row.impressions || '',
      row.reach || '',
      row.frequency || '',
      clicks || '',
      row.ctr || '',
      row.cpm || '',
      row.cpc || '',
      installs || '',
      cpi,
      hookRate,
      holdRate,
      cti
    ].join(','));
  }
  return lines.join('\n');
}

function actionsToMap(arr) {
  const m = {};
  if (Array.isArray(arr)) for (const x of arr) if (x && x.action_type) m[x.action_type] = x.value;
  return m;
}
function num(v) { const n = parseFloat(v); return isNaN(n) ? 0 : n; }
function csvField(s) {
  s = String(s == null ? '' : s);
  return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}

// ---------------- Static: only the dashboard HTML ----------------
// We do NOT use express.static(__dirname): that would expose server.js,
// package.json, the apps-script .gs files, README, etc.
app.get('/', (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.sendFile(path.join(__dirname, 'index.html'));
});
app.get('/index.html', (req, res) => res.redirect(301, '/'));

// Final catch-all → 404 JSON. Keeps the surface area tight.
app.use((req, res) => res.status(404).json({ error: 'not found' }));

// Centralised error handler — returns a clean JSON error without leaking
// stack traces or absolute file paths. Express's default handler dumps the
// stack into the response body in non-production environments, which is
// fine for debugging but not for an exposed deployment.
app.use((err, req, res, _next) => {
  if (res.headersSent) return; // streaming response already started
  const status = (err && (err.status || err.statusCode)) || 500;
  let message = 'server error';
  if (status === 413) message = 'request body too large';
  else if (status === 400) message = 'bad request';
  res.status(status).json({ error: message });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Dashboard listening on http://localhost:${PORT}`);
});
