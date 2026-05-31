/**
 * Tiny Express server for Railway (or any Node host).
 *
 * Env vars:
 *   DASHBOARD_PASSWORD — required in production. Shared secret that gates
 *                        every data endpoint (/config.json, /api/*).
 *                        If unset, the server runs in OPEN mode and prints
 *                        a warning. Never deploy without it.
 *   META_CSV_URL       — (legacy) published Google Sheet CSV for Meta ads
 *   LINKS_CSV_URL      — published Google Sheet CSV for ad-name → Drive link
 *   DRIVE_API_KEY      — Google Drive API key (used for folder resolution)
 *   META_TOKEN         — Meta Marketing API long-lived access token
 *   META_AD_ACCOUNT    — Meta ad account, e.g. "act_123456789"
 *   META_DATE_PRESET   — optional, defaults to "last_7d"
 *   META_CAMPAIGN_IDS  — optional, comma-separated campaign ids to limit to
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

const app = express();
// Railway terminates TLS at the edge; honour X-Forwarded-* so req.ip is real
// (rate limiter relies on it) and req.secure works for the Secure cookie flag.
app.set('trust proxy', true);
app.disable('x-powered-by');

// ---------------- CONFIG ----------------
const DASHBOARD_PASSWORD = process.env.DASHBOARD_PASSWORD || '';
const AUTH_COOKIE_NAME = 'dashauth';
const AUTH_COOKIE_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;

if (!DASHBOARD_PASSWORD) {
  console.warn(
    '\n  ⚠  DASHBOARD_PASSWORD is not set — running in OPEN mode.\n' +
    '     All data endpoints are publicly reachable. Set DASHBOARD_PASSWORD\n' +
    '     in Railway → Variables before exposing this deployment.\n'
  );
} else if (DASHBOARD_PASSWORD.length < 12) {
  console.warn(
    '\n  ⚠  DASHBOARD_PASSWORD is shorter than 12 characters. Pick a longer\n' +
    '     value — this is the only barrier between the public internet and\n' +
    '     your Meta ad data.\n'
  );
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

// Small JSON body limit — only /api/login uses a body.
app.use(express.json({ limit: '1kb' }));

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
  const sig = crypto.createHmac('sha256', DASHBOARD_PASSWORD).update(ts).digest('hex');
  return `${ts}.${sig}`;
}

function verifyAuthCookie(value) {
  if (!DASHBOARD_PASSWORD) return false;
  if (!value || typeof value !== 'string') return false;
  const dot = value.indexOf('.');
  if (dot <= 0) return false;
  const ts = value.slice(0, dot);
  const sig = value.slice(dot + 1);
  if (!/^\d+$/.test(ts) || !/^[a-f0-9]+$/i.test(sig)) return false;
  const expected = crypto.createHmac('sha256', DASHBOARD_PASSWORD).update(ts).digest('hex');
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
  if (!DASHBOARD_PASSWORD) return res.json({ required: false, authenticated: true });
  res.json({
    required: true,
    authenticated: verifyAuthCookie(readCookie(req, AUTH_COOKIE_NAME))
  });
});

app.post('/api/login', (req, res) => {
  res.set('Cache-Control', 'no-store');
  if (!DASHBOARD_PASSWORD) {
    return res.status(503).json({ error: 'login disabled (DASHBOARD_PASSWORD not set)' });
  }
  if (!loginAllowed(req)) {
    return res.status(429).json({ error: 'Too many attempts. Try again in a minute.' });
  }
  const password = (req.body && typeof req.body.password === 'string') ? req.body.password : '';
  if (!safeEq(password, DASHBOARD_PASSWORD)) {
    return res.status(401).json({ error: 'Invalid password.' });
  }
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
  if (!DASHBOARD_PASSWORD) return next(); // OPEN mode, warned at boot
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
    metaCsvUrl:  process.env.META_CSV_URL  || '',
    linksCsvUrl: process.env.LINKS_CSV_URL || '',
    driveApiKey: process.env.DRIVE_API_KEY || '',
    metaApiUrl:  hasMetaApi ? '/api/meta-insights.csv' : ''
  });
});

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
    const r = await fetch(url);
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
    const adUrl = `https://graph.facebook.com/v21.0/${encodeURIComponent(adId)}` +
                  `?fields=creative{video_id,thumbnail_url,image_url}` +
                  `&access_token=${encodeURIComponent(token)}`;
    const adRes = await fetch(adUrl);
    const adData = await adRes.json();
    if (!adRes.ok || adData.error) {
      const msg = adData.error ? `${adData.error.message} (code ${adData.error.code})` : `HTTP ${adRes.status}`;
      return res.status(502).json({ error: 'Meta API error: ' + msg });
    }
    const creative = adData.creative || {};
    let videoUrl = '';
    if (creative.video_id) {
      const vidUrl = `https://graph.facebook.com/v21.0/${encodeURIComponent(creative.video_id)}` +
                     `?fields=source&access_token=${encodeURIComponent(token)}`;
      const vidRes = await fetch(vidUrl);
      const vidData = await vidRes.json();
      if (vidRes.ok && !vidData.error && vidData.source) videoUrl = vidData.source;
    }
    const data = {
      video_url: videoUrl,
      thumbnail_url: creative.thumbnail_url || '',
      image_url: creative.image_url || ''
    };
    creativeCache.set(adId, { data, expiresAt: Date.now() + CREATIVE_TTL_MS });
    res.json(data);
  } catch (err) {
    res.status(502).json({ error: 'Meta API fetch failed.' });
  }
});

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
      const r = await fetch(nextUrl);
      const data = await r.json();
      if (!r.ok || data.error) {
        const msg = data.error
          ? `${data.error.message} (code ${data.error.code})`
          : `HTTP ${r.status}`;
        return res.status(502).type('text/plain').send('Meta API error: ' + msg);
      }
      if (Array.isArray(data.data)) rows.push(...data.data);
      // Meta's paging.next URL contains the access token; that's fine to
      // re-use as-is (it never leaves the server). We do NOT log it.
      nextUrl = data.paging && data.paging.next ? data.paging.next : null;
    }
    res.set('Cache-Control', 'no-store');
    res.type('text/csv').send(buildInsightsCSV(rows));
  } catch (err) {
    res.status(502).type('text/plain').send('Meta API fetch failed.');
  }
});

// ---------------- Helpers ----------------
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

function buildInsightsCSV(rows) {
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
      csvField(row.date_start || ''),
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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Dashboard listening on http://localhost:${PORT}`);
});
