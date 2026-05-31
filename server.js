/**
 * Tiny Express server for Railway (or any Node host).
 *
 * Env vars:
 *   META_CSV_URL     — (legacy) published Google Sheet CSV for Meta ads data
 *   LINKS_CSV_URL    — published Google Sheet CSV for ad-name → Drive link
 *   DRIVE_API_KEY    — Google Drive API key (used for folder resolution)
 *   META_TOKEN       — Meta Marketing API long-lived access token
 *   META_AD_ACCOUNT  — Meta ad account, e.g. "act_123456789"
 *   META_DATE_PRESET — optional, defaults to "last_7d"
 *
 * If META_TOKEN + META_AD_ACCOUNT are set, the dashboard pulls ad metrics
 * live from the Meta Graph API via /api/meta-insights.csv. Otherwise it
 * falls back to META_CSV_URL (the Google Sheets pipeline).
 */

const express = require('express');
const path = require('path');

const app = express();

// ---------- Runtime config for the browser ----------
// Exposed at /config.json. The token is NEVER sent to the client — only the
// path of the proxy endpoint that uses it server-side.
app.get('/config.json', (req, res) => {
  const hasMetaApi = !!(process.env.META_TOKEN && process.env.META_AD_ACCOUNT);
  res.set('Cache-Control', 'no-store');
  res.json({
    metaCsvUrl:  process.env.META_CSV_URL  || '',
    linksCsvUrl: process.env.LINKS_CSV_URL || '',
    driveApiKey: process.env.DRIVE_API_KEY || '',
    // When set, the dashboard pulls live from Meta API instead of the CSV.
    metaApiUrl:  hasMetaApi ? '/api/meta-insights.csv' : ''
  });
});

// ---------- Meta API: connection test ----------
// Mirrors the starter snippet you were given. Hit /api/ad-metrics to confirm
// the token + account ID combination works. Returns raw Graph API JSON.
app.get('/api/ad-metrics', async (req, res) => {
  const token = process.env.META_TOKEN;
  const account = process.env.META_AD_ACCOUNT;
  if (!token || !account) {
    return res.status(503).json({ error: 'Set META_TOKEN and META_AD_ACCOUNT env vars.' });
  }
  const datePreset = req.query.date_preset || process.env.META_DATE_PRESET || 'last_7d';
  const url = `https://graph.facebook.com/v21.0/${encodeURIComponent(account)}/insights` +
              `?fields=spend,impressions,clicks,ctr` +
              `&date_preset=${encodeURIComponent(datePreset)}` +
              `&access_token=${encodeURIComponent(token)}`;
  try {
    const r = await fetch(url);
    const data = await r.json();
    res.set('Cache-Control', 'no-store');
    res.status(r.ok ? 200 : 502).json(data);
  } catch (err) {
    res.status(502).json({ error: String(err && err.message || err) });
  }
});

// ---------- Meta API: full ad-level insights as CSV ----------
// Emits a CSV with the columns the dashboard's parseMetaCSV() already
// recognises. Handles pagination. Computes CPI/Hook/Hold/CTI from the
// `actions` and `video_*_actions` arrays the Graph API returns.
app.get('/api/meta-insights.csv', async (req, res) => {
  const token = process.env.META_TOKEN;
  const account = process.env.META_AD_ACCOUNT;
  if (!token || !account) {
    return res.status(503).type('text/plain')
      .send('Meta API not configured: set META_TOKEN and META_AD_ACCOUNT env vars.');
  }
  const datePreset = req.query.date_preset || process.env.META_DATE_PRESET || 'last_7d';
  const fields = [
    'ad_id','ad_name','adset_name','campaign_name',
    'spend','impressions','reach','frequency',
    'clicks','inline_link_clicks','ctr','cpm','cpc',
    'actions','cost_per_action_type',
    'video_3_sec_watched_actions','video_thruplay_watched_actions',
    'date_start','date_stop'
  ].join(',');

  const firstUrl =
    `https://graph.facebook.com/v21.0/${encodeURIComponent(account)}/insights` +
    `?level=ad&fields=${fields}` +
    `&date_preset=${encodeURIComponent(datePreset)}` +
    `&limit=500&access_token=${encodeURIComponent(token)}`;

  try {
    const rows = [];
    let nextUrl = firstUrl;
    // Hard cap on pages just in case — 50 * 500 = 25k ads.
    for (let page = 0; nextUrl && page < 50; page++) {
      const r = await fetch(nextUrl);
      const data = await r.json();
      if (!r.ok || data.error) {
        const msg = data.error ? `${data.error.message} (code ${data.error.code})` : `HTTP ${r.status}`;
        return res.status(502).type('text/plain').send('Meta API error: ' + msg);
      }
      if (Array.isArray(data.data)) rows.push(...data.data);
      nextUrl = data.paging && data.paging.next ? data.paging.next : null;
    }
    res.set('Cache-Control', 'no-store');
    res.type('text/csv').send(buildInsightsCSV(rows));
  } catch (err) {
    res.status(502).type('text/plain').send('Meta API fetch failed: ' + (err && err.message || err));
  }
});

// ---------- helpers ----------
function buildInsightsCSV(rows) {
  const header = [
    'Ad Name','Campaign','Ad Set','Date',
    'Spend','Impressions','Reach','Frequency',
    'Clicks','CTR','CPM','CPC',
    'Installs','CPI','Hook Rate','Hold Rate','CTI'
  ];
  const lines = [header.join(',')];

  for (const row of rows) {
    const actions    = actionsToMap(row.actions);
    const costPer    = actionsToMap(row.cost_per_action_type);
    const threeSec   = actionsToMap(row.video_3_sec_watched_actions);
    const thruplay   = actionsToMap(row.video_thruplay_watched_actions);

    const spend       = num(row.spend);
    const impressions = num(row.impressions);
    const installs    = num(actions.mobile_app_install)
                      || num(actions.app_install)
                      || num(actions.omni_app_install);
    const clicks      = num(row.inline_link_clicks) || num(row.clicks);
    const threeSecV   = num(threeSec.video_view);
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
      csvField(row.ad_name || ''),
      csvField(row.campaign_name || ''),
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

// ---------- Static files ----------
app.use(express.static(__dirname, {
  extensions: ['html'],
  setHeaders(res, filePath) {
    if (filePath.endsWith('index.html')) res.set('Cache-Control', 'no-store');
  }
}));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Dashboard listening on http://localhost:${PORT}`);
});
