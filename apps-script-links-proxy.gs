/**
 * LINKS PROXY — Apps Script Web App that reads the production "Foreign AI
 * Creatives" sheet directly and returns a clean Ad Name + Link CSV.
 *
 * It auto-picks the tab matching the current month and year (e.g.
 * "May 2026" → next month flips to "June 2026" with no code change). If
 * the current month's tab doesn't exist yet, it falls back to the most
 * recent prior month (up to 12 months back).
 *
 * --------------------------------------------------------------------
 * SETUP (one time, ~3 minutes)
 *
 * 1. Open the production sheet:
 *      https://docs.google.com/spreadsheets/d/18__KDrig76ij43mZ3QMDGjwfvwsVnE71fgLtvI-EQqw/edit
 *    Extensions → Apps Script → delete the default code → paste this whole
 *    file in → Save.
 *
 *    (Alternatively, make a new standalone Apps Script at
 *    script.google.com and paste this in — works the same.)
 *
 * 2. Deploy → New deployment → Type: Web app.
 *      - Description: "Links sheet proxy"
 *      - Execute as: Me (so it can read the sheet using your account)
 *      - Who has access: Anyone   ← required so Railway can fetch without auth
 *    Click Deploy → approve permissions on first run.
 *
 * 3. Copy the Web App URL it gives you. It looks like:
 *      https://script.google.com/macros/s/AKfycb.../exec
 *
 * 4. In Railway → Variables → set:
 *      LINKS_CSV_URL = <the Web App URL>
 *    Redeploy or wait for Railway's auto-redeploy.
 *
 * Done. The dashboard now reads directly from the live production sheet
 * — no Drive folder, no Pull-latest button, no monthly tab switching.
 * Just click "↻ Refresh data" on the dashboard whenever you want the
 * latest rows.
 *
 * --------------------------------------------------------------------
 * Optional URL parameters (for testing / one-offs)
 *   ?tab=April+2026          → force a specific tab by name
 *   ?tab=April%202026        → same, URL-encoded space
 * --------------------------------------------------------------------
 */

const SPREADSHEET_ID = '18__KDrig76ij43mZ3QMDGjwfvwsVnE71fgLtvI-EQqw';

const MONTH_NAMES = [
  'January', 'February', 'March', 'April', 'May', 'June',
  'July', 'August', 'September', 'October', 'November', 'December'
];

function _monthTabName(year, monthIdx) { return MONTH_NAMES[monthIdx] + ' ' + year; }

// Find the sheet to read from. Order of preference:
//   1. ?tab=<name>  override
//   2. Current month + year (e.g. "May 2026")
//   3. Each previous month, up to 12 months back
//   4. null if nothing matches → caller returns an empty CSV
function _pickSheet(spreadsheet, override) {
  const sheets = spreadsheet.getSheets();
  const byName = {};
  sheets.forEach(function (s) { byName[s.getName().trim().toLowerCase()] = s; });

  if (override) {
    const hit = byName[String(override).trim().toLowerCase()];
    if (hit) return hit;
  }

  const now = new Date();
  for (var back = 0; back <= 12; back++) {
    const d = new Date(now.getFullYear(), now.getMonth() - back, 1);
    const name = _monthTabName(d.getFullYear(), d.getMonth()).toLowerCase();
    if (byName[name]) return byName[name];
  }
  return null;
}

function _normalizeHeader(h) { return String(h || '').replace(/[^a-z0-9 ]/gi, '').trim().toLowerCase(); }

function _findColumns(headers) {
  var nameCol = -1, linkCol = -1;
  headers.forEach(function (h, i) {
    const hl = _normalizeHeader(h);
    if (nameCol === -1 && (hl.includes('ad name') || hl === 'name' || hl === 'ad' || hl.includes('creative name') || hl === 'creative')) nameCol = i;
    if (linkCol === -1 && (hl.includes('drive') || hl.includes('link') || hl.includes('url') || hl.includes('video'))) linkCol = i;
  });
  return { nameCol: nameCol, linkCol: linkCol };
}

function _csvEscape(cell) {
  const s = String(cell == null ? '' : cell);
  return /["\n,]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}

function _csvOutput(rows) {
  const body = rows.map(function (r) { return r.map(_csvEscape).join(','); }).join('\r\n') + '\r\n';
  return ContentService.createTextOutput(body).setMimeType(ContentService.MimeType.CSV);
}

function doGet(e) {
  try {
    const ss = SpreadsheetApp.openById(SPREADSHEET_ID);
    const override = (e && e.parameter && e.parameter.tab) ? e.parameter.tab : '';
    const sheet = _pickSheet(ss, override);
    if (!sheet) return _csvOutput([['Ad Name', 'Link']]);

    const data = sheet.getDataRange().getValues();
    if (data.length < 2) return _csvOutput([['Ad Name', 'Link']]);

    const cols = _findColumns(data[0]);
    if (cols.nameCol === -1 || cols.linkCol === -1) return _csvOutput([['Ad Name', 'Link']]);

    const rows = [['Ad Name', 'Link']];
    const seen = {};
    for (var i = 1; i < data.length; i++) {
      const name = String(data[i][cols.nameCol] || '').replace(/\s+/g, ' ').trim();
      const link = String(data[i][cols.linkCol] || '').trim();
      if (!name || !link) continue;
      if (!/^https?:\/\//i.test(link)) continue;
      const k = name.toLowerCase();
      if (seen[k]) continue;
      seen[k] = true;
      rows.push([name, link]);
    }
    return _csvOutput(rows);
  } catch (err) {
    return ContentService
      .createTextOutput('Ad Name,Link\r\n# ERROR: ' + err.message + '\r\n')
      .setMimeType(ContentService.MimeType.CSV);
  }
}
