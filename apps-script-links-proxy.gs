/**
 * LINKS PROXY — Apps Script Web App that reads the production "Foreign AI
 * Creatives" sheet directly and returns a clean Ad Name + Link CSV.
 *
 * Reads EVERY tab in the spreadsheet and combines them. Any tab that has a
 * "Name" (or "Ad Name") + "Link" column header is included; non-matching
 * tabs (summaries, scratch tabs, etc.) are skipped automatically. When the
 * same ad name appears in multiple tabs, the most recent occurrence wins
 * (later tabs overwrite earlier ones).
 *
 * --------------------------------------------------------------------
 * SETUP (one time, ~3 minutes)
 *
 * 1. Open the production sheet:
 *      https://docs.google.com/spreadsheets/d/18__KDrig76ij43mZ3QMDGjwfvwsVnE71fgLtvI-EQqw/edit
 *    Extensions → Apps Script → delete the default code → paste this whole
 *    file in → Save.
 *
 * 2. Deploy → New deployment → Type: Web app.
 *      - Description: "Links sheet proxy"
 *      - Execute as: Me                ← so it can read the sheet as you
 *      - Who has access: Anyone        ← so Railway can fetch unauthenticated
 *    Click Deploy → approve permissions on first run.
 *
 * 3. Copy the Web App URL. It looks like:
 *      https://script.google.com/macros/s/AKfycb.../exec
 *
 * 4. In Railway → Variables → set:
 *      LINKS_CSV_URL = <the Web App URL>
 *    Railway auto-redeploys.
 *
 * Done. The dashboard now reads EVERY MONTH of the production sheet
 * directly. The dashboard also auto-refreshes every hour, so any rows
 * you add to any tab will appear on the dashboard within ~1 hour
 * (or immediately if you click "↻ Refresh data").
 *
 * --------------------------------------------------------------------
 * Optional URL parameters
 *   ?tab=April+2026   → return ONLY that tab (handy for testing)
 *   ?tabs=all         → default; explicit for clarity
 * --------------------------------------------------------------------
 */

const SPREADSHEET_ID = '18__KDrig76ij43mZ3QMDGjwfvwsVnE71fgLtvI-EQqw';

function _normalizeHeader(h) {
  return String(h || '').replace(/[^a-z0-9 ]/gi, '').trim().toLowerCase();
}

function _findColumns(headers) {
  var nameCol = -1, linkCol = -1;
  headers.forEach(function (h, i) {
    const hl = _normalizeHeader(h);
    if (nameCol === -1 && (hl.indexOf('ad name') >= 0 || hl === 'name' || hl === 'ad' || hl.indexOf('creative name') >= 0 || hl === 'creative')) nameCol = i;
    if (linkCol === -1 && (hl.indexOf('drive') >= 0 || hl.indexOf('link') >= 0 || hl.indexOf('url') >= 0 || hl.indexOf('video') >= 0)) linkCol = i;
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
    const override = (e && e.parameter && e.parameter.tab) ? String(e.parameter.tab).trim().toLowerCase() : '';

    var sheets;
    if (override) {
      sheets = ss.getSheets().filter(function (s) { return s.getName().trim().toLowerCase() === override; });
    } else {
      sheets = ss.getSheets();
    }

    // Map: normalizedLowerName → { name (preserved case), link }. Iterating
    // tabs in their existing order — later iterations overwrite earlier
    // entries so the latest month's value wins when an ad name is duplicated.
    const dedup = {};
    var sheetsScanned = 0, sheetsSkipped = 0, rowsIn = 0;

    for (var s = 0; s < sheets.length; s++) {
      const sheet = sheets[s];
      const data = sheet.getDataRange().getValues();
      if (data.length < 2) { sheetsSkipped++; continue; }
      const cols = _findColumns(data[0]);
      if (cols.nameCol === -1 || cols.linkCol === -1) { sheetsSkipped++; continue; }
      sheetsScanned++;
      for (var i = 1; i < data.length; i++) {
        const name = String(data[i][cols.nameCol] || '').replace(/\s+/g, ' ').trim();
        const link = String(data[i][cols.linkCol] || '').trim();
        if (!name || !link) continue;
        if (!/^https?:\/\//i.test(link)) continue;
        rowsIn++;
        dedup[name.toLowerCase()] = { name: name, link: link };
      }
    }

    const rows = [['Ad Name', 'Link']];
    Object.keys(dedup).forEach(function (k) {
      rows.push([dedup[k].name, dedup[k].link]);
    });

    // Log so you can see what got picked up in Apps Script's Executions view.
    Logger.log('Scanned ' + sheetsScanned + ' tab(s), skipped ' + sheetsSkipped +
               ', rows in ' + rowsIn + ', deduped ' + (rows.length - 1));

    return _csvOutput(rows);
  } catch (err) {
    return ContentService
      .createTextOutput('Ad Name,Link\r\n# ERROR: ' + err.message + '\r\n')
      .setMimeType(ContentService.MimeType.CSV);
  }
}
