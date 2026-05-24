/**
 * Apps Script for the META ADS sheet.
 *
 * Setup (do this once, inside the Meta Google Sheet):
 *   1. Extensions → Apps Script
 *   2. Delete any default code, paste this whole file in
 *   3. Project Settings (left sidebar gear icon) → Script Properties →
 *      Add row: key = DRIVE_FOLDER_ID, value = <your Drive folder ID>
 *      (the long string in the folder's URL after /folders/)
 *   4. Save. Reload the spreadsheet.
 *   5. A new "Dashboard" menu appears next to Help. Click it →
 *      "Pull latest from Drive". Approve permissions on first run.
 *
 * Daily use:
 *   - Drop / overwrite "meta.csv" in the Drive folder.
 *   - Open this sheet, click Dashboard → Pull latest from Drive.
 *   - Sheet contents are wiped and replaced with the CSV.
 *   - Then go to the dashboard and click "↻ Refresh data".
 */

const CSV_FILENAME = 'meta.csv';

function getDriveFolderId_() {
  const id = PropertiesService.getScriptProperties().getProperty('DRIVE_FOLDER_ID');
  if (!id) {
    throw new Error(
      'DRIVE_FOLDER_ID is not set. Open Project Settings (gear icon) → ' +
      'Script Properties → add a row with key DRIVE_FOLDER_ID and the ' +
      'folder ID as the value.'
    );
  }
  return id;
}

function onOpen() {
  SpreadsheetApp.getUi()
    .createMenu('Dashboard')
    .addItem('Pull latest from Drive', 'pullLatestFromDrive')
    .addToUi();
}

function pullLatestFromDrive() {
  const ui = SpreadsheetApp.getUi();
  let folderId;
  try { folderId = getDriveFolderId_(); }
  catch (err) { ui.alert(err.message); return; }

  try {
    const folder = DriveApp.getFolderById(folderId);
    const files  = folder.getFilesByName(CSV_FILENAME);
    if (!files.hasNext()) {
      ui.alert('No file named "' + CSV_FILENAME + '" found in the Drive folder.');
      return;
    }
    // If multiple files share the name, take the most recently modified one.
    let chosen = files.next();
    while (files.hasNext()) {
      const f = files.next();
      if (f.getLastUpdated() > chosen.getLastUpdated()) chosen = f;
    }

    const csv  = chosen.getBlob().getDataAsString('UTF-8');
    const data = Utilities.parseCsv(csv);
    if (!data.length) { ui.alert('CSV is empty.'); return; }

    // Normalise: pad rows to the same width so setValues() doesn't error.
    const width = Math.max.apply(null, data.map(function (r) { return r.length; }));
    const padded = data.map(function (r) {
      while (r.length < width) r.push('');
      return r;
    });

    const sheet = SpreadsheetApp.getActiveSpreadsheet().getSheets()[0];
    sheet.clearContents();
    sheet.getRange(1, 1, padded.length, width).setValues(padded);

    ui.alert('Imported ' + (padded.length - 1) + ' rows from ' + CSV_FILENAME + '.\n\n' +
             'Now click "↻ Refresh data" in the dashboard to see the new data.');
  } catch (err) {
    ui.alert('Error: ' + err.message);
  }
}
