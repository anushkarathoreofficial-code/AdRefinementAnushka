/**
 * Apps Script for the LINKS sheet (Ad Name + Drive Link).
 *
 * Setup (do this once, inside the Links Google Sheet):
 *   1. Extensions → Apps Script
 *   2. Delete any default code, paste this whole file in
 *   3. Project Settings (gear icon, left sidebar) → Script Properties →
 *      Add row: key = DRIVE_FOLDER_ID, value = the SAME folder ID used by
 *      the Meta sheet's script.
 *   4. Save. Reload the spreadsheet.
 *   5. Click Dashboard → Pull latest from Drive. Approve permissions.
 *
 * Daily use:
 *   - Drop / overwrite "links.csv" in the Drive folder.
 *   - Open this sheet, click Dashboard → Pull latest from Drive.
 *   - Then click "↻ Refresh data" in the dashboard.
 */

const CSV_FILENAME = 'links.csv';

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
    let chosen = files.next();
    while (files.hasNext()) {
      const f = files.next();
      if (f.getLastUpdated() > chosen.getLastUpdated()) chosen = f;
    }

    const csv  = chosen.getBlob().getDataAsString('UTF-8');
    const data = Utilities.parseCsv(csv);
    if (!data.length) { ui.alert('CSV is empty.'); return; }

    const width = Math.max.apply(null, data.map(function (r) { return r.length; }));
    const padded = data.map(function (r) {
      while (r.length < width) r.push('');
      return r;
    });

    const sheet = SpreadsheetApp.getActiveSpreadsheet().getSheets()[0];
    sheet.clearContents();
    sheet.getRange(1, 1, padded.length, width).setValues(padded);

    ui.alert('Imported ' + (padded.length - 1) + ' rows from ' + CSV_FILENAME + '.\n\n' +
             'Now click "↻ Refresh data" in the dashboard to see the new links.');
  } catch (err) {
    ui.alert('Error: ' + err.message);
  }
}
