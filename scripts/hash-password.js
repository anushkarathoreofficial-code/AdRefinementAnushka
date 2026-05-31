#!/usr/bin/env node
/**
 * Generate a bcrypt hash for DASHBOARD_PASSWORD_HASH.
 *
 * Usage:
 *   npm run hash-password
 *
 * Prompts for a password (no echo) and prints the bcrypt hash. Paste the
 * hash into Railway → Variables as DASHBOARD_PASSWORD_HASH and remove the
 * old DASHBOARD_PASSWORD variable.
 *
 * Cost factor is fixed at 12 — well above the server's minimum of 10, and
 * still fast enough that login feels instant (~250ms verify).
 */

const bcrypt = require('bcryptjs');
const readline = require('node:readline');

const COST = 12;

function readPasswordSilently(promptText) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    process.stdout.write(promptText);
    // Mute stdout while typing so the password doesn't appear on screen.
    const origWrite = rl._writeToOutput.bind(rl);
    rl._writeToOutput = (chunk) => {
      if (chunk && chunk.includes && chunk.includes('\n')) origWrite('\n');
      // swallow all other chunks
    };
    rl.question('', (answer) => { rl.close(); resolve(answer); });
  });
}

(async () => {
  const p1 = await readPasswordSilently('Password: ');
  if (!p1) { console.error('Empty password — aborted.'); process.exit(1); }
  if (p1.length < 12) {
    console.error(`Password is only ${p1.length} characters. Use 12+ — this is the only barrier between the internet and your ad data.`);
    process.exit(1);
  }
  const p2 = await readPasswordSilently('Confirm:  ');
  if (p1 !== p2) { console.error('Passwords do not match — aborted.'); process.exit(1); }

  const hash = await bcrypt.hash(p1, COST);
  console.log('\nPaste this into Railway → Variables as DASHBOARD_PASSWORD_HASH:\n');
  console.log('  ' + hash);
  console.log('\nThen remove DASHBOARD_PASSWORD from the same Variables list.\n');
})().catch((e) => { console.error(e); process.exit(1); });
