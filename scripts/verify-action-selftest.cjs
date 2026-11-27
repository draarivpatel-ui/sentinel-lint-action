'use strict';

/**
 * CI helper: verify the outputs of the action running against its own
 * vulnerable fixture inside the real GitHub Actions runner. Reads
 * FINDINGS_COUNT and SARIF_FILE from the environment and exits non-zero on
 * any mismatch.
 */

const fs = require('node:fs');

function fail(message) {
  process.stderr.write(`self-test verification failed: ${message}\n`);
  process.exitCode = 1;
}

const countRaw = process.env.FINDINGS_COUNT || '';
const sarifFile = process.env.SARIF_FILE || '';

const count = Number(countRaw);
if (!Number.isInteger(count) || count < 1) {
  fail(`findings-count must be a positive integer for the vulnerable fixture, got "${countRaw}"`);
} else if (!sarifFile) {
  fail('sarif-file output is empty');
} else if (!fs.existsSync(sarifFile)) {
  fail(`sarif file does not exist: ${sarifFile}`);
} else {
  let sarif;
  try {
    sarif = JSON.parse(fs.readFileSync(sarifFile, 'utf8'));
  } catch {
    fail('sarif file is not valid JSON');
  }
  if (sarif) {
    if (sarif.version !== '2.1.0') {
      fail(`sarif version is ${sarif.version}, expected 2.1.0`);
    } else if (!Array.isArray(sarif.runs) || sarif.runs.length !== 1) {
      fail('sarif must contain exactly one run');
    } else if (!Array.isArray(sarif.runs[0].results) || sarif.runs[0].results.length !== count) {
      fail(`sarif results length does not match findings-count ${count}`);
    } else {
      process.stdout.write(`self-test verified: ${count} findings in valid SARIF 2.1.0 output\n`);
    }
  }
}
