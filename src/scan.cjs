'use strict';

/**
 * Execution of the sentinel-lint scan itself.
 *
 * The scanner binary inside the isolated install prefix is executed through
 * execFileSync with a fixed argument array. There is no shell anywhere in
 * the chain: every input-derived value travels as exactly one argv element,
 * and inputs were validated before this point, so no input can ever be
 * reparsed as a command, an option or a glob expansion.
 */

const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

class ScanError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ScanError';
  }
}

/**
 * Exit codes of the real sentinel-lint CLI, verified against the published
 * 0.2.0 package: 0 clean, 1 findings at or above the fail threshold,
 * 2 usage or configuration error, 3 internal error.
 */
const SCAN_EXIT = Object.freeze({ ok: 0, findings: 1, usage: 2, internal: 3 });

/**
 * Run one sentinel-lint scan and capture its JSON report.
 *
 * @param {object} options
 * @param {string} options.binPath absolute path of bin/sentinel-lint.mjs
 * @param {string} options.scanPath absolute validated scan target
 * @param {string} options.severity fail threshold severity, already validated
 * @param {boolean} options.failOnFindings when false the scan runs with --fail-on off
 * @param {string} options.jsonReportPath file the scanner writes its JSON report to
 * @param {string} options.cwd working directory for the scan, the workspace root
 * @param {string} [options.execPath] node executable, default process.execPath
 * @param {number} [options.timeoutMs] scan timeout, default 300000
 * @returns {{exitCode: number, stderr: string, report: object}}
 */
function runScan({ binPath, scanPath, severity, failOnFindings, jsonReportPath, cwd, execPath, timeoutMs }) {
  const node = execPath || process.execPath;
  const failOn = failOnFindings ? severity : 'off';
  const args = [
    binPath,
    'scan',
    scanPath,
    '--format',
    'json',
    '--output',
    jsonReportPath,
    '--fail-on',
    failOn,
  ];

  let exitCode = SCAN_EXIT.ok;
  let stderr = '';
  try {
    execFileSync(node, args, {
      cwd,
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: timeoutMs || 300000,
      maxBuffer: 16 * 1024 * 1024,
    });
  } catch (error) {
    if (error.status === undefined || error.status === null) {
      throw new ScanError(
        `sentinel-lint did not run to completion: ${error.message}`.slice(0, 2000),
      );
    }
    exitCode = error.status;
    stderr = error.stderr ? String(error.stderr) : '';
  }

  if (exitCode === SCAN_EXIT.usage || exitCode === SCAN_EXIT.internal) {
    throw new ScanError(
      `sentinel-lint exited with code ${exitCode} (${exitCode === SCAN_EXIT.usage ? 'usage or configuration error' : 'internal error'}): ${stderr.slice(0, 2000)}`,
    );
  }
  if (exitCode !== SCAN_EXIT.ok && exitCode !== SCAN_EXIT.findings) {
    throw new ScanError(`sentinel-lint exited with unexpected code ${exitCode}: ${stderr.slice(0, 2000)}`);
  }

  let raw;
  try {
    raw = fs.readFileSync(jsonReportPath, 'utf8');
  } catch {
    throw new ScanError('sentinel-lint did not write its JSON report file');
  }
  let report;
  try {
    report = JSON.parse(raw);
  } catch {
    throw new ScanError('the scan report is not valid JSON');
  }
  return { exitCode, stderr, report };
}

/**
 * Derive the findings count from the parsed report, preferring the summary
 * the scanner computed and falling back to the findings array length.
 * @param {object} report
 * @returns {number}
 */
function findingsCount(report) {
  if (
    report.summary &&
    typeof report.summary.findings === 'number' &&
    Number.isInteger(report.summary.findings) &&
    report.summary.findings >= 0
  ) {
    return report.summary.findings;
  }
  if (Array.isArray(report.findings)) return report.findings.length;
  throw new ScanError('the scan report has neither a summary count nor a findings array');
}

module.exports = { ScanError, SCAN_EXIT, runScan, findingsCount };
