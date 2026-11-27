'use strict';

/**
 * Entrypoint of the sentinel-lint GitHub Action.
 *
 * Pipeline: validate every input, install the exact published sentinel-lint
 * package into an isolated prefix with lifecycle scripts disabled, run one
 * scan in the machine readable JSON format, render the requested report
 * format in pure zero-dependency Node.js, publish step outputs, and fail the
 * step exactly when the scanner says findings reached the fail threshold.
 */

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { InputError, readInputs, validateScanPath } = require('./inputs.cjs');
const { InstallError, installSentinelLint } = require('./install.cjs');
const { ScanError, SCAN_EXIT, runScan, findingsCount } = require('./scan.cjs');
const { ReportError, jsonReportToSarif, serializeSarif } = require('./sarif.cjs');
const { renderTextReport } = require('./report-text.cjs');
const { info, error, notice, writeOutput } = require('./output.cjs');

const REPORT_BASENAMES = Object.freeze({
  text: 'sentinel-lint-report.txt',
  json: 'sentinel-lint-report.json',
  sarif: 'sentinel-lint.sarif',
});

/**
 * Run the action. Returns the process exit code.
 * @param {object} env usually process.env
 * @returns {number}
 */
function run(env) {
  const workspace = env.GITHUB_WORKSPACE || process.cwd();

  let inputs;
  try {
    inputs = readInputs(env);
  } catch (err) {
    if (err instanceof InputError) {
      error(`invalid input: ${err.message}`);
      return 1;
    }
    throw err;
  }

  let scanPath;
  try {
    scanPath = validateScanPath(inputs.scanPathInput, workspace);
  } catch (err) {
    if (err instanceof InputError) {
      error(`invalid input: ${err.message}`);
      return 1;
    }
    throw err;
  }

  if (!fs.existsSync(scanPath)) {
    error(`scan path does not exist: ${inputs.scanPathInput}`);
    return 1;
  }

  info(`sentinel-lint-action: scanning ${inputs.scanPathInput} with sentinel-lint@${inputs.version}`);

  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-lint-action-'));
  try {
    const installDir = path.join(tempDir, 'install');
    let packageRoot;
    try {
      packageRoot = installSentinelLint({ version: inputs.version, installDir });
    } catch (err) {
      if (err instanceof InstallError) {
        error(err.message);
        return 1;
      }
      throw err;
    }
    info(`sentinel-lint-action: installed sentinel-lint@${inputs.version} in an isolated prefix`);

    const jsonReportPath = path.join(tempDir, 'scan-report.json');
    const binPath = path.join(packageRoot, 'bin', 'sentinel-lint.mjs');
    let scan;
    try {
      scan = runScan({
        binPath,
        scanPath,
        severity: inputs.severity,
        failOnFindings: inputs.failOnFindings,
        jsonReportPath,
        cwd: workspace,
      });
    } catch (err) {
      if (err instanceof ScanError) {
        error(err.message);
        return 1;
      }
      throw err;
    }

    const count = findingsCount(scan.report);

    const reportBasename = REPORT_BASENAMES[inputs.format];
    const reportFile = path.join(workspace, reportBasename);
    if (inputs.format === 'json') {
      fs.copyFileSync(jsonReportPath, reportFile);
    } else if (inputs.format === 'sarif') {
      let sarifText;
      try {
        sarifText = serializeSarif(jsonReportToSarif(scan.report));
      } catch (err) {
        if (err instanceof ReportError) {
          error(`could not convert the scan report to SARIF: ${err.message}`);
          return 1;
        }
        throw err;
      }
      fs.writeFileSync(reportFile, sarifText, 'utf8');
    } else {
      fs.writeFileSync(reportFile, renderTextReport(scan.report), 'utf8');
    }

    writeOutput(env, 'findings-count', String(count));
    writeOutput(env, 'report-file', reportFile);
    writeOutput(env, 'sarif-file', inputs.format === 'sarif' ? reportFile : '');

    const summary = scan.report.summary || {};
    info(
      `sentinel-lint-action: ${count} ${count === 1 ? 'finding' : 'findings'} in ` +
        `${typeof summary.filesScanned === 'number' ? summary.filesScanned : 0} files; ` +
        `report written to ${reportBasename}`,
    );

    if (scan.exitCode === SCAN_EXIT.findings) {
      error(
        `sentinel-lint found findings at or above the "${inputs.severity}" severity threshold; ` +
          'see the report file for details',
      );
      return 1;
    }

    notice(`scan completed: ${count} findings, none at or above the "${inputs.severity}" fail threshold`);
    return 0;
  } finally {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // A read-only file inside the temp tree must not mask the scan result.
    }
  }
}

if (require.main === module) {
  try {
    process.exitCode = run(process.env);
  } catch (err) {
    error(`sentinel-lint-action failed unexpectedly: ${err && err.stack ? err.stack : String(err)}`);
    process.exitCode = 1;
  }
}

module.exports = { run, REPORT_BASENAMES };
