'use strict';

/**
 * Isolated installation of the published sentinel-lint npm package.
 *
 * The package is installed with npm itself, never through a shell. npm is
 * located as the npm-cli.js that ships inside the same Node.js distribution
 * as the running interpreter, and it is executed with execFileSync and an
 * argument array, so no input is ever reparsed by a shell or a cmd shim.
 */

const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

class InstallError extends Error {
  constructor(message) {
    super(message);
    this.name = 'InstallError';
  }
}

/**
 * Locate the npm-cli.js bundled with the running Node.js distribution.
 *
 * Probe order covers the posix layout (`<prefix>/bin/node` next to
 * `<prefix>/lib/node_modules/npm`), the Windows layout (`node.exe` next to
 * `node_modules/npm`), and the case of a bin directory shim, resolving
 * symlinks first so version managers that link node into a bin directory
 * still expose the real distribution prefix.
 *
 * @param {string} execPath usually process.execPath
 * @returns {string} absolute path to npm-cli.js
 */
function findNpmCli(execPath) {
  let resolved = execPath;
  try {
    resolved = fs.realpathSync(execPath);
  } catch {
    resolved = execPath;
  }
  const binDir = path.dirname(resolved);
  const candidates = [
    path.join(binDir, '..', 'lib', 'node_modules', 'npm', 'bin', 'npm-cli.js'),
    path.join(binDir, '..', 'node_modules', 'npm', 'bin', 'npm-cli.js'),
    path.join(binDir, 'node_modules', 'npm', 'bin', 'npm-cli.js'),
  ];
  for (const candidate of candidates) {
    const normalized = path.normalize(candidate);
    if (fs.existsSync(normalized)) return normalized;
  }
  throw new InstallError(
    'could not locate the npm client bundled with this Node.js distribution; ' +
      'the action requires a Node.js runtime that ships npm',
  );
}

/**
 * Install sentinel-lint at an exact version into an isolated prefix.
 *
 * Hardening properties:
 *  - execFileSync with an argument array: no shell anywhere in the chain.
 *  - `--ignore-scripts`: no lifecycle script from anything in the install
 *    tree can execute, even though sentinel-lint itself has none.
 *  - exact semver pinned spec `sentinel-lint@<version>`: no ranges, so npm
 *    cannot resolve a different version than the workflow asked for.
 *  - the installed package.json is read back and both the package name and
 *    the exact version are verified before the binary is ever executed.
 *
 * @param {object} options
 * @param {string} options.version exact semver version, already validated
 * @param {string} options.installDir empty directory owned by this run
 * @param {string} [options.execPath] node executable, default process.execPath
 * @param {number} [options.timeoutMs] install timeout, default 180000
 * @returns {string} absolute path of the installed sentinel-lint package root
 */
function installSentinelLint({ version, installDir, execPath, timeoutMs }) {
  const node = execPath || process.execPath;
  const npmCli = findNpmCli(node);
  fs.mkdirSync(installDir, { recursive: true });
  fs.writeFileSync(path.join(installDir, 'package.json'), '{}\n', 'utf8');

  const spec = `sentinel-lint@${version}`;
  const args = [
    npmCli,
    'install',
    '--ignore-scripts',
    '--no-audit',
    '--no-fund',
    '--loglevel=error',
    '--prefix',
    installDir,
    spec,
  ];

  try {
    execFileSync(node, args, {
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: timeoutMs || 180000,
      maxBuffer: 16 * 1024 * 1024,
    });
  } catch (error) {
    const stderr = error.stderr ? String(error.stderr).slice(0, 2000) : '';
    throw new InstallError(
      `npm failed to install ${spec} (exit ${error.status === undefined ? 'unknown' : error.status}): ${stderr}`,
    );
  }

  const packageRoot = path.join(installDir, 'node_modules', 'sentinel-lint');
  const manifestPath = path.join(packageRoot, 'package.json');
  let manifest;
  try {
    manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  } catch {
    throw new InstallError(`npm reported success but ${spec} is not present in the install prefix`);
  }
  if (manifest.name !== 'sentinel-lint') {
    throw new InstallError(`installed package name is "${manifest.name}", expected "sentinel-lint"`);
  }
  if (manifest.version !== version) {
    throw new InstallError(
      `installed sentinel-lint version is "${manifest.version}", expected exactly "${version}"`,
    );
  }

  const binPath = path.join(packageRoot, 'bin', 'sentinel-lint.mjs');
  if (!fs.existsSync(binPath)) {
    throw new InstallError('the installed sentinel-lint package has no bin/sentinel-lint.mjs entry');
  }
  return packageRoot;
}

module.exports = { InstallError, findNpmCli, installSentinelLint };
