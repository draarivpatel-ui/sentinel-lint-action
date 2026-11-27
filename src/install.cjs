'use strict';

/**
 * Isolated installation of the published sentinel-lint npm package.
 *
 * The package tarball is downloaded straight from the npm registry over
 * HTTPS, verified byte for byte against the sha512 integrity value the
 * registry metadata publishes, and extracted with the defensive zero-
 * dependency tar parser in untar.cjs. No package manager executes, no
 * lifecycle script can ever run, and the whole pipeline is identical on
 * every operating system, including Windows runners whose node runtime
 * ships without an npm client.
 */

const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');
const { createHash } = require('node:crypto');

const { RegistryError, fetchDistInfo, getBuffer } = require('./registry.cjs');
const { UntarError, extractTar } = require('./untar.cjs');

class InstallError extends Error {
  constructor(message) {
    super(message);
    this.name = 'InstallError';
  }
}

/**
 * Verify a tarball buffer against a Subresource Integrity string of the
 * form `sha512-<base64>` or `sha1-<base64>`, or against a legacy hex sha1
 * shasum. At least one check must exist and pass; a missing integrity
 * contract fails closed.
 * @param {Buffer} tarball
 * @param {string} integrity SRI string from the registry metadata
 * @param {string} shasum legacy hex sha1 from the registry metadata
 */
function verifyIntegrity(tarball, integrity, shasum) {
  if (integrity) {
    const dash = integrity.indexOf('-');
    if (dash === -1) throw new InstallError('the registry integrity value is malformed');
    const algorithm = integrity.slice(0, dash);
    const expected = integrity.slice(dash + 1);
    if (!['sha512', 'sha1', 'sha256'].includes(algorithm)) {
      throw new InstallError(`unsupported integrity algorithm "${algorithm}"`);
    }
    const actual = createHash(algorithm).update(tarball).digest('base64');
    if (actual !== expected) {
      throw new InstallError(
        `tarball integrity mismatch: registry metadata expects ${algorithm}-${expected} but the download hashes to ${algorithm}-${actual}`,
      );
    }
    return;
  }
  if (shasum) {
    const actual = createHash('sha1').update(tarball).digest('hex');
    if (actual !== shasum) {
      throw new InstallError('tarball sha1 mismatch against the registry metadata');
    }
    return;
  }
  throw new InstallError('the registry metadata carries neither an integrity value nor a shasum; refusing to install');
}

/**
 * Install sentinel-lint at an exact version into an isolated directory.
 *
 * Hardening properties:
 *  - exact semver pinned download: no ranges, so the bytes cannot resolve to
 *    a different version than the workflow asked for.
 *  - sha512 integrity verification against registry metadata before a single
 *    byte is written to disk.
 *  - extraction rejects links, device entries, absolute paths, traversal and
 *    oversized content; no lifecycle script exists in this pipeline at all.
 *  - the installed package.json is read back and the package name, the exact
 *    version and the zero-dependency contract are verified before the binary
 *    is ever executed.
 *
 * @param {object} options
 * @param {string} options.version exact semver version, already validated
 * @param {string} options.installDir empty directory owned by this run
 * @returns {Promise<string>} absolute path of the installed sentinel-lint package root
 */
async function installSentinelLint({ version, installDir }) {
  let dist;
  try {
    dist = await fetchDistInfo(version);
  } catch (error) {
    if (error instanceof RegistryError) throw new InstallError(error.message);
    throw error;
  }

  const spec = `sentinel-lint@${version}`;
  let tarball;
  try {
    tarball = await getBuffer(dist.tarball);
  } catch (error) {
    if (error instanceof RegistryError) throw new InstallError(`could not download ${spec}: ${error.message}`);
    throw error;
  }

  verifyIntegrity(tarball, dist.integrity, dist.shasum);

  let tarBuffer;
  try {
    tarBuffer = zlib.gunzipSync(tarball);
  } catch {
    throw new InstallError('the downloaded tarball is not valid gzip data');
  }

  fs.mkdirSync(installDir, { recursive: true });
  try {
    extractTar(tarBuffer, installDir);
  } catch (error) {
    if (error instanceof UntarError) throw new InstallError(`refusing to extract ${spec}: ${error.message}`);
    throw error;
  }

  // npm tarballs place every entry under a single `package/` directory.
  const packageRoot = path.join(installDir, 'package');
  const manifestPath = path.join(packageRoot, 'package.json');
  let manifest;
  try {
    manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  } catch {
    throw new InstallError(`the extracted ${spec} tarball has no readable package.json`);
  }
  if (manifest.name !== 'sentinel-lint') {
    throw new InstallError(`installed package name is "${manifest.name}", expected "sentinel-lint"`);
  }
  if (manifest.version !== version) {
    throw new InstallError(
      `installed sentinel-lint version is "${manifest.version}", expected exactly "${version}"`,
    );
  }
  if (manifest.dependencies && Object.keys(manifest.dependencies).length > 0) {
    throw new InstallError(
      `sentinel-lint@${version} declares runtime dependencies; this action installs the zero-dependency package contract only`,
    );
  }

  const binPath = path.join(packageRoot, 'bin', 'sentinel-lint.mjs');
  if (!fs.existsSync(binPath)) {
    throw new InstallError('the installed sentinel-lint package has no bin/sentinel-lint.mjs entry');
  }
  return packageRoot;
}

module.exports = { InstallError, installSentinelLint, verifyIntegrity };
