'use strict';

/**
 * Input parsing and validation for the sentinel-lint action.
 *
 * Every input that reaches a child process argument, a filesystem path or a
 * report file is validated here before anything executes. Validation is
 * allowlist based: inputs either match a strict grammar exactly or the step
 * fails before npm or sentinel-lint ever runs.
 */

const path = require('node:path');

class InputError extends Error {
  constructor(message) {
    super(message);
    this.name = 'InputError';
  }
}

/**
 * Official semver grammar from semver.org, anchored. A version input that
 * matches this regex cannot contain spaces, shell metacharacters, option
 * dashes or registry specifiers, so it is safe to embed in the single
 * argument `sentinel-lint@<version>` passed to npm.
 */
const SEMVER_RE = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$/;

const SEVERITIES = Object.freeze(['info', 'warning', 'error', 'critical']);
const FORMATS = Object.freeze(['text', 'json', 'sarif']);

const DEFAULTS = Object.freeze({
  version: '0.2.0',
  path: '.',
  severity: 'warning',
  format: 'sarif',
  'fail-on-findings': 'true',
});

/**
 * Resolve the environment key for an input exactly the way the GitHub
 * Actions runner does: the input name uppercased with spaces replaced by
 * underscores. Hyphens are preserved, so `fail-on-findings` arrives as
 * INPUT_FAIL-ON-FINDINGS, not INPUT_FAIL_ON_FINDINGS. The underscore form is
 * accepted as a fallback for local harnesses that cannot easily set
 * hyphenated environment variables.
 */
function readRawInput(env, name) {
  const exactKey = `INPUT_${name.replace(/ /g, '_').toUpperCase()}`;
  const fallbackKey = `INPUT_${name.replace(/-/g, '_').toUpperCase()}`;
  const raw = env[exactKey] !== undefined && env[exactKey].trim() !== '' ? env[exactKey] : env[fallbackKey];
  if (raw === undefined || raw.trim() === '') return DEFAULTS[name];
  return raw.trim();
}

/**
 * Validate the sentinel-lint version against the strict semver grammar.
 * @param {string} version
 * @returns {string}
 */
function validateVersion(version) {
  if (typeof version !== 'string' || version.length === 0 || version.length > 128) {
    throw new InputError('version must be a non-empty string of at most 128 characters');
  }
  if (!SEMVER_RE.test(version)) {
    throw new InputError(
      `version "${version}" is not a strict semver version like 0.2.0; ` +
        'ranges, tags, spaces and shell metacharacters are rejected',
    );
  }
  return version;
}

/**
 * Validate the severity input. These are the exact severities the real
 * sentinel-lint CLI accepts for --fail-on, verified against the published
 * package: info, warning, error, critical.
 * @param {string} severity
 * @returns {string}
 */
function validateSeverity(severity) {
  if (!SEVERITIES.includes(severity)) {
    throw new InputError(`severity must be one of ${SEVERITIES.join(', ')}; got "${severity}"`);
  }
  return severity;
}

/**
 * Validate the report format. `text` is rendered by this action from the
 * machine readable scan output; `json` and `sarif` are machine formats.
 * @param {string} format
 * @returns {string}
 */
function validateFormat(format) {
  if (!FORMATS.includes(format)) {
    throw new InputError(`format must be one of ${FORMATS.join(', ')}; got "${format}"`);
  }
  return format;
}

/**
 * Validate the fail-on-findings toggle as a strict boolean string.
 * @param {string} value
 * @returns {boolean}
 */
function validateFailOnFindings(value) {
  const lowered = value.toLowerCase();
  if (lowered !== 'true' && lowered !== 'false') {
    throw new InputError(`fail-on-findings must be "true" or "false"; got "${value}"`);
  }
  return lowered === 'true';
}

/**
 * Resolve the scan path inside the workspace and reject anything that
 * escapes it. The scan target of a repository scanning action is always part
 * of the checked out tree, so an absolute path outside the workspace or a
 * `..` traversal past the workspace root is never legitimate.
 *
 * Backslashes are normalized to forward slashes on every platform before
 * resolution, so a `..\..` traversal payload cannot slip past validation on
 * posix runners while still being a separator on Windows runners.
 *
 * The containment check compares path segments through the platform path
 * parser rather than raw string prefixes, so `workspace-evil` siblings do
 * not pass and on Windows the comparison is case insensitive.
 *
 * @param {string} inputPath
 * @param {string} workspace
 * @returns {string} absolute resolved scan path inside the workspace
 */
function validateScanPath(inputPath, workspace) {
  if (typeof inputPath !== 'string' || inputPath.length === 0) {
    throw new InputError('path must be a non-empty string');
  }
  if (inputPath.length > 1024) {
    throw new InputError('path is longer than 1024 characters');
  }
  if (inputPath.includes('\u0000')) {
    throw new InputError('path must not contain NUL bytes');
  }
  if (typeof workspace !== 'string' || workspace.length === 0) {
    throw new InputError('workspace root is unknown; cannot validate the scan path');
  }

  const root = path.resolve(workspace);
  const canonical = inputPath.replace(/\\/g, '/');
  const resolved = path.resolve(root, canonical);

  const normalize = (value) => (process.platform === 'win32' ? value.toLowerCase() : value);
  const rootNorm = normalize(root);
  const resolvedNorm = normalize(resolved);
  const inside = resolvedNorm === rootNorm || resolvedNorm.startsWith(rootNorm + path.sep);
  if (!inside) {
    throw new InputError(
      `path "${inputPath}" resolves outside the workspace root; ` +
        'parent traversal and absolute paths outside the checkout are rejected',
    );
  }
  return resolved;
}

/**
 * Read and validate every action input from the environment.
 * @param {object} env usually process.env
 * @returns {{version: string, scanPathInput: string, severity: string, format: string, failOnFindings: boolean}}
 */
function readInputs(env) {
  const version = validateVersion(readRawInput(env, 'version'));
  const scanPathInput = readRawInput(env, 'path');
  const severity = validateSeverity(readRawInput(env, 'severity'));
  const format = validateFormat(readRawInput(env, 'format'));
  const failOnFindings = validateFailOnFindings(readRawInput(env, 'fail-on-findings'));
  return { version, scanPathInput, severity, format, failOnFindings };
}

module.exports = {
  InputError,
  SEMVER_RE,
  SEVERITIES,
  FORMATS,
  DEFAULTS,
  readInputs,
  validateVersion,
  validateSeverity,
  validateFormat,
  validateFailOnFindings,
  validateScanPath,
};
