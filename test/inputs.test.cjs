'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs');

const {
  InputError,
  readInputs,
  validateVersion,
  validateSeverity,
  validateFormat,
  validateFailOnFindings,
  validateScanPath,
} = require('../src/inputs.cjs');

test('default inputs match the action manifest', () => {
  const inputs = readInputs({});
  assert.equal(inputs.version, '0.2.0');
  assert.equal(inputs.scanPathInput, '.');
  assert.equal(inputs.severity, 'warning');
  assert.equal(inputs.format, 'sarif');
  assert.equal(inputs.failOnFindings, true);
});

test('explicit inputs are read from INPUT_ environment variables', () => {
  const inputs = readInputs({
    INPUT_VERSION: '1.2.3',
    INPUT_PATH: 'src',
    INPUT_SEVERITY: 'critical',
    INPUT_FORMAT: 'json',
    'INPUT_FAIL-ON-FINDINGS': 'false',
  });
  assert.equal(inputs.version, '1.2.3');
  assert.equal(inputs.scanPathInput, 'src');
  assert.equal(inputs.severity, 'critical');
  assert.equal(inputs.format, 'json');
  assert.equal(inputs.failOnFindings, false);
});

test('hyphenated input names arrive with hyphens preserved, the exact runner behavior', () => {
  // Regression test: the GitHub Actions runner uppercases input names and
  // replaces spaces with underscores, but preserves hyphens. Reading
  // INPUT_FAIL_ON_FINDINGS instead of INPUT_FAIL-ON-FINDINGS silently falls
  // back to the default and inverts the fail gate.
  const strict = readInputs({ 'INPUT_FAIL-ON-FINDINGS': 'false' });
  assert.equal(strict.failOnFindings, false);
  const fallback = readInputs({ INPUT_FAIL_ON_FINDINGS: 'false' });
  assert.equal(fallback.failOnFindings, false);
  const exactWins = readInputs({ 'INPUT_FAIL-ON-FINDINGS': 'false', INPUT_FAIL_ON_FINDINGS: 'true' });
  assert.equal(exactWins.failOnFindings, false);
});

test('valid semver versions are accepted', () => {
  for (const version of ['0.2.0', '1.0.0', '2.1.3-alpha.1', '1.0.0+build.5', '10.20.30']) {
    assert.equal(validateVersion(version), version);
  }
});

test('non-semver versions are rejected', () => {
  for (const version of ['latest', '^0.2.0', '~1.0', '0.2', 'v1.0.0', '1.0.0.0', '']) {
    assert.throws(() => validateVersion(version), InputError, `expected rejection of ${version}`);
  }
});

test('severity accepts exactly the real sentinel-lint severities', () => {
  for (const severity of ['info', 'warning', 'error', 'critical']) {
    assert.equal(validateSeverity(severity), severity);
  }
  for (const severity of ['high', 'medium', 'low', 'none', 'off', 'WARNING', '']) {
    assert.throws(() => validateSeverity(severity), InputError, `expected rejection of ${severity}`);
  }
});

test('format accepts text, json and sarif only', () => {
  for (const format of ['text', 'json', 'sarif']) {
    assert.equal(validateFormat(format), format);
  }
  for (const format of ['terminal', 'html', 'SARIF', '']) {
    assert.throws(() => validateFormat(format), InputError, `expected rejection of ${format}`);
  }
});

test('fail-on-findings parses strict boolean strings', () => {
  assert.equal(validateFailOnFindings('true'), true);
  assert.equal(validateFailOnFindings('false'), false);
  assert.equal(validateFailOnFindings('TRUE'), true);
  for (const value of ['yes', '1', 'on', '']) {
    assert.throws(() => validateFailOnFindings(value), InputError, `expected rejection of ${value}`);
  }
});

test('scan paths inside the workspace are accepted and resolved', () => {
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'sla-inputs-'));
  try {
    const resolved = validateScanPath('.', workspace);
    assert.equal(resolved, path.resolve(workspace));
    const nested = validateScanPath('src/lib', workspace);
    assert.equal(nested, path.resolve(workspace, 'src/lib'));
    const dotdotInside = validateScanPath('src/../lib', workspace);
    assert.equal(dotdotInside, path.resolve(workspace, 'lib'));
  } finally {
    fs.rmSync(workspace, { recursive: true, force: true });
  }
});

test('scan paths escaping the workspace are rejected', () => {
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'sla-inputs-'));
  try {
    assert.throws(() => validateScanPath('..', workspace), InputError);
    assert.throws(() => validateScanPath('../../etc', workspace), InputError);
    assert.throws(() => validateScanPath(path.resolve(workspace, '..', 'outside'), workspace), InputError);
    const root = path.parse(workspace).root;
    assert.throws(() => validateScanPath(root, workspace), InputError);
  } finally {
    fs.rmSync(workspace, { recursive: true, force: true });
  }
});

test('scan paths with NUL bytes or excessive length are rejected', () => {
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'sla-inputs-'));
  try {
    assert.throws(() => validateScanPath('src/\u0000evil.js', workspace), InputError);
    assert.throws(() => validateScanPath('x'.repeat(2000), workspace), InputError);
    assert.throws(() => validateScanPath('', workspace), InputError);
  } finally {
    fs.rmSync(workspace, { recursive: true, force: true });
  }
});

test('a sibling directory with a shared name prefix is not inside the workspace', () => {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'sla-inputs-'));
  const workspace = path.join(parent, 'repo');
  fs.mkdirSync(workspace);
  try {
    assert.throws(() => validateScanPath('../repo-evil', workspace), InputError);
  } finally {
    fs.rmSync(parent, { recursive: true, force: true });
  }
});
