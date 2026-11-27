'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs');
const fc = require('fast-check');

const {
  InputError,
  SEMVER_RE,
  readInputs,
  validateFailOnFindings,
  validateFormat,
  validateScanPath,
  validateSeverity,
  validateVersion,
} = require('../src/inputs.cjs');

function outcome(fn) {
  try {
    return { value: fn(), error: null };
  } catch (error) {
    return { value: null, error };
  }
}

function insideWorkspace(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative === '' || (relative !== '..' && !relative.startsWith('..' + path.sep) && !path.isAbsolute(relative));
}

const hostileUnit = fc.constantFrom(
  '', '0', '1', '0.2.0', 'latest', '^', '~', 'v', ';', '&', '|', '`', '$', '(', ')', ' ', '\n', '\r', '\0',
  '..', '/', '\\', 'warning', 'sarif', 'true', 'false', 'evil'
);
const hostileText = fc.string({ unit: hostileUnit, minLength: 0, maxLength: 16 });

test('fast-check fuzzed action versions either satisfy strict semver or fail closed', () => {
  fc.assert(fc.property(hostileText, (input) => {
    const result = outcome(() => validateVersion(input));
    if (result.error) {
      assert.ok(result.error instanceof InputError, 'unexpected error type');
      return;
    }
    assert.equal(result.value, input);
    assert.equal(SEMVER_RE.test(result.value), true);
    assert.equal(/[\s;&|`$()]/.test(result.value), false);
  }), { seed: 0x5e11, numRuns: 240 });
});

test('fast-check shell metacharacter insertion in versions is always rejected', () => {
  fc.assert(fc.property(
    fc.integer({ min: 0, max: 5 }),
    fc.constantFrom(';', '&', '|', '`', '$', '(', ')', ' ', '\n', '\r', '\0'),
    (position, marker) => {
      const base = '0.2.0';
      const input = base.slice(0, position) + marker + base.slice(position);
      assert.throws(() => validateVersion(input), InputError);
    }
  ), { seed: 0x5e12, numRuns: 120 });
});

test('fast-check fuzzed scan paths either resolve inside the workspace or fail closed', () => {
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'sla-fuzz-workspace-'));
  try {
    const root = path.resolve(workspace);
    fc.assert(fc.property(hostileText, (input) => {
      const result = outcome(() => validateScanPath(input, workspace));
      if (result.error) {
        assert.ok(result.error instanceof InputError, 'unexpected error type');
        return;
      }
      assert.equal(typeof result.value, 'string');
      assert.equal(result.value.includes('\0'), false);
      assert.equal(insideWorkspace(root, result.value), true, 'scan path escaped the workspace');
    }), { seed: 0x5e13, numRuns: 240 });
  } finally {
    fs.rmSync(workspace, { recursive: true, force: true });
  }
});

test('fast-check readInputs never throws outside InputError and returns only strict values', () => {
  fc.assert(fc.property(hostileText, hostileText, hostileText, hostileText, hostileText, (version, scanPath, severity, format, failOnFindings) => {
    const env = {
      INPUT_VERSION: version,
      INPUT_PATH: scanPath,
      INPUT_SEVERITY: severity,
      INPUT_FORMAT: format,
      'INPUT_FAIL-ON-FINDINGS': failOnFindings,
    };
    const result = outcome(() => readInputs(env));
    if (result.error) {
      assert.ok(result.error instanceof InputError, 'unexpected error type');
      return;
    }
    assert.equal(SEMVER_RE.test(result.value.version), true);
    assert.equal(typeof result.value.scanPathInput, 'string');
    assert.equal(['info', 'warning', 'error', 'critical'].includes(result.value.severity), true);
    assert.equal(['text', 'json', 'sarif'].includes(result.value.format), true);
    assert.equal(typeof result.value.failOnFindings, 'boolean');
    assert.equal({}.polluted, undefined);
  }), { seed: 0x5e14, numRuns: 220 });
});

test('fast-check enum and boolean validators reject hostile strings without platform errors', () => {
  fc.assert(fc.property(hostileText, (input) => {
    for (const validate of [validateSeverity, validateFormat, validateFailOnFindings]) {
      const result = outcome(() => validate(input));
      if (result.error) {
        assert.ok(result.error instanceof InputError, 'unexpected error type');
      }
    }
  }), { seed: 0x5e15, numRuns: 140 });
});
