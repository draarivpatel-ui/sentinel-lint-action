'use strict';

/**
 * Live integration tests against the published sentinel-lint npm package.
 * These tests need network access to the npm registry. Set
 * SENTINEL_ACTION_SKIP_NETWORK=1 to skip them in offline environments.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs');
const { execFileSync } = require('node:child_process');

const { run } = require('../src/main.cjs');
const { installSentinelLint, findNpmCli } = require('../src/install.cjs');
const { jsonReportToSarif } = require('../src/sarif.cjs');

const SKIP = process.env.SENTINEL_ACTION_SKIP_NETWORK === '1';
const FIXTURE = path.join(__dirname, 'fixtures', 'vulnerable');

function makeWorkspace() {
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'sla-it-workspace-'));
  const target = path.join(workspace, 'target');
  fs.mkdirSync(target);
  for (const file of fs.readdirSync(FIXTURE)) {
    fs.copyFileSync(path.join(FIXTURE, file), path.join(target, file));
  }
  return workspace;
}

function makeEnv(workspace, overrides) {
  const outputFile = path.join(workspace, 'github-output.txt');
  return {
    env: {
      GITHUB_WORKSPACE: workspace,
      GITHUB_OUTPUT: outputFile,
      INPUT_VERSION: '0.2.0',
      INPUT_PATH: 'target',
      INPUT_SEVERITY: 'warning',
      INPUT_FORMAT: 'sarif',
      'INPUT_FAIL-ON-FINDINGS': 'false',
      ...overrides,
    },
    outputFile,
  };
}

function readOutputs(outputFile) {
  const outputs = new Map();
  for (const line of fs.readFileSync(outputFile, 'utf8').split('\n')) {
    if (line === '') continue;
    const eq = line.indexOf('=');
    outputs.set(line.slice(0, eq), line.slice(eq + 1));
  }
  return outputs;
}

test('findNpmCli locates the npm client of this Node.js distribution', { skip: SKIP }, () => {
  const cli = findNpmCli(process.execPath);
  assert.ok(cli.endsWith('npm-cli.js'));
  assert.ok(fs.existsSync(cli));
});

test('the exact published package installs into an isolated prefix', { skip: SKIP }, () => {
  const installDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sla-it-install-'));
  try {
    const root = installSentinelLint({ version: '0.2.0', installDir });
    const manifest = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
    assert.equal(manifest.name, 'sentinel-lint');
    assert.equal(manifest.version, '0.2.0');
    assert.ok(fs.existsSync(path.join(root, 'bin', 'sentinel-lint.mjs')));
  } finally {
    fs.rmSync(installDir, { recursive: true, force: true });
  }
});

test('full action run with format sarif produces valid SARIF 2.1.0 and correct outputs', { skip: SKIP }, (t) => {
  const workspace = makeWorkspace();
  t.after(() => fs.rmSync(workspace, { recursive: true, force: true }));
  const { env, outputFile } = makeEnv(workspace, { INPUT_FORMAT: 'sarif', 'INPUT_FAIL-ON-FINDINGS': 'false' });

  const code = run(env);
  assert.equal(code, 0);

  const outputs = readOutputs(outputFile);
  const count = Number(outputs.get('findings-count'));
  assert.ok(Number.isInteger(count) && count >= 1, 'the vulnerable fixture must produce findings');

  const sarifFile = outputs.get('sarif-file');
  assert.ok(sarifFile.length > 0);
  assert.equal(outputs.get('report-file'), sarifFile);
  assert.ok(fs.existsSync(sarifFile));

  const sarif = JSON.parse(fs.readFileSync(sarifFile, 'utf8'));
  assert.equal(sarif.version, '2.1.0');
  assert.equal(sarif.$schema, 'https://json.schemastore.org/sarif-2.1.0.json');
  assert.equal(sarif.runs.length, 1);
  assert.equal(sarif.runs[0].tool.driver.name, 'sentinel-lint');
  assert.equal(sarif.runs[0].results.length, count);
  for (const result of sarif.runs[0].results) {
    assert.equal(typeof result.ruleId, 'string');
    assert.ok(Array.isArray(result.locations));
    const uri = result.locations[0].physicalLocation.artifactLocation.uri;
    assert.ok(!uri.startsWith('/'), 'artifact URIs must be repository relative');
  }
});

test('full action run with format json fails the step when findings reach the threshold', { skip: SKIP }, (t) => {
  const workspace = makeWorkspace();
  t.after(() => fs.rmSync(workspace, { recursive: true, force: true }));
  const { env, outputFile } = makeEnv(workspace, { INPUT_FORMAT: 'json', 'INPUT_FAIL-ON-FINDINGS': 'true', INPUT_SEVERITY: 'warning' });

  const code = run(env);
  assert.equal(code, 1, 'warning level findings exist in the fixture, so the step must fail');

  const outputs = readOutputs(outputFile);
  const count = Number(outputs.get('findings-count'));
  assert.ok(count >= 1);
  assert.equal(outputs.get('sarif-file'), '');
  const report = JSON.parse(fs.readFileSync(outputs.get('report-file'), 'utf8'));
  assert.equal(report.reportVersion, 1);
  assert.equal(report.summary.findings, count);
});

test('full action run with format text writes a readable report', { skip: SKIP }, (t) => {
  const workspace = makeWorkspace();
  t.after(() => fs.rmSync(workspace, { recursive: true, force: true }));
  const { env, outputFile } = makeEnv(workspace, { INPUT_FORMAT: 'text', 'INPUT_FAIL-ON-FINDINGS': 'false' });

  const code = run(env);
  assert.equal(code, 0);
  const outputs = readOutputs(outputFile);
  const text = fs.readFileSync(outputs.get('report-file'), 'utf8');
  assert.ok(text.includes('scan report'));
  assert.ok(/finding|findings/.test(text));
});

test('converted SARIF matches the native scanner SARIF in result count and rule ids', { skip: SKIP }, (t) => {
  const workspace = makeWorkspace();
  t.after(() => fs.rmSync(workspace, { recursive: true, force: true }));

  const installDir = path.join(workspace, 'install');
  const root = installSentinelLint({ version: '0.2.0', installDir });
  const bin = path.join(root, 'bin', 'sentinel-lint.mjs');
  const target = path.join(workspace, 'target');

  const jsonPath = path.join(workspace, 'native.json');
  const sarifPath = path.join(workspace, 'native.sarif');
  for (const args of [
    [bin, 'scan', target, '--format', 'json', '--output', jsonPath, '--fail-on', 'off'],
    [bin, 'scan', target, '--format', 'sarif', '--output', sarifPath, '--fail-on', 'off'],
  ]) {
    execFileSync(process.execPath, args, { stdio: ['ignore', 'pipe', 'pipe'] });
  }

  const report = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));
  const native = JSON.parse(fs.readFileSync(sarifPath, 'utf8'));
  const converted = jsonReportToSarif(report);

  assert.equal(converted.runs[0].results.length, native.runs[0].results.length);
  const nativeRuleIds = native.runs[0].results.map((r) => r.ruleId).sort();
  const convertedRuleIds = converted.runs[0].results.map((r) => r.ruleId).sort();
  assert.deepEqual(convertedRuleIds, nativeRuleIds);
  const nativeLevels = native.runs[0].results.map((r) => r.level).sort();
  const convertedLevels = converted.runs[0].results.map((r) => r.level).sort();
  assert.deepEqual(convertedLevels, nativeLevels);
});

test('a malicious version input fails before any install or scan', { skip: SKIP }, (t) => {
  const workspace = makeWorkspace();
  t.after(() => fs.rmSync(workspace, { recursive: true, force: true }));
  const { env } = makeEnv(workspace, { INPUT_VERSION: '0.2.0; echo pwned' });

  const code = run(env);
  assert.equal(code, 1);
  assert.ok(!fs.existsSync(path.join(workspace, 'sentinel-lint.sarif')));
  assert.ok(!fs.existsSync(path.join(workspace, 'sentinel-lint-report.json')));
});

test('a path traversal input fails before any install or scan', { skip: SKIP }, (t) => {
  const workspace = makeWorkspace();
  t.after(() => fs.rmSync(workspace, { recursive: true, force: true }));
  const { env } = makeEnv(workspace, { INPUT_PATH: '../../etc' });

  const code = run(env);
  assert.equal(code, 1);
  assert.ok(!fs.existsSync(path.join(workspace, 'sentinel-lint.sarif')));
});
