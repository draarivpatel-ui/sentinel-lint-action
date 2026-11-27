'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  ReportError,
  artifactUri,
  fingerprintFor,
  jsonReportToSarif,
  serializeSarif,
} = require('../src/sarif.cjs');

/**
 * A representative scan report in the exact reportVersion 1 shape produced
 * by the published sentinel-lint 0.2.0 scanner.
 */
function sampleReport() {
  return {
    tool: { name: 'sentinel-lint', version: '0.2.0' },
    reportVersion: 1,
    summary: {
      filesScanned: 1,
      findings: 2,
      suppressed: 0,
      ruleErrors: 0,
      diagnostics: 0,
      bySeverity: { info: 0, warning: 1, error: 1, critical: 0 },
    },
    findings: [
      {
        ruleId: 'repo/missing-security-policy',
        severity: 'warning',
        category: 'repo',
        cwe: null,
        file: null,
        line: 1,
        column: 1,
        message: 'No SECURITY.md was found at the repository root.',
        fix: 'Add SECURITY.md with a private reporting channel.',
        docsUrl: 'docs/rules.md#repomissing-security-policy',
      },
      {
        ruleId: 'repo/child-process-injection',
        severity: 'error',
        category: 'repo',
        cwe: 'CWE-78',
        file: 'evil.mjs',
        line: 3,
        column: 10,
        message: 'child_process.exec receives a command assembled from interpolated data.',
        fix: 'Use execFile or spawn with an argument array.',
        docsUrl: 'docs/rules.md#repochild-process-injection',
      },
    ],
    diagnostics: [],
    rules: [
      {
        id: 'repo/missing-security-policy',
        severity: 'warning',
        category: 'repo',
        cwe: null,
        title: 'repository has no security policy',
      },
      {
        id: 'repo/child-process-injection',
        severity: 'error',
        category: 'repo',
        cwe: 'CWE-78',
        title: 'child process command injection',
      },
    ],
  };
}

test('the conversion produces a valid SARIF 2.1.0 envelope', () => {
  const sarif = jsonReportToSarif(sampleReport());
  assert.equal(sarif.version, '2.1.0');
  assert.equal(sarif.$schema, 'https://json.schemastore.org/sarif-2.1.0.json');
  assert.ok(Array.isArray(sarif.runs));
  assert.equal(sarif.runs.length, 1);
  const run = sarif.runs[0];
  assert.equal(run.tool.driver.name, 'sentinel-lint');
  assert.equal(run.tool.driver.version, '0.2.0');
  assert.equal(run.tool.driver.informationUri, 'https://github.com/draarivpatel-ui/sentinel-lint');
  assert.ok(Array.isArray(run.tool.driver.rules));
  assert.ok(Array.isArray(run.results));
});

test('every rule carries the SARIF 2.1.0 reporting descriptor shape', () => {
  const sarif = jsonReportToSarif(sampleReport());
  for (const rule of sarif.runs[0].tool.driver.rules) {
    assert.equal(typeof rule.id, 'string');
    assert.equal(typeof rule.name, 'string');
    assert.ok(/^[A-Za-z0-9_]+$/.test(rule.name), 'rule name must be a valid SARIF logical name');
    assert.equal(typeof rule.shortDescription.text, 'string');
    assert.ok(['note', 'warning', 'error'].includes(rule.defaultConfiguration.level));
    assert.ok(Array.isArray(rule.properties.tags));
    assert.ok(rule.properties.tags.includes('security'));
  }
});

test('every result carries the SARIF 2.1.0 result shape with a valid location', () => {
  const sarif = jsonReportToSarif(sampleReport());
  assert.equal(sarif.runs[0].results.length, 2);
  for (const result of sarif.runs[0].results) {
    assert.equal(typeof result.ruleId, 'string');
    assert.ok(['note', 'warning', 'error'].includes(result.level));
    assert.equal(typeof result.message.text, 'string');
    assert.ok(Array.isArray(result.locations));
    const physical = result.locations[0].physicalLocation;
    assert.equal(typeof physical.artifactLocation.uri, 'string');
    assert.ok(!physical.artifactLocation.uri.startsWith('/'), 'artifact URI must be relative');
    assert.ok(Number.isInteger(physical.region.startLine) && physical.region.startLine >= 1);
    assert.ok(Number.isInteger(physical.region.startColumn) && physical.region.startColumn >= 1);
    assert.equal(typeof result.partialFingerprints['sentinelLintFindingHash/v1'], 'string');
  }
});

test('severity levels map exactly like the upstream scanner reporter', () => {
  const report = sampleReport();
  const sarif = jsonReportToSarif(report);
  const byRule = new Map(sarif.runs[0].results.map((r) => [r.ruleId, r.level]));
  assert.equal(byRule.get('repo/missing-security-policy'), 'warning');
  assert.equal(byRule.get('repo/child-process-injection'), 'error');
});

test('ruleIndex points at the matching driver rule', () => {
  const sarif = jsonReportToSarif(sampleReport());
  const rules = sarif.runs[0].tool.driver.rules;
  for (const result of sarif.runs[0].results) {
    assert.equal(rules[result.ruleIndex].id, result.ruleId);
  }
});

test('repo level findings without a file still produce a valid location', () => {
  const sarif = jsonReportToSarif(sampleReport());
  const repoFinding = sarif.runs[0].results.find((r) => r.ruleId === 'repo/missing-security-policy');
  const uri = repoFinding.locations[0].physicalLocation.artifactLocation.uri;
  assert.equal(typeof uri, 'string');
  assert.ok(uri.length > 0);
  assert.ok(!uri.startsWith('/'));
});

test('hostile paths cannot escape into absolute artifact URIs', () => {
  assert.equal(artifactUri('../../etc/passwd'), 'etc/passwd');
  assert.equal(artifactUri('/etc/passwd'), 'etc/passwd');
  assert.equal(artifactUri('C:\\Windows\\system32'), 'Windows/system32');
  assert.equal(artifactUri('src/some file.mjs'), 'src/some%20file.mjs');
  assert.ok(!artifactUri('..').startsWith('/'));
  assert.equal(artifactUri('..'), '.');
});

test('fingerprints are stable and independent of the line number', () => {
  const finding = sampleReport().findings[1];
  const moved = { ...finding, line: 99, column: 1 };
  assert.equal(fingerprintFor(finding), fingerprintFor(moved));
  const other = { ...finding, message: 'different message' };
  assert.notEqual(fingerprintFor(finding), fingerprintFor(other));
});

test('serialization round trips as parseable JSON with a trailing newline', () => {
  const text = serializeSarif(jsonReportToSarif(sampleReport()));
  assert.ok(text.endsWith('\n'));
  const parsed = JSON.parse(text);
  assert.equal(parsed.version, '2.1.0');
});

test('unsupported or malformed reports are rejected', () => {
  assert.throws(() => jsonReportToSarif(null), ReportError);
  assert.throws(() => jsonReportToSarif({ reportVersion: 2, findings: [], rules: [] }), ReportError);
  assert.throws(() => jsonReportToSarif({ reportVersion: 1 }), ReportError);
});

test('conversion is deterministic for the same report', () => {
  const first = serializeSarif(jsonReportToSarif(sampleReport()));
  const second = serializeSarif(jsonReportToSarif(sampleReport()));
  assert.equal(first, second);
});
