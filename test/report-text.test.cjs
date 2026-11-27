'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { renderTextReport } = require('../src/report-text.cjs');

function reportWith(findings) {
  return {
    tool: { name: 'sentinel-lint', version: '0.2.0' },
    reportVersion: 1,
    summary: {
      filesScanned: 3,
      findings: findings.length,
      suppressed: 0,
      ruleErrors: 0,
      diagnostics: 0,
      bySeverity: {
        info: findings.filter((f) => f.severity === 'info').length,
        warning: findings.filter((f) => f.severity === 'warning').length,
        error: findings.filter((f) => f.severity === 'error').length,
        critical: findings.filter((f) => f.severity === 'critical').length,
      },
    },
    findings,
    diagnostics: [],
    rules: [],
  };
}

test('an empty report renders a clean summary', () => {
  const text = renderTextReport(reportWith([]));
  assert.ok(text.includes('0 findings in 3 files'));
  assert.ok(text.includes('no findings'));
  assert.ok(text.endsWith('\n'));
});

test('findings render with severity, rule, location, message and fix', () => {
  const text = renderTextReport(
    reportWith([
      {
        ruleId: 'repo/child-process-injection',
        severity: 'error',
        category: 'repo',
        cwe: 'CWE-78',
        file: 'evil.mjs',
        line: 3,
        column: 10,
        message: 'injection risk',
        fix: 'use execFile',
        docsUrl: null,
      },
    ]),
  );
  assert.ok(text.includes('1 finding in 3 files'));
  assert.ok(text.includes('error  repo/child-process-injection  evil.mjs:3:10'));
  assert.ok(text.includes('injection risk'));
  assert.ok(text.includes('fix: use execFile'));
  assert.ok(text.includes('1 error'));
});

test('repo level findings render without a file location', () => {
  const text = renderTextReport(
    reportWith([
      {
        ruleId: 'repo/missing-security-policy',
        severity: 'warning',
        category: 'repo',
        cwe: null,
        file: null,
        line: 1,
        column: 1,
        message: 'no policy',
        fix: null,
        docsUrl: null,
      },
    ]),
  );
  assert.ok(text.includes('repo/missing-security-policy  repository'));
});

test('rendering is deterministic and ordered by severity', () => {
  const report = reportWith([
    { ruleId: 'a/info-rule', severity: 'info', category: 'repo', cwe: null, file: 'a.mjs', line: 1, column: 1, message: 'info one', fix: null, docsUrl: null },
    { ruleId: 'b/critical-rule', severity: 'critical', category: 'repo', cwe: null, file: 'b.mjs', line: 1, column: 1, message: 'critical one', fix: null, docsUrl: null },
  ]);
  const first = renderTextReport(report);
  const second = renderTextReport(report);
  assert.equal(first, second);
  assert.ok(first.indexOf('critical one') < first.indexOf('info one'));
});
