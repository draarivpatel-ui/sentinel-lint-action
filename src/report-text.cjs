'use strict';

/**
 * Plain text rendering of a sentinel-lint JSON scan report.
 *
 * The scanner's own terminal format is designed for an interactive console.
 * This renderer produces a deterministic plain text document from the machine
 * readable report, suitable for build logs and artifacts.
 */

const SEVERITY_ORDER = Object.freeze({ critical: 0, error: 1, warning: 2, info: 3 });

function compareFindings(a, b) {
  const sev = (SEVERITY_ORDER[a.severity] === undefined ? 4 : SEVERITY_ORDER[a.severity]) -
    (SEVERITY_ORDER[b.severity] === undefined ? 4 : SEVERITY_ORDER[b.severity]);
  if (sev !== 0) return sev;
  const fileA = a.file || '';
  const fileB = b.file || '';
  if (fileA !== fileB) return fileA < fileB ? -1 : 1;
  if ((a.line || 0) !== (b.line || 0)) return (a.line || 0) - (b.line || 0);
  return String(a.ruleId) < String(b.ruleId) ? -1 : 1;
}

/**
 * Render the report as plain text with a trailing newline.
 * @param {object} report parsed sentinel-lint JSON report
 * @returns {string}
 */
function renderTextReport(report) {
  const version = report.tool && report.tool.version ? report.tool.version : 'unknown';
  const summary = report.summary || {};
  const count = typeof summary.findings === 'number' ? summary.findings : report.findings.length;
  const files = typeof summary.filesScanned === 'number' ? summary.filesScanned : 0;

  const lines = [];
  lines.push(`sentinel-lint ${version} scan report`);
  lines.push(`${count} ${count === 1 ? 'finding' : 'findings'} in ${files} ${files === 1 ? 'file' : 'files'}`);
  lines.push('');

  if (summary.bySeverity && typeof summary.bySeverity === 'object') {
    const parts = [];
    for (const severity of ['critical', 'error', 'warning', 'info']) {
      const n = summary.bySeverity[severity] || 0;
      if (n > 0) parts.push(`${n} ${severity}`);
    }
    if (parts.length > 0) {
      lines.push(`severity breakdown: ${parts.join(', ')}`);
      lines.push('');
    }
  }

  const findings = [...report.findings].sort(compareFindings);
  for (const finding of findings) {
    const location = finding.file ? `${finding.file}:${finding.line}:${finding.column}` : 'repository';
    lines.push(`${finding.severity}  ${finding.ruleId}  ${location}`);
    lines.push(`  ${finding.message}`);
    if (finding.fix) lines.push(`  fix: ${finding.fix}`);
    lines.push('');
  }

  if (findings.length === 0) {
    lines.push('no findings');
    lines.push('');
  }

  return `${lines.join('\n').replace(/\n{3,}/g, '\n\n')}\n`;
}

module.exports = { renderTextReport };
