'use strict';

/**
 * Conversion of a sentinel-lint JSON report (reportVersion 1) into a valid
 * SARIF 2.1.0 log in pure zero-dependency Node.js.
 *
 * The JSON report carries every field a SARIF consumer needs: the tool
 * version, the active rule metadata (id, title, severity, category, CWE) and
 * each finding with its repository relative file, 1-based line and column,
 * message and remediation text. The conversion is deterministic: findings
 * keep their scan order and rule ordering follows the report.
 */

const { createHash } = require('node:crypto');

const SARIF_SCHEMA = 'https://json.schemastore.org/sarif-2.1.0.json';
const SARIF_VERSION = '2.1.0';
const INFORMATION_URI = 'https://github.com/draarivpatel-ui/sentinel-lint';

class ReportError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ReportError';
  }
}

const LEVEL_BY_SEVERITY = Object.freeze({
  info: 'note',
  warning: 'warning',
  error: 'error',
  critical: 'error',
});

const SECURITY_SEVERITY = Object.freeze({
  info: '0.0',
  warning: '4.0',
  error: '7.0',
  critical: '9.0',
});

/**
 * Encode a repository relative path as a SARIF artifact URI. The result is
 * always relative: drive letters, leading slashes and dot segments are
 * removed so a malformed or hostile finding cannot publish an absolute host
 * path into a SARIF log attached to a code scanning alert.
 * @param {string} filePath
 * @returns {string}
 */
function artifactUri(filePath) {
  const normalized = String(filePath)
    .replace(/\\/g, '/')
    .replace(/^[A-Za-z]:/, '')
    .replace(/^\/+/, '');
  const segments = normalized
    .split('/')
    .filter((segment) => segment !== '' && segment !== '.' && segment !== '..')
    .map((segment) => encodeURIComponent(segment));
  return segments.length === 0 ? '.' : segments.join('/');
}

/**
 * Stable fingerprint for a finding. It does not depend on the line number,
 * so a finding that moves within its file is still recognized as the same
 * issue by code scanning alert tracking.
 * @param {object} finding
 * @returns {string}
 */
function fingerprintFor(finding) {
  const material = [finding.ruleId, finding.file || '', finding.message].join('\u0000');
  return createHash('sha256').update(material, 'utf8').digest('hex').slice(0, 32);
}

function sarifRule(rule) {
  const descriptor = {
    id: rule.id,
    name: String(rule.id).replace(/[^A-Za-z0-9]+/g, '_'),
    shortDescription: { text: rule.title || rule.id },
    defaultConfiguration: { level: LEVEL_BY_SEVERITY[rule.severity] || 'warning' },
    properties: {
      tags: ['security', rule.category || 'repo'],
      precision: 'high',
      'security-severity': SECURITY_SEVERITY[rule.severity] || '4.0',
    },
  };
  if (rule.cwe) descriptor.properties.cwe = rule.cwe;
  return descriptor;
}

function sarifResult(finding, ruleIndex) {
  const result = {
    ruleId: finding.ruleId,
    level: LEVEL_BY_SEVERITY[finding.severity] || 'warning',
    message: { text: finding.message },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: artifactUri(finding.file || '.') },
          region: {
            startLine: Math.max(1, finding.line || 1),
            startColumn: Math.max(1, finding.column || 1),
          },
        },
      },
    ],
    partialFingerprints: {
      'sentinelLintFindingHash/v1': fingerprintFor(finding),
    },
    properties: {
      severity: finding.severity,
      category: finding.category || 'repo',
    },
  };
  if (ruleIndex !== undefined) result.ruleIndex = ruleIndex;
  if (finding.cwe) result.properties.cwe = finding.cwe;
  if (finding.fix) result.properties.fix = finding.fix;
  return result;
}

/**
 * Convert a parsed sentinel-lint JSON report into a SARIF 2.1.0 object.
 * @param {object} report parsed JSON report of reportVersion 1
 * @returns {object} SARIF 2.1.0 log
 */
function jsonReportToSarif(report) {
  if (report === null || typeof report !== 'object') {
    throw new ReportError('the scan report is not a JSON object');
  }
  if (report.reportVersion !== 1) {
    throw new ReportError(
      `unsupported scan report version "${String(report.reportVersion)}"; expected reportVersion 1`,
    );
  }
  if (!Array.isArray(report.findings) || !Array.isArray(report.rules)) {
    throw new ReportError('the scan report is missing its findings or rules arrays');
  }

  const ruleIndexById = new Map();
  report.rules.forEach((rule, index) => {
    if (!ruleIndexById.has(rule.id)) ruleIndexById.set(rule.id, index);
  });

  return {
    $schema: SARIF_SCHEMA,
    version: SARIF_VERSION,
    runs: [
      {
        tool: {
          driver: {
            name: 'sentinel-lint',
            version: report.tool && report.tool.version ? report.tool.version : 'unknown',
            informationUri: INFORMATION_URI,
            rules: report.rules.map(sarifRule),
          },
        },
        results: report.findings.map((finding) => sarifResult(finding, ruleIndexById.get(finding.ruleId))),
      },
    ],
  };
}

/**
 * Serialize a SARIF log with a trailing newline, matching the byte layout
 * code scanning tooling expects on disk.
 * @param {object} sarif
 * @returns {string}
 */
function serializeSarif(sarif) {
  return `${JSON.stringify(sarif, null, 2)}\n`;
}

module.exports = {
  ReportError,
  SARIF_SCHEMA,
  SARIF_VERSION,
  INFORMATION_URI,
  artifactUri,
  fingerprintFor,
  jsonReportToSarif,
  serializeSarif,
};
