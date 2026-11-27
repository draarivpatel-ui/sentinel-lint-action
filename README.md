# sentinel-lint-action

GitHub Action that scans your repository with the published
[`sentinel-lint`](https://github.com/draarivpatel-ui/sentinel-lint) security
policy linter and produces SARIF 2.1.0, JSON or plain text reports that plug
straight into GitHub code scanning.

- **Zero runtime dependencies.** The action is plain Node.js; there is
  nothing to audit beyond the sources in this repository.
- **Shell-free execution.** npm and the scanner are executed with
  `execFileSync` and fixed argument arrays. No input is ever reparsed by a
  shell, a command shim or a glob expansion.
- **Strictly validated inputs.** The package version must be exact semver,
  severities and formats are allowlisted, and scan paths that escape the
  workspace are rejected before anything executes.
- **Supply-chain conscious install.** The scanner tarball is downloaded
  straight from the npm registry, verified byte for byte against the sha512
  integrity value in the registry metadata, and extracted with a defensive
  zero-dependency tar parser. No package manager or lifecycle script ever
  executes, on any operating system.

## Usage

```yaml
name: security-scan
on:
  push:
    branches: [main]
  pull_request:

permissions:
  security-events: write
  contents: read

jobs:
  sentinel-lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run sentinel-lint
        id: sentinel
        uses: draarivpatel-ui/sentinel-lint-action@v1
        with:
          path: '.'
          severity: warning
          format: sarif
          fail-on-findings: 'false'

      - name: Upload SARIF to code scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ${{ steps.sentinel.outputs.sarif-file }}
```

Set `fail-on-findings` to `'true'` (the default) to fail the workflow when
any finding reaches the severity threshold. Keep it `'false'` while adopting
the action so code scanning collects results without blocking merges.

The `security-events: write` permission is required for the SARIF upload on
private repositories and is good practice everywhere.

## Inputs

| Input | Default | Description |
| --- | --- | --- |
| `version` | `0.2.0` | Exact semver version of the published `sentinel-lint` npm package. Strict semver is enforced; ranges and tags are rejected. |
| `path` | `.` | Directory or file to scan, relative to the workspace root. Paths resolving outside the workspace are rejected. |
| `severity` | `warning` | Minimum severity that fails the step: `info`, `warning`, `error` or `critical`. These are the exact severities of the sentinel-lint CLI. |
| `format` | `sarif` | Report format written into the workspace: `text`, `json` or `sarif`. |
| `fail-on-findings` | `true` | When `true` the step fails if any finding reaches the severity threshold. |

## Outputs

| Output | Description |
| --- | --- |
| `findings-count` | Total number of findings reported by the scan. |
| `report-file` | Absolute path of the report file written into the workspace. |
| `sarif-file` | Absolute path of the SARIF 2.1.0 file when `format` is `sarif`, empty otherwise. |

## Report formats

The action runs one scan in the scanner's machine readable JSON format and
renders the requested report from it in pure zero-dependency Node.js:

- `sarif` writes `sentinel-lint.sarif`, a valid SARIF 2.1.0 log with rule
  metadata, severity levels, CWE tags, repository-relative artifact URIs and
  stable partial fingerprints, ready for `github/codeql-action/upload-sarif`.
- `json` writes `sentinel-lint-report.json`, the scanner's own machine
  readable report (reportVersion 1).
- `text` writes `sentinel-lint-report.txt`, a deterministic plain text report
  for build logs and artifacts.

## What sentinel-lint scans for

`sentinel-lint` is a plugin-first, zero-dependency security policy linter.
Its built-in rules cover GitHub Actions workflow risks such as
`pull_request_target` checkouts of untrusted code and script injection
through untrusted context interpolation, repository hygiene such as missing
security policies, dependency and supply-chain shapes, and MCP configuration
weaknesses, mapped to CWE identifiers including CWE-78, CWE-79, CWE-94,
CWE-95, CWE-200, CWE-272, CWE-319, CWE-732, CWE-798, CWE-829 and CWE-1357.
See the [scanner repository](https://github.com/draarivpatel-ui/sentinel-lint)
for the full rule list.

## Scanning a subdirectory

```yaml
- uses: draarivpatel-ui/sentinel-lint-action@v1
  with:
    path: 'services/api'
    format: json
```

## Pinning the scanner version

```yaml
- uses: draarivpatel-ui/sentinel-lint-action@v1
  with:
    version: 0.2.0
```

The version must be exact semver. An input such as `latest`, `^0.2.0` or any
string with shell metacharacters fails validation before npm ever runs.

## Security

See [SECURITY.md](SECURITY.md). In short: inputs are validated against
allowlists, no shell is ever invoked, the scanner tarball is verified against
registry integrity metadata before extraction, and SARIF artifact URIs are
sanitized so a hostile scan target cannot publish absolute host paths into
code scanning alerts.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The test suite covers input
validation, adversarial command-injection and path-traversal attempts, SARIF
2.1.0 output structure and a live integration scan of the published
`sentinel-lint` package; CI runs it on Ubuntu and Windows and then runs the
action itself against a fixture.

## License

[MIT](LICENSE)
