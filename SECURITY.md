# Security Policy

## Reporting a vulnerability

Privately report a suspected vulnerability through the repository's [Security Advisory reporting form](https://github.com/draarivpatel-ui/sentinel-lint-action/security/advisories/new). Do not open a public issue for a suspected vulnerability.

Please include:

- A minimal reproduction that uses synthetic input only.
- The affected project version, commit or action ref, and Node.js version.
- The expected security boundary and the observed violation.
- Logs, output, or proof-of-concept code needed to reproduce the finding, with real secrets removed.

Never include a real token, cookie, password, private key, production log line or real personal data in a report.

Vulnerability handling steps:

1. The maintainer acknowledges the private report within 72 hours.
2. The maintainer reproduces the finding against the latest supported version and confirms severity within 14 days when enough information is available.
3. A fix is developed privately, with regression coverage where practical.
4. The maintainer coordinates the advisory, affected versions, reporter credit and disclosure date with the reporter.
5. The target coordinated disclosure window is 90 days or less from acknowledgment. If more time is needed, the maintainer and reporter agree on a new date before disclosure.

## Scope

This repository is a GitHub Action that installs and executes the published
[`sentinel-lint`](https://github.com/draarivpatel-ui/sentinel-lint) npm
package. Reports about the scanner's rules or engine belong to the scanner
repository; reports about input validation, process execution, report
generation or workflow integration belong here.

## Hardening measures in this action

- **No shell anywhere.** npm and the scanner run through `execFileSync` with
  fixed argument arrays. Input values travel as single argv elements and are
  never reparsed by a shell, a `cmd` shim or a glob expansion.
- **Strict semver enforcement.** The `version` input must match the official
  semver grammar exactly. Ranges, tags, spaces and shell metacharacters are
  rejected, so the input cannot be turned into a different package spec, an
  npm option or a registry redirect.
- **Allowlisted enums.** `severity` and `format` are validated against exact
  allowlists matching the real sentinel-lint CLI surface.
- **Workspace containment.** The scan path must resolve inside the GitHub
  workspace. Parent traversal and absolute paths outside the checkout are
  rejected, so an untrusted workflow input cannot scan or leak arbitrary host
  paths.
- **Integrity-verified install.** The scanner tarball is downloaded from the
  npm registry and verified byte for byte against the sha512 integrity value
  in the registry metadata before extraction. The extractor rejects links,
  device entries, absolute paths, dot-dot traversal and oversized content.
  No package manager or lifecycle script ever executes, so the pipeline is
  identical on Linux, macOS and Windows runners.
- **SARIF sanitization.** Artifact URIs in generated SARIF are
  repository-relative with drive letters, leading slashes and dot segments
  removed, so a hostile scan target cannot publish absolute host paths into
  code scanning alerts.
- **Output hygiene.** Step outputs are written through the file-based
  `$GITHUB_OUTPUT` mechanism with newline rejection, and workflow command
  messages are escaped, so scan content cannot inject runner commands.

## Supported versions

The latest commit on `main` and the most recent major version tag are
supported. Pin to a major tag such as `@v1` in your workflows.
