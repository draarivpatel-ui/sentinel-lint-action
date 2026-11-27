# Security Policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's private vulnerability
reporting on this repository (Security tab, then "Report a vulnerability").
Do not open a public issue for a security problem.

You can expect an acknowledgement within 7 days. If the report is accepted, a
fix will be prepared before any public disclosure, and credit will be given
in the release notes unless you prefer otherwise.

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
