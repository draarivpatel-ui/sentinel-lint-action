# Contributing

Thanks for improving sentinel-lint-action. This document explains how to set
up, test and propose changes.

## Ground rules

- **Zero runtime dependencies.** The action runs in the GitHub `node20`
  runtime straight from the sources in this repository. Do not add npm
  dependencies; if a capability seems to need one, implement it in the
  zero-dependency style of the existing modules or open an issue first.
- **No shell execution.** Child processes run through `execFileSync` with
  fixed argument arrays. Never introduce `exec`, `execSync`, `spawn` with
  `shell: true` or string-concatenated commands.
- **Validate at the boundary.** Every new input must be validated in
  `src/inputs.cjs` against a strict allowlist or grammar before use.
- **Verify against the real scanner.** The CLI surface this action relies on
  (commands, flags, exit codes, report shape) is defined by the published
  [`sentinel-lint`](https://github.com/draarivpatel-ui/sentinel-lint) npm
  package. Confirm assumptions against the real package, not against memory.

## Setup

The only requirement is Node.js 20 or newer with npm. There is nothing to
install:

```sh
git clone https://github.com/draarivpatel-ui/sentinel-lint-action.git
cd sentinel-lint-action
npm test
```

## Test suite

Run the suite with `npm test` (which is `node --test test/`).

- `test/inputs.test.cjs` covers input parsing and validation.
- `test/injection.test.cjs` covers adversarial command-injection and
  path-traversal attempts against every input.
- `test/sarif.test.cjs` covers the SARIF 2.1.0 conversion structure.
- `test/report-text.test.cjs` covers the plain text rendering.
- `test/integration.test.cjs` performs a live scan of a fixture using the
  published `sentinel-lint` npm package and exercises the full action entry
  point. It needs network access to the npm registry; set
  `SENTINEL_ACTION_SKIP_NETWORK=1` to skip it offline.

The CI workflow additionally runs the action itself (`uses: ./`) against a
vulnerable fixture on Ubuntu and Windows, so every change is exercised
end-to-end in the real runner environment.

## Style

- CommonJS modules, strict mode, small documented functions.
- Comments explain why a security measure exists, not what the code does.
- No external dependencies in `dependencies` or `devDependencies`.

## Pull requests

- Keep changes focused and explain the security reasoning.
- Add tests for every behavior change, including adversarial cases for
  anything that touches input handling or process execution.
- CI must be green on both Ubuntu and Windows.
