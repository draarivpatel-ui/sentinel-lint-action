'use strict';

/**
 * CI helper: verify that the action running in fail-on-findings mode against
 * the vulnerable fixture actually failed the step, proving the severity
 * threshold gate works end to end in the real runner.
 */

const outcome = process.env.OUTCOME || '';
const count = Number(process.env.FINDINGS_COUNT || '');

if (outcome !== 'failure') {
  process.stderr.write(
    `strict self-test verification failed: the scan step outcome was "${outcome}", expected "failure"\n`,
  );
  process.exitCode = 1;
} else if (!Number.isInteger(count) || count < 1) {
  process.stderr.write(
    `strict self-test verification failed: findings-count must be a positive integer, got "${process.env.FINDINGS_COUNT}"\n`,
  );
  process.exitCode = 1;
} else {
  process.stdout.write(`strict self-test verified: step failed as required with ${count} findings\n`);
}
