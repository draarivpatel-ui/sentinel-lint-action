// Deliberately vulnerable fixture used to prove that scans produce findings.
// This file is scan target data only; it is never executed by any test.
import { execSync } from 'node:child_process';

export function run(userInput) {
  return execSync('sh -c "' + userInput + '"');
}
