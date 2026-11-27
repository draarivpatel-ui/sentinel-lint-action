'use strict';

/**
 * GitHub Actions step output and workflow command helpers, implemented with
 * the file based output mechanism and escaped workflow commands. No external
 * dependency is needed for either.
 */

const fs = require('node:fs');

/**
 * Escape a value embedded in a workflow command so it cannot smuggle command
 * terminators or additional commands into the runner protocol.
 * @param {string} value
 * @returns {string}
 */
function escapeCommandValue(value) {
  return String(value).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
}

function info(message) {
  process.stdout.write(`${message}\n`);
}

function error(message) {
  process.stdout.write(`::error::${escapeCommandValue(message)}\n`);
}

function notice(message) {
  process.stdout.write(`::notice::${escapeCommandValue(message)}\n`);
}

/**
 * Write one step output through $GITHUB_OUTPUT. Values produced by this
 * action are single line paths and integers; a value containing a newline is
 * rejected rather than escaped, because a newline in any of them means
 * upstream corruption.
 *
 * @param {object} env usually process.env
 * @param {string} name
 * @param {string} value
 */
function writeOutput(env, name, value) {
  const text = String(value);
  if (text.includes('\n') || text.includes('\r')) {
    throw new Error(`refusing to write multiline value to step output "${name}"`);
  }
  const target = env.GITHUB_OUTPUT;
  if (target) {
    fs.appendFileSync(target, `${name}=${text}\n`, 'utf8');
  } else {
    info(`output ${name}=${text}`);
  }
}

module.exports = { escapeCommandValue, info, error, notice, writeOutput };
