'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

function unquote(value) {
  if (
    value.length >= 2 &&
    ((value.startsWith("'") && value.endsWith("'")) || (value.startsWith('"') && value.endsWith('"')))
  ) {
    return value.slice(1, -1);
  }
  return value;
}

function readActionDescription() {
  const lines = fs.readFileSync(path.join(__dirname, '..', 'action.yml'), 'utf8').split(/\r?\n/);
  const index = lines.findIndex((line) => line.startsWith('description:'));
  assert.notEqual(index, -1, 'action.yml must declare a description');

  const inline = lines[index].slice('description:'.length).trim();
  if (!/^[>|][+-]?$/.test(inline)) {
    return unquote(inline);
  }

  const block = [];
  for (let i = index + 1; i < lines.length; i += 1) {
    const line = lines[i];
    if (line.trim() !== '' && !/^\s/.test(line)) break;
    if (line.trim() !== '') block.push(line.trim());
  }
  assert.ok(block.length > 0, 'the description block scalar must not be empty');
  return block.join(' ');
}

test('GitHub Marketplace description fits the 125 character limit', () => {
  const description = readActionDescription();
  assert.ok(description.length > 0, 'action description must not be empty');
  assert.ok(!/[\r\n]/.test(description), 'action description must be a single line');
  assert.ok(
    description.length <= 125,
    `action description is ${description.length} characters; GitHub Marketplace allows at most 125`,
  );
});
