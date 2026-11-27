'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs');

const { UntarError, extractTar, safeSegments } = require('../src/untar.cjs');
const { verifyIntegrity } = require('../src/install.cjs');
const { createHash } = require('node:crypto');

/**
 * Build a ustar header block for tests.
 */
function headerBlock(name, size, typeByte, prefix) {
  const header = Buffer.alloc(512);
  header.write(name.slice(0, 100), 0, 'utf8');
  header.write('0000644\0', 100, 'utf8');
  header.write('0000000\0', 108, 'utf8');
  header.write('0000000\0', 116, 'utf8');
  header.write(size.toString(8).padStart(11, '0') + '\0', 124, 'utf8');
  header.write('00000000000\0', 136, 'utf8');
  header.write('        ', 148, 'utf8');
  header.write(String.fromCharCode(typeByte), 156, 'utf8');
  header.write('ustar\0', 257, 'utf8');
  header.write('00', 263, 'utf8');
  if (prefix) header.write(prefix, 345, 'utf8');
  // checksum: sum of all bytes with the checksum field as spaces
  let sum = 0;
  for (const byte of header) sum += byte;
  header.write(sum.toString(8).padStart(6, '0') + '\0 ', 148, 'utf8');
  return header;
}

function fileEntry(name, content, typeByte = 0x30) {
  const body = Buffer.from(content, 'utf8');
  const header = headerBlock(name, body.length, typeByte);
  const padded = Buffer.alloc(Math.ceil(body.length / 512) * 512);
  body.copy(padded);
  return Buffer.concat([header, padded]);
}

function endBlocks() {
  return Buffer.alloc(1024);
}

function makeTarget() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'sla-untar-'));
}

test('a simple archive extracts files and directories', () => {
  const target = makeTarget();
  try {
    const tar = Buffer.concat([
      fileEntry('package/index.mjs', 'export const x = 1;\n'),
      fileEntry('package/lib/util.mjs', 'export const y = 2;\n'),
      endBlocks(),
    ]);
    const result = extractTar(tar, target);
    assert.equal(result.files, 2);
    assert.equal(
      fs.readFileSync(path.join(target, 'package', 'index.mjs'), 'utf8'),
      'export const x = 1;\n',
    );
    assert.equal(
      fs.readFileSync(path.join(target, 'package', 'lib', 'util.mjs'), 'utf8'),
      'export const y = 2;\n',
    );
  } finally {
    fs.rmSync(target, { recursive: true, force: true });
  }
});

test('path segments validation rejects traversal and absolute paths', () => {
  assert.throws(() => safeSegments('../evil'), UntarError);
  assert.throws(() => safeSegments('a/../../evil'), UntarError);
  assert.throws(() => safeSegments('/etc/passwd'), UntarError);
  assert.throws(() => safeSegments('C:/evil'), UntarError);
  assert.throws(() => safeSegments('a\\b'), UntarError);
  assert.deepEqual(safeSegments('package/src/index.mjs'), ['package', 'src', 'index.mjs']);
  assert.deepEqual(safeSegments('./package/x.mjs'), ['package', 'x.mjs']);
});

test('archives with traversal entries are rejected before writing', () => {
  const target = makeTarget();
  try {
    const tar = Buffer.concat([fileEntry('package/../../evil.mjs', 'evil'), endBlocks()]);
    assert.throws(() => extractTar(tar, target), UntarError);
    assert.ok(!fs.existsSync(path.join(target, '..', 'evil.mjs')));
  } finally {
    fs.rmSync(target, { recursive: true, force: true });
  }
});

test('symlink and hardlink entries are rejected', () => {
  const target = makeTarget();
  try {
    for (const typeByte of [0x31, 0x32]) {
      const tar = Buffer.concat([fileEntry('package/link', 'target', typeByte), endBlocks()]);
      assert.throws(() => extractTar(tar, target), UntarError, `typebyte ${typeByte} must be rejected`);
    }
  } finally {
    fs.rmSync(target, { recursive: true, force: true });
  }
});

test('device and fifo entries are rejected', () => {
  const target = makeTarget();
  try {
    for (const typeByte of [0x33, 0x34, 0x36]) {
      const tar = Buffer.concat([fileEntry('package/dev', '', typeByte), endBlocks()]);
      assert.throws(() => extractTar(tar, target), UntarError);
    }
  } finally {
    fs.rmSync(target, { recursive: true, force: true });
  }
});

test('pax extended headers apply long paths to the next entry', () => {
  const target = makeTarget();
  try {
    const longName = `package/${'deep/'.repeat(30)}file.mjs`;
    // pax record length covers the digits themselves, the space, the
    // key=value text and the trailing newline; compute the fixed point.
    const base = `path=${longName}\n`;
    let len = base.length + 2;
    while (String(len).length + 1 + base.length !== len) {
      len = String(len).length + 1 + base.length;
    }
    const paxContent = `${len} ${base}`;
    const paxHeader = headerBlock('PaxHeaders.0/x', Buffer.byteLength(paxContent), 0x78);
    const paxBody = Buffer.alloc(Math.ceil(Buffer.byteLength(paxContent) / 512) * 512);
    paxBody.write(paxContent, 0, 'utf8');
    const tar = Buffer.concat([
      paxHeader,
      paxBody,
      fileEntry('package/short', 'content'),
      endBlocks(),
    ]);
    extractTar(tar, target);
    const extracted = path.join(target, 'package', ...'deep/'.repeat(30).split('/').filter(Boolean), 'file.mjs');
    assert.ok(fs.existsSync(extracted), 'the pax long path must be applied to the following entry');
  } finally {
    fs.rmSync(target, { recursive: true, force: true });
  }
});

test('truncated archives are rejected', () => {
  const target = makeTarget();
  try {
    // 700 bytes of content occupy 1024 padded bytes after the 512 byte
    // header; cutting the archive at byte 600 removes real file content.
    const tar = fileEntry('package/index.mjs', 'x'.repeat(700));
    assert.throws(() => extractTar(tar.subarray(0, 600), target), UntarError);
    const headerOnly = headerBlock('package/index.mjs', 700, 0x30);
    assert.throws(() => extractTar(headerOnly, target), UntarError);
  } finally {
    fs.rmSync(target, { recursive: true, force: true });
  }
});

test('non-ustar magic is rejected', () => {
  const target = makeTarget();
  try {
    const entry = fileEntry('package/index.mjs', 'x');
    entry.write('notust', 257, 'utf8');
    assert.throws(() => extractTar(Buffer.concat([entry, endBlocks()]), target), UntarError);
  } finally {
    fs.rmSync(target, { recursive: true, force: true });
  }
});

test('integrity verification accepts matching sha512 and rejects mismatch', () => {
  const data = Buffer.from('tarball bytes');
  const sri = `sha512-${createHash('sha512').update(data).digest('base64')}`;
  assert.doesNotThrow(() => verifyIntegrity(data, sri, ''));
  assert.throws(() => verifyIntegrity(Buffer.from('tampered'), sri, ''), /integrity mismatch/);
});

test('integrity verification falls back to sha1 hex and fails closed when empty', () => {
  const data = Buffer.from('tarball bytes');
  const sha1 = createHash('sha1').update(data).digest('hex');
  assert.doesNotThrow(() => verifyIntegrity(data, '', sha1));
  assert.throws(() => verifyIntegrity(data, '', ''), /refusing to install/);
  assert.throws(() => verifyIntegrity(Buffer.from('tampered'), '', sha1));
});

test('sri with unsupported algorithm is rejected', () => {
  const data = Buffer.from('x');
  assert.throws(() => verifyIntegrity(data, 'md5-aaaa', ''));
});
