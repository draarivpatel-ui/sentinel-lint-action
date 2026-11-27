'use strict';

/**
 * Minimal, defensive ustar/pax tar extractor in pure zero-dependency Node.js.
 *
 * Only regular files and directories are extracted. Hard links, symlinks,
 * device nodes, fifos and every other typeflag are rejected outright. Entry
 * paths are validated segment by segment: absolute paths, drive letters,
 * dot-dot traversal and NUL bytes never reach the filesystem. Sizes are
 * capped per file, per entry count and in total.
 */

const fs = require('node:fs');
const path = require('node:path');

const BLOCK = 512;
const MAX_FILE_BYTES = 64 * 1024 * 1024;
const MAX_TOTAL_BYTES = 256 * 1024 * 1024;
const MAX_ENTRIES = 100000;

const TYPE_FILE = 0x30; // '0'; a NUL byte (0x00) also means a regular file
const TYPE_FILE_NUL = 0x00;
const TYPE_DIRECTORY = 0x35; // '5'
const TYPE_PAX = 0x78; // 'x'
const TYPE_PAX_GLOBAL = 0x67; // 'g'
const TYPE_GNU_LONGNAME = 0x4c; // 'L'
const TYPE_GNU_LONGLINK = 0x4b; // 'K'

class UntarError extends Error {
  constructor(message) {
    super(message);
    this.name = 'UntarError';
  }
}

function readNullTerminated(buffer, start, length) {
  const slice = buffer.subarray(start, start + length);
  const end = slice.indexOf(0);
  return slice.subarray(0, end === -1 ? slice.length : end).toString('utf8');
}

function parseOctal(buffer, start, length) {
  const raw = readNullTerminated(buffer, start, length).trim();
  if (raw === '') return 0;
  if (!/^[0-7]+$/.test(raw)) {
    throw new UntarError('tar header contains a non-octal numeric field');
  }
  return parseInt(raw, 8);
}

/**
 * Parse pax extended header records of the form `<len> <key>=<value>\n`.
 * @param {Buffer} content
 * @returns {Map<string, string>}
 */
function parsePax(content) {
  const records = new Map();
  let offset = 0;
  const text = content.toString('utf8');
  while (offset < text.length) {
    const space = text.indexOf(' ', offset);
    if (space === -1) break;
    const length = Number(text.slice(offset, space));
    if (!Number.isInteger(length) || length <= 0) break;
    const record = text.slice(space + 1, offset + length - 1);
    const equals = record.indexOf('=');
    if (equals > 0) {
      records.set(record.slice(0, equals), record.slice(equals + 1));
    }
    offset += length;
  }
  return records;
}

/**
 * Validate an archive entry path and return a clean list of segments.
 * @param {string} entryPath
 * @returns {string[]}
 */
function safeSegments(entryPath) {
  if (entryPath.includes('\u0000')) throw new UntarError('tar entry path contains a NUL byte');
  if (entryPath.startsWith('/')) throw new UntarError(`tar entry path is absolute: ${entryPath}`);
  if (/^[A-Za-z]:/.test(entryPath)) throw new UntarError(`tar entry path has a drive letter: ${entryPath}`);
  if (entryPath.includes('\\')) throw new UntarError(`tar entry path contains a backslash: ${entryPath}`);
  const segments = entryPath.split('/').filter((segment) => segment !== '' && segment !== '.');
  if (segments.length === 0) throw new UntarError('tar entry path is empty');
  if (segments.includes('..')) throw new UntarError(`tar entry path traverses upward: ${entryPath}`);
  return segments;
}

/**
 * Extract a tar archive buffer into a target directory.
 * @param {Buffer} tarBuffer uncompressed tar archive
 * @param {string} targetDir directory created or reused for the extraction
 * @returns {{files: number, directories: number, bytes: number}}
 */
function extractTar(tarBuffer, targetDir) {
  if (!Buffer.isBuffer(tarBuffer) || tarBuffer.length < BLOCK) {
    throw new UntarError('the archive is too small to be a tar file');
  }

  let offset = 0;
  let files = 0;
  let directories = 0;
  let bytes = 0;
  let entries = 0;
  let pendingName = null;
  let zeroBlocks = 0;

  while (offset + BLOCK <= tarBuffer.length) {
    const header = tarBuffer.subarray(offset, offset + BLOCK);
    if (header.every((byte) => byte === 0)) {
      zeroBlocks += 1;
      offset += BLOCK;
      if (zeroBlocks >= 2) break;
      continue;
    }
    zeroBlocks = 0;

    const magic = readNullTerminated(header, 257, 6);
    if (magic !== 'ustar') {
      throw new UntarError(`unsupported tar magic "${magic}"; only posix ustar archives are supported`);
    }

    entries += 1;
    if (entries > MAX_ENTRIES) throw new UntarError('tar entry count cap exceeded');

    const typeByte = header[156];
    const size = parseOctal(header, 124, 12);
    let name = readNullTerminated(header, 0, 100);
    const prefix = readNullTerminated(header, 345, 155);
    if (prefix !== '') name = `${prefix}/${name}`;

    const contentStart = offset + BLOCK;
    const contentEnd = contentStart + size;
    if (contentEnd > tarBuffer.length) {
      throw new UntarError('tar archive is truncated inside an entry');
    }
    const content = tarBuffer.subarray(contentStart, contentEnd);
    offset = contentStart + Math.ceil(size / BLOCK) * BLOCK;

    if (typeByte === TYPE_PAX) {
      const pax = parsePax(content);
      if (pax.has('path')) pendingName = pax.get('path');
      continue;
    }
    if (typeByte === TYPE_PAX_GLOBAL) {
      continue;
    }
    if (typeByte === TYPE_GNU_LONGNAME) {
      pendingName = content.toString('utf8').replace(/\0+$/, '');
      continue;
    }
    if (typeByte === TYPE_GNU_LONGLINK) {
      throw new UntarError('gnu longlink entries are not supported because links are rejected');
    }

    if (pendingName !== null) {
      name = pendingName;
      pendingName = null;
    }

    if (typeByte === TYPE_DIRECTORY) {
      const segments = safeSegments(name.replace(/\/+$/, ''));
      fs.mkdirSync(path.join(targetDir, ...segments), { recursive: true });
      directories += 1;
      continue;
    }

    if (typeByte === TYPE_FILE || typeByte === TYPE_FILE_NUL) {
      if (size > MAX_FILE_BYTES) throw new UntarError(`tar entry exceeds the per-file cap: ${name}`);
      bytes += size;
      if (bytes > MAX_TOTAL_BYTES) throw new UntarError('tar archive exceeds the total size cap');
      const segments = safeSegments(name);
      const destination = path.join(targetDir, ...segments);
      const resolvedTarget = path.resolve(targetDir);
      const resolvedDestination = path.resolve(destination);
      if (resolvedDestination !== resolvedTarget && !resolvedDestination.startsWith(resolvedTarget + path.sep)) {
        throw new UntarError(`tar entry escapes the extraction directory: ${name}`);
      }
      fs.mkdirSync(path.dirname(destination), { recursive: true });
      fs.writeFileSync(destination, content);
      files += 1;
      continue;
    }

    throw new UntarError(
      `tar entry "${name}" has typeflag byte 0x${typeByte.toString(16)}; only regular files and directories are extracted`,
    );
  }

  if (files === 0 && directories === 0) {
    throw new UntarError('the archive contained no extractable entries');
  }
  return { files, directories, bytes };
}

module.exports = { UntarError, extractTar, safeSegments, parsePax };
