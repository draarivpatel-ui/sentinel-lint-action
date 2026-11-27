'use strict';

/**
 * Minimal registry client for fetching npm packument metadata and tarballs
 * over HTTPS with the built-in http stack only. Redirects are followed with
 * a bound, response bodies are capped, and every request has a timeout.
 */

const https = require('node:https');

const REGISTRY_BASE = 'https://registry.npmjs.org';
const MAX_REDIRECTS = 5;
const MAX_BODY_BYTES = 64 * 1024 * 1024;
const REQUEST_TIMEOUT_MS = 30000;

class RegistryError extends Error {
  constructor(message) {
    super(message);
    this.name = 'RegistryError';
  }
}

/**
 * GET a URL and return the raw body as a Buffer, following redirects.
 * @param {string} url
 * @param {number} redirectsLeft
 * @returns {Promise<Buffer>}
 */
function getBuffer(url, redirectsLeft = MAX_REDIRECTS) {
  return new Promise((resolve, reject) => {
    const request = https.get(
      url,
      {
        headers: {
          'user-agent': 'sentinel-lint-action/1.0 (+https://github.com/draarivpatel-ui/sentinel-lint-action)',
          accept: 'application/vnd.npm.install-v1+json, application/json, application/octet-stream',
        },
        timeout: REQUEST_TIMEOUT_MS,
      },
      (response) => {
        const status = response.statusCode || 0;
        if (status >= 300 && status < 400 && response.headers.location) {
          response.resume();
          if (redirectsLeft <= 0) {
            reject(new RegistryError(`too many redirects fetching ${url}`));
            return;
          }
          const target = new URL(response.headers.location, url);
          if (target.protocol !== 'https:') {
            reject(new RegistryError(`refusing non-HTTPS redirect to ${target.protocol}`));
            return;
          }
          getBuffer(target.href, redirectsLeft - 1).then(resolve, reject);
          return;
        }
        if (status !== 200) {
          response.resume();
          reject(new RegistryError(`HTTP ${status} fetching ${url}`));
          return;
        }
        const chunks = [];
        let size = 0;
        response.on('data', (chunk) => {
          size += chunk.length;
          if (size > MAX_BODY_BYTES) {
            request.destroy(new RegistryError(`response body exceeds ${MAX_BODY_BYTES} bytes`));
            return;
          }
          chunks.push(chunk);
        });
        response.on('end', () => resolve(Buffer.concat(chunks)));
        response.on('error', reject);
      },
    );
    request.on('timeout', () => {
      request.destroy(new RegistryError(`request timed out fetching ${url}`));
    });
    request.on('error', reject);
  });
}

/**
 * Fetch the version metadata document for sentinel-lint from the npm
 * registry and return the dist descriptor for the requested version.
 * @param {string} version exact semver, already validated
 * @returns {Promise<{tarball: string, integrity: string, shasum: string}>}
 */
async function fetchDistInfo(version) {
  const body = await getBuffer(`${REGISTRY_BASE}/sentinel-lint/${encodeURIComponent(version)}`);
  let document;
  try {
    document = JSON.parse(body.toString('utf8'));
  } catch {
    throw new RegistryError('the registry response is not valid JSON');
  }
  if (!document.dist || typeof document.dist.tarball !== 'string') {
    throw new RegistryError(`the registry response has no dist.tarball for sentinel-lint@${version}`);
  }
  if (!document.dist.tarball.startsWith('https://')) {
    throw new RegistryError('the tarball URL is not HTTPS');
  }
  return {
    tarball: document.dist.tarball,
    integrity: typeof document.dist.integrity === 'string' ? document.dist.integrity : '',
    shasum: typeof document.dist.shasum === 'string' ? document.dist.shasum : '',
    dependencies: document.dependencies && typeof document.dependencies === 'object'
      ? Object.keys(document.dependencies).length
      : 0,
  };
}

module.exports = { RegistryError, REGISTRY_BASE, getBuffer, fetchDistInfo };
