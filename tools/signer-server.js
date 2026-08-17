'use strict';

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const repoRoot = path.resolve(__dirname, '../..');
const fintechRoot = path.dirname(repoRoot);
const defaultPaymentHtml = path.join(fintechRoot, 'pos-form-main/public/payment.html');
const port = Number(process.env.POSTMAN_SIGNER_PORT || 8787);

function readPrivateKey() {
  if (process.env.LUNIXI_PRIVATE_KEY) return process.env.LUNIXI_PRIVATE_KEY.replace(/\\n/g, '\n');
  if (process.env.LUNIXI_PRIVATE_KEY_PATH) return fs.readFileSync(process.env.LUNIXI_PRIVATE_KEY_PATH, 'utf8');
  const html = fs.existsSync(defaultPaymentHtml) ? fs.readFileSync(defaultPaymentHtml, 'utf8') : '';
  const match = html.match(/LOCAL_TEST_PEM\s*=\s*'([^']+)'/);
  if (match) return match[1].replace(/\\n/g, '\n');
  throw new Error('No private key found. Set LUNIXI_PRIVATE_KEY_PATH or LUNIXI_PRIVATE_KEY.');
}

function signRequest({ method, path: requestPath, body = null, keyId }) {
  if (!keyId) throw new Error('keyId is required.');
  if (!requestPath || !requestPath.startsWith('/')) throw new Error('path must start with /.');

  const privateKey = crypto.createPrivateKey(readPrivateKey());
  const date = new Date().toISOString();
  const nonce = crypto.randomUUID();
  const lines = [
    String(method || 'POST').toUpperCase(),
    requestPath,
    `X-Date:${date}`,
    `X-Nonce:${nonce}`,
  ];
  const headers = {
    'X-Key-Id': keyId,
    'X-Date': date,
    'X-Nonce': nonce,
  };

  if (body !== null && body !== undefined && body !== '') {
    const rawBody = typeof body === 'string' ? body : JSON.stringify(body);
    const digest = `SHA-256=${crypto.createHash('sha256').update(rawBody).digest('base64')}`;
    lines.push(`Digest:${digest}`);
    headers.Digest = digest;
  }

  headers['X-Signature'] = crypto.sign(null, Buffer.from(lines.join('\n')), privateKey).toString('base64');
  return headers;
}

async function mintToken(input) {
  const baseUrl = String(input.baseUrl || '').replace(/\/$/, '');
  const authTokenPath = input.authTokenPath || '/api/v1/auth/token';
  if (!baseUrl) throw new Error('baseUrl is required.');
  const headers = signRequest({
    method: 'POST',
    path: authTokenPath,
    keyId: input.keyId,
  });
  headers.Accept = 'application/json';

  const response = await fetch(baseUrl + authTokenPath, {
    method: 'POST',
    headers,
  });
  const text = await response.text();
  let json;
  try { json = text ? JSON.parse(text) : {}; } catch { json = { message: text }; }

  if (!response.ok) {
    const message = json.message || `Token mint failed with HTTP ${response.status}`;
    const error = new Error(message);
    error.statusCode = response.status;
    error.response = json;
    throw error;
  }

  const data = json.data && typeof json.data === 'object' ? json.data : json;
  const token = data.access_token || data.accessToken || data.token;
  const ttl = Number(data.expires_in || data.expiresIn || 3600);
  if (!token) throw new Error(`Token response did not include an access token: ${text}`);

  return {
    accessToken: token,
    expiresIn: ttl,
    expiresAt: Date.now() + Math.max(1, ttl) * 1000 - 30000,
    rawResponse: json,
  };
}

function send(res, status, body) {
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'content-type',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
  });
  res.end(JSON.stringify(body, null, 2));
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (chunk) => { data += chunk; });
    req.on('end', () => {
      try { resolve(data ? JSON.parse(data) : {}); } catch (error) { reject(error); }
    });
    req.on('error', reject);
  });
}

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === 'OPTIONS') return send(res, 204, {});
    if (req.method === 'GET' && req.url === '/health') {
      const publicKey = crypto.createPublicKey(crypto.createPrivateKey(readPrivateKey()))
        .export({ type: 'spki', format: 'der' });
      return send(res, 200, {
        ok: true,
        publicKeyFingerprint: crypto.createHash('sha256').update(publicKey).digest('hex').slice(0, 16),
      });
    }
    if (req.method === 'POST' && req.url === '/sign') {
      return send(res, 200, { headers: signRequest(await readJson(req)) });
    }
    if (req.method === 'POST' && req.url === '/token') {
      return send(res, 200, await mintToken(await readJson(req)));
    }
    return send(res, 404, { ok: false, message: 'Not found' });
  } catch (error) {
    return send(res, error.statusCode || 500, {
      ok: false,
      message: error.message,
      response: error.response,
    });
  }
});

server.listen(port, '127.0.0.1', () => {
  console.log(`Lunixi Postman signer listening on http://127.0.0.1:${port}`);
  console.log(`Default key source: ${defaultPaymentHtml}`);
});

