'use strict';

/*
 * Signing lock for the payment Postman collections and the fraud event-ingest requests.
 *
 * The pre-request scripts are run in a stand-in for the Postman sandbox, then the
 * request is encoded the way Postman encodes a URL before sending (postman-url-encoder)
 * and sent to a local server that verifies it the way the
 * gateway's SignatureGuard does (nest-payment-gateway,
 * apps/api-gateway/src/auth/guards/signature.guard.ts):
 *   - canonical string: METHOD, received request target (path + query), X-Date, X-Nonce,
 *     and Digest when the header is present;
 *   - Digest: SHA-256 over JSON.stringify of the PARSED body, not over the bytes sent.
 * The test scripts run after each response, as in newman, so a pair that signs in one
 * request and sends in the next (the fraud local-signer profile) is exercised too.
 *
 * Run: cd postman && node --test
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const net = require('node:net');
const path = require('node:path');
const { spawn } = require('node:child_process');

const POSTMAN_DIR = path.resolve(__dirname, '..');
const COLLECTIONS = {
  standalone: 'standalone/Lunixi-Payment-Gateway.standalone.postman_collection.json',
  'local-signer': 'local-signer/Lunixi-Payment-Gateway.local-signer.postman_collection.json',
  'fraud-standalone': 'fraud/standalone/Lunixi-Fraud.standalone.postman_collection.json',
  'fraud-local-signer': 'fraud/local-signer/Lunixi-Fraud.local-signer.postman_collection.json',
};
const KEY_ID = 'mk_test_sk_postman_lock';
const STEP_UP_TARGETS = [/\/payments\/intents$/, /\/payments\/direct\/2d$/, /\/payments\/direct\/3d$/, /\/payments\/[^/]+\/capture$/];
// Headers that authenticate a gateway request. Not one of them may reach the storage host.
const GATEWAY_CREDENTIAL_HEADERS = ['authorization', 'x-key-id', 'x-date', 'x-nonce', 'x-signature', 'digest'];
// Stands in for the file a user selects under Body → binary (a PNG signature and IHDR start).
const SELECTED_FILE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52]);

// Names the Postman sandbox passes to every script as function parameters
// (postman-sandbox LEGACY_GLOBS plus the pm scope). A top-level `const data` (or any
// of these) is a SyntaxError there and the whole script silently never runs.
const SANDBOX_GLOBALS = [
  'tests', 'globals', 'environment', 'data', 'request', 'responseCookies', 'responseHeaders', 'responseTime',
  'responseCode', 'responseBody', 'iteration', 'postman', '_', 'CryptoJS', 'atob', 'btoa', 'tv4', 'xml2Json',
  'Backbone', 'cheerio', 'pm', 'console', 'Buffer', 'setTimeout', 'setInterval', 'setImmediate',
  'clearTimeout', 'clearInterval', 'clearImmediate',
];

function loadCollection(name) {
  return JSON.parse(fs.readFileSync(path.join(POSTMAN_DIR, COLLECTIONS[name]), 'utf8'));
}

function scriptOf(node, listen) {
  const event = (node.event || []).find((e) => e.listen === listen);
  return event ? event.script.exec.join('\n') : null;
}

function requestItems(items, trail = []) {
  return items.flatMap((item) => (item.item
    ? requestItems(item.item, [...trail, item])
    : [{ item, trail }]));
}

// --- Sandbox stand-in ---------------------------------------------------------------

function wordArray(buffer) {
  const words = [];
  for (let i = 0; i < buffer.length; i++) words[i >>> 2] |= buffer[i] << (24 - (i % 4) * 8);
  return { words, sigBytes: buffer.length };
}
const Base64Encoder = { parse: (value) => wordArray(Buffer.from(value, 'base64')) };
const CryptoJS = {
  enc: { Base64: Base64Encoder, Utf8: { parse: (value) => wordArray(Buffer.from(value, 'utf8')) } },
  SHA256(value) {
    const digest = crypto.createHash('sha256').update(String(value), 'utf8').digest();
    return {
      toString(encoder) {
        assert.equal(encoder, Base64Encoder, 'stand-in only implements Base64 digests');
        return digest.toString('base64');
      },
    };
  },
};

function createEnvironment(values) {
  const store = new Map(Object.entries(values));
  const replaceIn = (text) => {
    let current = String(text);
    for (let depth = 0; depth < 10; depth++) {
      const next = current.replace(/\{\{([^{}]+)\}\}/g, (token, name) => {
        if (name === '$guid') return crypto.randomUUID();
        if (name === '$timestamp') return String(Math.floor(Date.now() / 1000));
        return store.has(name) ? String(store.get(name)) : token;
      });
      if (next === current) return current;
      current = next;
    }
    return current;
  };
  return { store, replaceIn };
}

function createRequest(item) {
  const source = item.request;
  let url = typeof source.url === 'string' ? source.url : source.url.raw;
  const headers = (source.header || []).map((h) => ({ key: h.key, value: h.value }));
  const find = (name) => headers.find((h) => h.key.toLowerCase() === String(name).toLowerCase());
  const body = source.body ? { mode: source.body.mode, raw: source.body.raw, options: source.body.options } : undefined;
  if (body) body.update = (next) => Object.assign(body, { mode: next.mode, raw: next.raw, options: next.options });
  return {
    name: item.name,
    method: source.method,
    auth: source.auth,
    headers,
    body,
    get url() { return url; },
    pm: {
      method: source.method,
      url: {
        toString: () => url,
        update: (next) => { url = String(next); },
        // Url#getPath: no host and no query; {{variables}} are left unresolved.
        getPath: () => '/' + url.replace(/^([a-z][a-z0-9+.-]*:\/\/)?[^/?#]*\/?/i, '').split(/[?#]/)[0],
      },
      headers: {
        get: (name) => (find(name) ? find(name).value : undefined),
        upsert: ({ key, value }) => { const h = find(key); if (h) h.value = value; else headers.push({ key, value }); },
      },
      body,
    },
  };
}

function httpSend({ method, url, headers, body }) {
  return new Promise((resolve, reject) => {
    const target = new URL(url);
    const request = http.request({
      host: target.hostname,
      port: target.port,
      method,
      // Sent verbatim: the stand-in has already encoded the target like Postman does.
      path: url.slice(url.indexOf('/', url.indexOf('//') + 2)),
      headers,
    }, (response) => {
      let text = '';
      response.setEncoding('utf8');
      response.on('data', (chunk) => { text += chunk; });
      response.on('end', () => resolve({
        code: response.statusCode,
        headers: { get: (name) => response.headers[String(name).toLowerCase()] },
        text: () => text,
        json: () => JSON.parse(text),
      }));
    });
    request.on('error', reject);
    if (body) request.write(body);
    request.end();
  });
}

function toHeaderObject(header) {
  if (!Array.isArray(header)) return header || {};
  return Object.fromEntries(header.map((h) => [h.key, h.value]));
}

// The chai surface the scripts use. Any other property throws, so an assertion the
// stand-in does not know fails its pm.test instead of passing silently.
function expectation(actual, message) {
  let negated = false;
  const check = (passed, expected) => {
    if (passed === negated) {
      throw new assert.AssertionError({ message: message || `expected ${JSON.stringify(actual)} ${negated ? 'not ' : ''}${expected}` });
    }
    return chain;
  };
  const words = {
    to: () => chain,
    be: () => chain,
    and: () => chain,
    not: () => { negated = !negated; return chain; },
    empty: () => {
      if (actual === null || actual === undefined) throw new TypeError(`.empty was passed ${actual}`);
      return check(Object.keys(actual).length === 0, 'to be empty');
    },
  };
  const methods = {
    a: (type) => check(typeof actual === type, `to be a ${type}`),
    below: (limit) => check(actual < limit, `to be below ${limit}`),
    equal: (value) => check(actual === value, `to equal ${JSON.stringify(value)}`),
    oneOf: (list) => check(list.includes(actual), `to be one of ${JSON.stringify(list)}`),
    within: (low, high) => check(actual >= low && actual <= high, `to be within ${low}..${high}`),
  };
  const chain = new Proxy({}, {
    get(target, key) {
      if (Object.hasOwn(words, key)) return words[key]();
      if (Object.hasOwn(methods, key)) return methods[key];
      throw new TypeError(`stand-in pm.expect has no .${String(key)}`);
    },
  });
  return chain;
}

// `require` is not a script parameter in the sandbox (uniscope ignores it); it comes
// from the enclosing scope. Only the built-in module the collections use is provided.
function sandboxRequire(name) {
  if (name === 'uuid') return { v4: () => crypto.randomUUID() };
  throw new Error(`stand-in sandbox has no module '${name}'`);
}

async function runScript(code, request, environment, response) {
  const pending = [];
  const tests = [];
  const pm = {
    info: { requestName: request.name },
    environment: { get: (k) => environment.store.get(k), set: (k, v) => environment.store.set(k, v) },
    variables: { replaceIn: environment.replaceIn },
    request: request.pm,
    response: response && {
      ...response,
      to: { have: { status: (code) => expectation(response.code, `expected response to have status code ${code} but got ${response.code}`).to.equal(code) } },
    },
    test(name, assertion) {
      try {
        assertion();
        tests.push({ name, error: null });
      } catch (error) {
        tests.push({ name, error: error.message });
      }
    },
    expect: expectation,
    sendRequest(options, callback) {
      const body = options.body && options.body.raw;
      pending.push(httpSend({ method: options.method, url: options.url, headers: toHeaderObject(options.header), body })
        .then((reply) => callback(null, reply), (error) => callback(error)));
    },
  };
  const values = { pm, CryptoJS, console, Buffer, btoa: (binary) => Buffer.from(binary, 'latin1').toString('base64') };
  // eslint-disable-next-line no-new-func
  const script = new Function('require', `return function (${SANDBOX_GLOBALS.join(', ')}) {;var arguments = undefined;\n${code}\n;};`)(sandboxRequire);
  script(...SANDBOX_GLOBALS.map((name) => values[name]));
  while (pending.length) await pending.shift();
  return tests;
}

// postman-url-encoder: what Postman does to the URL right before sending it. Existing
// %XX escapes are kept; C0 controls, DEL and non-ASCII bytes are always encoded.
function postmanEncode(value, extra) {
  const bytes = Buffer.from(value, 'utf8');
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    const escaped = bytes[i] === 0x25 && /^[0-9A-Fa-f]{2}$/.test(bytes.subarray(i + 1, i + 3).toString('latin1'));
    if (escaped) { out += bytes.subarray(i, i + 3).toString('latin1'); i += 2; continue; }
    const ch = String.fromCharCode(bytes[i]);
    const encode = bytes[i] < 0x20 || bytes[i] >= 0x7f || extra.includes(ch);
    out += encode ? '%' + bytes[i].toString(16).toUpperCase().padStart(2, '0') : ch;
  }
  return out;
}
function postmanWireTarget(target) {
  const queryAt = target.indexOf('?');
  const pathPart = postmanEncode(queryAt === -1 ? target : target.slice(0, queryAt), [' ', '"', '#', '<', '>', '`', '?', '{', '}']);
  if (queryAt === -1) return pathPart;
  const query = target.slice(queryAt + 1).split('&').map((param) => {
    const eq = param.indexOf('=');
    const queryChars = [' ', '"', '#', "'", '<', '>'];
    if (eq === -1) return postmanEncode(param, [...queryChars, '&', '=']);
    return postmanEncode(param.slice(0, eq), [...queryChars, '&', '=']) + '=' + postmanEncode(param.slice(eq + 1), [...queryChars, '&']);
  }).join('&');
  return pathPart + '?' + query;
}

// Resolve what is still unresolved, apply collection auth, encode like Postman, send.
async function sendPrepared(request, environment, collectionAuth) {
  const resolved = environment.replaceIn(request.url);
  const origin = /^[a-z][a-z0-9+.-]*:\/\/[^/?#]*/i.exec(resolved)[0];
  const headers = Object.fromEntries(request.headers.map((h) => [h.key, environment.replaceIn(h.value)]));
  const auth = request.auth || collectionAuth;
  if (auth && auth.type === 'bearer') headers.Authorization = 'Bearer ' + environment.replaceIn(auth.bearer[0].value);
  let body;
  if (request.body && request.body.mode === 'file') body = SELECTED_FILE;
  else if (request.body && request.body.raw) body = environment.replaceIn(request.body.raw);
  return httpSend({ method: request.method, url: origin + postmanWireTarget(resolved.slice(origin.length)), headers, body });
}

// --- Gateway stand-in -----------------------------------------------------------------

function verifyLikeSignatureGuard(req, raw, publicKey, nonces) {
  const h = req.headers;
  if (!h['x-key-id'] || !h['x-date'] || !h['x-nonce'] || !h['x-signature']) return 'AUTH_HEADERS_MISSING';
  const requestTime = new Date(h['x-date']).getTime();
  if (Number.isNaN(requestTime) || Math.abs(Date.now() - requestTime) > 300000) return 'INVALID_DATE';
  if (nonces.has(`${h['x-key-id']}:${h['x-nonce']}`)) return 'NONCE_REPLAY';
  if (h['x-key-id'] !== KEY_ID) return 'INVALID_KID';
  // express.json(): only a JSON content type is parsed into req.body.
  const body = raw && /application\/json/i.test(h['content-type'] || '') ? JSON.parse(raw) : undefined;
  if (body && Object.keys(body).length > 0) {
    if (!h.digest) return 'DIGEST_MISSING';
    const expected = crypto.createHash('sha256').update(JSON.stringify(body)).digest('base64');
    if (h.digest.trim() !== 'SHA-256=' + expected) return 'INVALID_DIGEST';
  }
  const canonical = [req.method.toUpperCase(), req.url, `X-Date:${h['x-date']}`, `X-Nonce:${h['x-nonce']}`];
  if (h.digest) canonical.push(`Digest:${h.digest}`);
  const valid = crypto.verify(null, Buffer.from(canonical.join('\n'), 'utf8'), publicKey, Buffer.from(h['x-signature'], 'base64'));
  if (!valid) return 'INVALID_SIGNATURE';
  nonces.add(`${h['x-key-id']}:${h['x-nonce']}`);
  return 'OK';
}

async function startGateway(publicKey, storageUrl) {
  const nonces = new Set();
  const received = [];
  const issuedTokens = new Set();
  const issuedUploads = [];
  const walletIssued = [];
  const server = http.createServer((req, res) => {
    let raw = '';
    req.setEncoding('utf8');
    req.on('data', (chunk) => { raw += chunk; });
    req.on('end', () => {
      const verdict = verifyLikeSignatureGuard(req, raw, publicKey, nonces);
      const reply = (status, payload) => { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(payload)); };
      if (req.method === 'POST' && req.url === '/api/v1/auth/token') {
        if (verdict !== 'OK') return reply(401, { code: verdict });
        const token = 'at_test_' + crypto.randomUUID();
        issuedTokens.add(token);
        return reply(200, { data: { access_token: token, expires_in: 3600 } });
      }
      const bearer = issuedTokens.has(String(req.headers.authorization || '').replace(/^Bearer /, ''));
      received.push({ method: req.method, url: req.url, raw, verdict, bearer, idempotencyKey: req.headers['idempotency-key'] });
      if (verdict !== 'OK') return reply(401, { code: verdict, data: {} });
      // Link images (contract §3.2): the upload target is a presigned URL on the storage stand-in.
      if (req.method === 'POST' && req.url === '/api/v1/payments/links/images') {
        const assetId = crypto.randomUUID();
        const upload = {
          assetId,
          uploadUrl: `${storageUrl}/lunixi-media/org_lock/general/${assetId}.png`
            + `?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-SignedHeaders=content-type%3Bhost&X-Amz-Signature=${'ab'.repeat(32)}`,
          uploadMethod: 'PUT',
          uploadHeaders: { 'Content-Type': JSON.parse(raw).contentType },
          expiresAt: new Date(Date.now() + 900000).toISOString(),
        };
        issuedUploads.push(upload);
        return reply(201, { data: upload });
      }
      const confirm = /^\/api\/v1\/payments\/links\/images\/([^/?]+)\/confirm$/.exec(req.url);
      if (req.method === 'POST' && confirm) {
        return reply(200, { data: { assetId: confirm[1], url: `https://cdn.lunixi.com/assets/${confirm[1]}`, state: 'PUBLISHED' } });
      }
      if (req.url.startsWith('/api/v1/wallet/')) {
        const answer = walletReply(req.method, req.url.split('?')[0].slice('/api/v1/wallet'.length), walletIssued);
        if (answer && answer.svg) {
          res.writeHead(200, { 'Content-Type': 'image/svg+xml' });
          return res.end(answer.svg);
        }
        if (answer) return reply(answer.status, { status: 'success', code: 'OK', message: 'OK', data: answer.data, requestId: 'req_lock' });
      }
      return reply(200, { code: verdict, data: {} });
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return { url: `http://127.0.0.1:${server.address().port}`, received, issuedUploads, walletIssued, close: () => new Promise((r) => server.close(r)) };
}

// Wallet answers (contract: gateway wallet.service views, under the envelope's `data`)
// for the routes whose ids the Wallet folder chains. Two-step operations get fresh ids
// so a complete that reuses a stale or another flow's operation is caught.
const WALLET_IDS = {
  program: '10000000-0000-4000-8000-000000000001',
  endUser: '10000000-0000-4000-8000-000000000002',
  wallet: '10000000-0000-4000-8000-000000000003',
  account: '10000000-0000-4000-8000-000000000004',
  secondWallet: '10000000-0000-4000-8000-000000000005',
  corporate: '10000000-0000-4000-8000-000000000006',
  topup: '10000000-0000-4000-8000-000000000007',
  payment: '10000000-0000-4000-8000-000000000008',
  qr: '10000000-0000-4000-8000-000000000009',
  batch: '10000000-0000-4000-8000-00000000000a',
  walletNo: '5810763412',
  depositReference: 'LNX7Q2M9K4',
  depositIban: 'TR120006200000000006296219',
  qrPayload: 'LNX1|P2P_DYNAMIC|TRY|7500|sig',
};
// Values a user has before running the folder. The chained ones differ from what the
// stand-in answers, so a request that does not pick up the chained value is caught.
const WALLET_ENVIRONMENT = {
  wallet_program_id: '',
  wallet_phone: '+905320000001',
  wallet_external_customer_id: 'postman-customer-001',
  wallet_end_user_id: '20000000-0000-4000-8000-000000000002',
  wallet_id: '20000000-0000-4000-8000-000000000003',
  wallet_no: '5810760000',
  wallet_account_id: '20000000-0000-4000-8000-000000000004',
  wallet_destination_wallet_no: '5810769999',
  wallet_business_end_user_id: '20000000-0000-4000-8000-00000000000b',
  wallet_iban: 'TR330006100519786457841326',
  wallet_beneficiary_name: 'AYSE YILMAZ',
  wallet_rail_id: 'test-rail',
  wallet_deposit_reference: 'stale-reference',
  wallet_deposit_iban: '',
  wallet_corporate_account_id: '20000000-0000-4000-8000-000000000006',
  wallet_employee_external_id: 'postman-employee-001',
  wallet_operation_id: '20000000-0000-4000-8000-000000000010',
  wallet_integrity_hash: 'f'.repeat(64),
  wallet_nonce: 'e'.repeat(64),
  wallet_topup_operation_id: '20000000-0000-4000-8000-000000000007',
  wallet_agent_id: '20000000-0000-4000-8000-00000000000c',
  wallet_payment_operation_id: '20000000-0000-4000-8000-000000000008',
  wallet_payment_code: '483920',
  wallet_qr_id: '20000000-0000-4000-8000-000000000009',
  wallet_qr_payload: 'stale-payload',
  wallet_bulk_batch_id: '20000000-0000-4000-8000-00000000000a',
};
function walletReply(method, route, issued) {
  const twoStep = (label, idField) => {
    const step = { route: label, id: crypto.randomUUID(), integrityHash: crypto.randomBytes(32).toString('hex'), nonce: crypto.randomBytes(32).toString('hex') };
    issued.push(step);
    return { status: 201, data: { [idField]: step.id, status: 'INITIALIZED', otpRequired: false, integrityHash: step.integrityHash, nonce: step.nonce } };
  };
  const key = `${method} ${route}`;
  if (key === 'GET /programs/me') return { status: 200, data: { items: [{ id: WALLET_IDS.program, name: 'Lock program' }], nextCursor: null } };
  if (key === 'POST /end-users') {
    return { status: 201, data: {
      endUser: { id: WALLET_IDS.endUser, programId: WALLET_IDS.program, accountType: 'PERSONAL' },
      defaultWallet: { id: WALLET_IDS.wallet, endUserId: WALLET_IDS.endUser, walletNo: WALLET_IDS.walletNo, isDefault: true,
        accounts: [{ id: crypto.randomUUID(), walletId: WALLET_IDS.wallet, currency: 'EUR' }, { id: WALLET_IDS.account, walletId: WALLET_IDS.wallet, currency: 'TRY' }] },
    } };
  }
  if (/^POST \/end-users\/[^/]+\/wallets$/.test(key)) return { status: 201, data: { id: WALLET_IDS.secondWallet, endUserId: WALLET_IDS.endUser, walletNo: '5810763499', accounts: [] } };
  if (/^POST \/end-users\/[^/]+\/deposit-instructions$/.test(key)) {
    return { status: 201, data: { instruction: { id: crypto.randomUUID(), referenceCode: WALLET_IDS.depositReference, sharedIban: WALLET_IDS.depositIban, assignedIban: null } } };
  }
  if (key === 'POST /corporate-accounts') return { status: 201, data: { corporateAccount: { id: WALLET_IDS.corporate, code: 'PM1' } } };
  if (key === 'POST /transfers/w2w' || key === 'POST /transfers/w2iban' || key === 'POST /withdrawals/bank') return twoStep(key, 'operationId');
  if (key === 'POST /payments/buy') return twoStep(key, 'requestId');
  // A top-up answers the card payment's id too: it must not land in payment_id.
  if (key === 'POST /topups/card') return { status: 201, data: { operationId: WALLET_IDS.topup, paymentId: 'pay_card_topup', status: 'BANK_PROCESSING', token: 'tok_not_a_checkout' } };
  if (key === 'POST /qr') return { status: 201, data: { id: WALLET_IDS.qr, qrType: 'P2P_DYNAMIC', payload: WALLET_IDS.qrPayload } };
  if (key === 'POST /bulk-payouts') return { status: 201, data: { batch: { id: WALLET_IDS.batch, status: 'DRAFT' } } };
  if (/^GET \/qr\/[^/]+\/image$/.test(key)) return { svg: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 8 8"/>' };
  // Any other wallet route: an object answer that carries an `id`, as most reads do.
  return { status: 200, data: { id: crypto.randomUUID() } };
}

// --- Storage stand-in -----------------------------------------------------------------

// The presigned upload URL's host. Like S3, it refuses a request that carries an
// Authorization header next to the presigned query (a second auth mechanism).
async function startStorage() {
  const received = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => {
      received.push({ method: req.method, url: req.url, headers: req.headers, body: Buffer.concat(chunks) });
      res.writeHead(req.headers.authorization ? 400 : 200);
      res.end();
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return { url: `http://127.0.0.1:${server.address().port}`, received, close: () => new Promise((r) => server.close(r)) };
}

function credentialHeaders(hit) {
  return Object.keys(hit.headers).filter((name) => GATEWAY_CREDENTIAL_HEADERS.includes(name.toLowerCase()));
}

async function freePort() {
  const probe = net.createServer();
  await new Promise((resolve) => probe.listen(0, '127.0.0.1', resolve));
  const { port } = probe.address();
  await new Promise((resolve) => probe.close(resolve));
  return port;
}

async function startSigner(privateKeyPem) {
  const port = await freePort();
  const child = spawn(process.execPath, [path.join(POSTMAN_DIR, 'tools/signer-server.js')], {
    env: { ...process.env, POSTMAN_SIGNER_PORT: String(port), LUNIXI_PRIVATE_KEY: privateKeyPem },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  await new Promise((resolve, reject) => {
    child.stdout.on('data', (chunk) => { if (String(chunk).includes('listening')) resolve(); });
    child.on('exit', (code) => reject(new Error(`signer-server exited with ${code}`)));
  });
  return { url: `http://127.0.0.1:${port}`, close: () => child.kill('SIGTERM') };
}

async function setUp(profile) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const storage = await startStorage();
  const gateway = await startGateway(publicKey, storage.url);
  const signer = profile === 'local-signer' ? await startSigner(privateKeyPem) : null;
  const environment = createEnvironment({
    base_url: gateway.url,
    signer_url: signer ? signer.url : '',
    auth_token_path: '/api/v1/auth/token',
    key_id: KEY_ID,
    private_key_pem: profile === 'standalone' ? privateKeyPem : '',
    access_token: '',
    access_token_expires_at: '0',
    callback_url: 'http://localhost:8080/payment.html',
    currency: 'TRY',
    amount_minor: '10050',
    order_id: 'pm-{{$timestamp}}',
    idempotency_key: 'pm-{{$guid}}',
    payment_id: '3f1c2a9e-5b7d-4c1e-9a2b-6d8e0f1a2b3c',
    stored_card_token: 'sc_lock',
    card_user_key: 'postman-user-001',
    provider_credential_id: 'pc_lock',
    org_id: 'org_lock',
    secret_id: 'sec_lock',
    webhook_endpoint_id: 'we_lock',
    delivery_id: 'dl_lock',
    payment_link_id: '6f0c1d2e-3a4b-4c5d-8e9f-0a1b2c3d4e5f',
    payment_link_row_version: '1',
    payment_link_recipient_email: '',
    payment_link_image_asset_id: '',
    payment_link_image_upload_url: '',
    payment_link_image_content_type: '',
    checkout_token: 'ct_original',
    ...WALLET_ENVIRONMENT,
  });
  const teardown = async () => { if (signer) signer.close(); await gateway.close(); await storage.close(); };
  return { gateway, storage, environment, teardown };
}

// Like newman: pre-request scripts, send, then test scripts (collection → folders → item).
async function runItem(collection, entry, environment) {
  const request = createRequest(entry.item);
  const scopes = [collection, ...entry.trail, entry.item];
  for (const node of scopes) {
    const code = scriptOf(node, 'prerequest');
    if (code) await runScript(code, request, environment);
  }
  const response = await sendPrepared(request, environment, collection.auth);
  const tests = [];
  for (const node of scopes) {
    const code = scriptOf(node, 'test');
    if (code) tests.push(...await runScript(code, request, environment, response));
  }
  return { response, tests };
}

// --- Tests ----------------------------------------------------------------------------

test('every Postman script compiles in the sandbox scope (no top-level `const data`)', () => {
  for (const name of Object.keys(COLLECTIONS)) {
    const collection = loadCollection(name);
    const nodes = [collection, ...requestItems(collection.item).flatMap((e) => [...e.trail, e.item])];
    for (const node of new Set(nodes)) {
      for (const event of node.event || []) {
        const where = `${name} › ${node.name || node.info.name} › ${event.listen}`;
        // eslint-disable-next-line no-new-func
        assert.doesNotThrow(() => new Function(...SANDBOX_GLOBALS, event.script.exec.join('\n')), where);
      }
    }
  }
});

for (const profile of ['standalone', 'local-signer']) {
  test(`${profile}: every gateway request is signed the way SignatureGuard verifies it`, async () => {
    const { gateway, storage, environment, teardown } = await setUp(profile);
    try {
      const collection = loadCollection(profile);
      const entries = requestItems(collection.item);
      for (const entry of entries) await runItem(collection, entry, environment);

      const gatewayBound = entries.filter((e) => {
        const url = createRequest(e.item).url;
        return url.startsWith('{{base_url}}') && !url.includes('{{auth_token_path}}');
      });
      assert.equal(gateway.received.length, gatewayBound.length, 'every gateway request reached the stand-in');
      for (const hit of gateway.received) {
        assert.equal(hit.verdict, 'OK', `${hit.method} ${hit.url}`);
        assert.ok(hit.bearer, `${hit.method} ${hit.url} carries the minted access token`);
      }
      for (const stepUp of STEP_UP_TARGETS) {
        assert.ok(gateway.received.some((hit) => hit.method === 'POST' && stepUp.test(hit.url)), `step-up request ${stepUp} was exercised`);
      }
      // The one request that leaves the gateway is the link image PUT to storage, without credentials.
      assert.deepEqual(storage.received.map((hit) => hit.method), ['PUT'], 'the image upload reached storage once');
      for (const hit of storage.received) {
        assert.deepEqual(credentialHeaders(hit), [], `storage ${hit.url} must not receive gateway credentials`);
      }
    } finally {
      await teardown();
    }
  });

  test(`${profile}: the signed target and body are exactly what is sent`, async () => {
    const { gateway, environment, teardown } = await setUp(profile);
    try {
      const collection = loadCollection(profile);
      environment.store.set('card_user_key', "müşteri 1'x/ü%zz");
      const odd = [
        { request: { method: 'GET', header: [], url: '{{base_url}}/api/v1/payments/cards?cardUserKey={{card_user_key}}' } },
        {
          request: {
            method: 'POST',
            header: [{ key: 'Content-Type', value: 'application/json' }],
            body: { mode: 'raw', raw: '{\n  "paymentIntentId": "{{$guid}}",\n  "reason": "Çağrı {{order_id}}"\n}' },
            url: '{{base_url}}/api/v1/payments/{{payment_id}}/capture',
          },
        },
      ];
      for (const item of odd) await runItem(collection, { item, trail: [] }, environment);

      const [list, capture] = gateway.received;
      assert.equal(list.verdict, 'OK');
      assert.equal(list.url, '/api/v1/payments/cards?cardUserKey=m%C3%BC%C5%9Fteri%201%27x/%C3%BC%25zz');
      assert.equal(capture.verdict, 'OK');
      assert.doesNotMatch(capture.raw, /\{\{|\n/, 'body is sent resolved and compact');
      assert.equal(capture.raw, JSON.stringify(JSON.parse(capture.raw)));
    } finally {
      await teardown();
    }
  });
}

for (const profile of ['standalone', 'local-signer']) {
  test(`fraud ${profile}: event ingest is signed the way SignatureGuard verifies it`, async () => {
    const { gateway, environment, teardown } = await setUp(profile);
    try {
      const collection = loadCollection(`fraud-${profile}`);
      const ingest = requestItems(collection.item).filter((e) => e.trail.some((folder) => folder.name === 'Event Ingest'));
      const tests = [];
      for (const entry of ingest) tests.push(...(await runItem(collection, entry, environment)).tests);

      assert.deepEqual(gateway.received.map((hit) => `${hit.method} ${hit.url} ${hit.verdict}`), [
        'POST /api/v1/fraud/events/transactions OK',
        'POST /api/v1/fraud/events/transactions/batch OK',
      ]);
      for (const hit of gateway.received) {
        assert.ok(hit.bearer, `${hit.method} ${hit.url} carries the minted access token`);
      }
      assert.deepEqual(tests.filter((t) => t.error), [], "the collection's own assertions pass");
      assert.equal(tests.filter((t) => t.name === 'event accepted').length, 2);
    } finally {
      await teardown();
    }
  });
}

// --- Payment Links folder -----------------------------------------------------------

// The gateway validates bodies with forbidNonWhitelisted: a key outside the DTO is a
// 400. The field list is the SDK's, so the collection and the SDKs cannot drift apart.
const { PAYMENT_LINK_SPEC_FIELDS } = require('../../node/src/payment/payment-link-values');
const LINK_BODY_FIELDS = {
  'POST /api/v1/payments/links': new Set(['environment', ...PAYMENT_LINK_SPEC_FIELDS]),
  'PATCH /api/v1/payments/links/:id': new Set(['expectedRowVersion', ...PAYMENT_LINK_SPEC_FIELDS]),
  'POST /api/v1/payments/links/:id/pause': new Set(['expectedRowVersion', 'reason']),
  'POST /api/v1/payments/links/:id/resume': new Set(['expectedRowVersion', 'reason']),
  'POST /api/v1/payments/links/:id/deactivate': new Set(['expectedRowVersion', 'reason']),
  'POST /api/v1/payments/links/:id/send': new Set(['channel', 'recipientEmail', 'recipientPhone', 'locale']),
  // PublicAssetUploadDto; the confirmation reads no body (the collection sends `{}`).
  'POST /api/v1/payments/links/images': new Set(['fileName', 'contentType', 'sizeBytes']),
  'POST /api/v1/payments/links/images/:assetId/confirm': new Set(),
};
const IMAGE_CONTENT_TYPES = ['image/png', 'image/jpeg', 'image/webp'];
const LINK_IDEMPOTENCY_REQUIRED = new Set(['POST /api/v1/payments/links', 'POST /api/v1/payments/links/:id/send']);
const IDEMPOTENCY_KEY_FORMAT = /^[\x21-\x7E]{8,200}$/;

// `images` is a fixed segment the gateway routes before `:id`, so it is matched first.
function linkRoute(hit) {
  const pathOnly = hit.url.split('?')[0]
    .replace(/^\/api\/v1\/payments\/links\/images\/[^/]+\/confirm$/, '/api/v1/payments/links/images/:assetId/confirm')
    .replace(/^\/api\/v1\/payments\/links\/(?!images(?:\/|$))[^/]+/, '/api/v1/payments/links/:id');
  return `${hit.method} ${pathOnly}`;
}

function paymentLinksFolder(collection) {
  const folder = collection.item.find((node) => node.name === 'Payment Links');
  assert.ok(folder, 'the collection has a Payment Links folder');
  return folder;
}

for (const profile of ['standalone', 'local-signer']) {
  test(`${profile}: Payment Links requests are signed, keyed and whitelisted`, async () => {
    const { gateway, storage, environment, teardown } = await setUp(profile);
    try {
      const collection = loadCollection(profile);
      const folder = paymentLinksFolder(collection);
      const tests = [];
      for (const item of folder.item) tests.push(...(await runItem(collection, { item, trail: [folder] }, environment)).tests);

      const hits = gateway.received;
      const gatewayItems = folder.item.filter((item) => createRequest(item).url.startsWith('{{base_url}}'));
      assert.equal(hits.length, gatewayItems.length, 'every gateway request of the folder reached the stand-in');
      assert.deepEqual([...new Set(hits.map(linkRoute))].sort(), [
        'GET /api/v1/payments/links',
        'GET /api/v1/payments/links/:id',
        'GET /api/v1/payments/links/:id/attempts',
        'GET /api/v1/payments/links/:id/payments',
        'GET /api/v1/payments/links/:id/qr',
        'PATCH /api/v1/payments/links/:id',
        'POST /api/v1/payments/links',
        'POST /api/v1/payments/links/:id/deactivate',
        'POST /api/v1/payments/links/:id/pause',
        'POST /api/v1/payments/links/:id/resume',
        'POST /api/v1/payments/links/:id/send',
        'POST /api/v1/payments/links/images',
        'POST /api/v1/payments/links/images/:assetId/confirm',
      ]);
      for (const hit of hits) {
        const route = linkRoute(hit);
        assert.equal(hit.verdict, 'OK', `${route}: the API-key signature must verify`);
        if (LINK_IDEMPOTENCY_REQUIRED.has(route)) {
          const key = hit.idempotencyKey;
          assert.ok(typeof key === 'string' && IDEMPOTENCY_KEY_FORMAT.test(key), `${route}: Idempotency-Key is required, got ${key}`);
        }
        const allowed = LINK_BODY_FIELDS[route];
        if (allowed) {
          const unknown = Object.keys(JSON.parse(hit.raw)).filter((key) => !allowed.has(key));
          assert.deepEqual(unknown, [], `${route}: fields the gateway would reject with 400`);
        } else {
          assert.equal(hit.raw, '', `${route}: a read sends no body`);
        }
      }
      const create = hits.filter((hit) => linkRoute(hit) === 'POST /api/v1/payments/links');
      for (const hit of create) assert.equal(typeof JSON.parse(hit.raw).amountMode, 'string');
      assert.equal(JSON.parse(create[0].raw).amountMinor, 10050, 'money is sent as an integer in minor units');

      // Link image: declared as PublicAssetUploadDto takes it, PUT to the issued storage URL
      // without the key's credentials, then confirmed and set by the issued asset id.
      const declared = JSON.parse(hits.find((hit) => linkRoute(hit) === 'POST /api/v1/payments/links/images').raw);
      assert.ok(IMAGE_CONTENT_TYPES.includes(declared.contentType), `declared type ${declared.contentType}`);
      assert.ok(Number.isSafeInteger(declared.sizeBytes) && declared.sizeBytes >= 1, 'sizeBytes is a JSON integer (a string is 400)');
      assert.equal(gateway.issuedUploads.length, 1);
      const [issued] = gateway.issuedUploads;
      assert.equal(storage.received.length, 1, 'the image went to storage once');
      const [put] = storage.received;
      assert.equal(put.method, 'PUT');
      assert.equal(put.url, issued.uploadUrl.slice(storage.url.length), 'the presigned URL is sent verbatim');
      assert.deepEqual(credentialHeaders(put), [], 'neither the access token nor the signature reaches storage');
      assert.equal(put.headers['content-type'], issued.uploadHeaders['Content-Type'], 'the Content-Type the URL was signed for');
      assert.ok(put.body.equals(SELECTED_FILE), 'the selected file is the body');
      assert.ok(hits.some((hit) => hit.url === `/api/v1/payments/links/images/${issued.assetId}/confirm`), 'confirm names the issued asset');
      const setImage = hits.find((hit) => hit.method === 'PATCH' && 'imageAssetId' in JSON.parse(hit.raw));
      assert.equal(JSON.parse(setImage.raw).imageAssetId, issued.assetId, 'the link gets the confirmed image');
      assert.deepEqual(tests.filter((t) => t.error), [], "the folder's own assertions pass");
    } finally {
      await teardown();
    }
  });

  test(`${profile}: a payment-link response chains payment_link_* and leaves payment_id alone`, async () => {
    const collection = loadCollection(profile);
    const folder = paymentLinksFolder(collection);
    const runTests = async (url, envelope, nodes) => {
      const environment = createEnvironment({ payment_id: 'pi_original' });
      const pm = {
        test() {},
        environment: { get: (k) => environment.store.get(k), set: (k, v) => environment.store.set(k, v) },
        request: { url: { toString: () => url } },
        response: { code: 200, json: () => envelope },
      };
      for (const node of nodes) {
        // eslint-disable-next-line no-new-func
        new Function(...SANDBOX_GLOBALS, scriptOf(node, 'test'))(...SANDBOX_GLOBALS.map((name) => (name === 'pm' ? pm : undefined)));
      }
      return environment.store;
    };
    const link = { id: '6f0c1d2e-3a4b-4c5d-8e9f-0a1b2c3d4e5f', shortCode: 'K7M2Q9XR4T', url: 'https://pay.lunixi.com/K7M2Q9XR4T', rowVersion: 4 };

    const afterLink = await runTests('https://api-gateway.lunixi.com/api/v1/payments/links', { data: link }, [collection, folder]);
    assert.equal(afterLink.get('payment_id'), 'pi_original', 'a link id is not a payment id');
    assert.equal(afterLink.get('payment_link_id'), link.id);
    assert.equal(afterLink.get('payment_link_row_version'), '4');
    assert.equal(afterLink.get('payment_link_url'), link.url);

    const afterPayment = await runTests('https://api-gateway.lunixi.com/api/v1/payments/pi_new', { data: { id: 'pi_new' } }, [collection]);
    assert.equal(afterPayment.get('payment_id'), 'pi_new', 'payment responses still chain payment_id');

    const target = { assetId: '33333333-3333-4333-8333-333333333333', uploadUrl: 'https://storage.invalid/o?X-Amz-Signature=ab', uploadMethod: 'PUT', uploadHeaders: { 'Content-Type': 'image/png' } };
    const afterImage = await runTests('https://api-gateway.lunixi.com/api/v1/payments/links/images', { data: target }, [collection, folder]);
    assert.equal(afterImage.get('payment_id'), 'pi_original', 'an asset id is not a payment id');
    assert.equal(afterImage.get('payment_link_id'), undefined, 'an asset id is not a link id');
  });
}

test('the gateway stand-in rejects what SignatureGuard rejects', async () => {
  const { gateway, environment, teardown } = await setUp('standalone');
  try {
    const collection = loadCollection('standalone');
    const item = {
      request: {
        method: 'POST',
        header: [{ key: 'Content-Type', value: 'application/json' }],
        body: { mode: 'raw', raw: '{"amount": 1}' },
        url: '{{base_url}}/api/v1/payments/intents',
      },
    };
    const signed = async () => {
      const request = createRequest(item);
      await runScript(scriptOf(collection, 'prerequest'), request, environment);
      return request;
    };
    // 1. Unsigned: the request as it looked before the collection signed it.
    await sendPrepared(createRequest(item), environment, collection.auth);
    // 2. Digest over the bytes sent (indented) instead of over the parsed JSON.
    const indented = await signed();
    indented.body.raw = JSON.stringify(JSON.parse(indented.body.raw), null, 2);
    indented.pm.headers.upsert({ key: 'Digest', value: 'SHA-256=' + crypto.createHash('sha256').update(indented.body.raw).digest('base64') });
    await sendPrepared(indented, environment, collection.auth);
    // 3. Query added after signing: the signature covers path AND query.
    const retargeted = await signed();
    retargeted.pm.url.update(retargeted.url + '?limit=1');
    await sendPrepared(retargeted, environment, collection.auth);
    // 4. Untouched signed request.
    await sendPrepared(await signed(), environment, collection.auth);

    assert.deepEqual(gateway.received.map((hit) => hit.verdict), ['AUTH_HEADERS_MISSING', 'INVALID_DIGEST', 'INVALID_SIGNATURE', 'OK']);
  } finally {
    await teardown();
  }
});

// --- Wallet folder ----------------------------------------------------------------------

// The SDK's route table: method, path, Idempotency-Key and the body fields the gateway
// DTO accepts (forbidNonWhitelisted). The collection and the SDKs cannot drift apart.
const { WALLET_ROUTES, WALLET_NESTED_FIELDS, AMOUNT_PATTERN, WALLET_IDEMPOTENCY_KEY_MAX } = require('../../node/src/wallet/wallet-values');
const ENVIRONMENT_TEMPLATES = {
  standalone: 'standalone/environments/lunixi.standalone.template.postman_environment.json',
  'local-signer': 'local-signer/environments/lunixi.local-signer.template.postman_environment.json',
};

function walletFolder(collection) {
  const folder = collection.item.find((node) => node.name === 'Wallet');
  assert.ok(folder, 'the collection has a Wallet folder');
  return folder;
}

function walletEntries(collection) {
  const folder = walletFolder(collection);
  return requestItems(folder.item, [folder]);
}

// `{{base_url}}/api/v1/wallet/end-users/{{wallet_end_user_id}}?…` → `getEndUser`. Path
// parameters must be variables; the query is checked separately.
function walletRouteOf(item) {
  const url = createRequest(item).url;
  const matches = Object.entries(WALLET_ROUTES).filter(([, route]) => {
    const pattern = route.path.split('/').map((segment) => (segment.startsWith(':') ? '\\{\\{[a-z_]+\\}\\}' : segment)).join('/');
    return route.method === item.request.method && new RegExp(`^\\{\\{base_url\\}\\}${pattern}(?:\\?.*)?$`).test(url);
  });
  assert.equal(matches.length, 1, `${item.name}: ${item.request.method} ${url} must match exactly one wallet route, got ${matches.map(([name]) => name)}`);
  return matches[0][0];
}

function bodyListField(routeName) {
  return routeName === 'createBulkPayout' ? 'items' : 'rows';
}

function checkWalletBody(routeName, body) {
  const route = WALLET_ROUTES[routeName];
  const allowed = new Set([...(route.required || []), ...(route.optional || [])]);
  assert.deepEqual(Object.keys(body).filter((key) => !allowed.has(key)), [], `${routeName}: fields the gateway would reject with 400`);
  assert.deepEqual((route.required || []).filter((key) => body[key] === undefined || body[key] === ''), [], `${routeName}: required fields missing`);
  if (body.amount !== undefined) assert.match(body.amount, AMOUNT_PATTERN, `${routeName}: amount is minor units as a digit string`);
  const nested = WALLET_NESTED_FIELDS[routeName];
  if (!nested) return;
  const rows = body[bodyListField(routeName)];
  assert.ok(Array.isArray(rows) && rows.length > 0, `${routeName}: ${bodyListField(routeName)} is a non-empty array`);
  const rowAllowed = new Set([...nested.required, ...nested.optional]);
  rows.forEach((row, index) => {
    const label = `${routeName}.${bodyListField(routeName)}[${index}]`;
    assert.deepEqual(Object.keys(row).filter((key) => !rowAllowed.has(key)), [], `${label}: fields the gateway would reject with 400`);
    assert.deepEqual(nested.required.filter((key) => row[key] === undefined || row[key] === ''), [], `${label}: required fields missing`);
    if (row.amount !== undefined) assert.match(row.amount, AMOUNT_PATTERN, `${label}: amount is minor units as a digit string`);
  });
}

test('the Wallet folder is the same in both payment collections', () => {
  const [standalone, localSigner] = ['standalone', 'local-signer'].map((profile) => walletFolder(loadCollection(profile)));
  assert.equal(JSON.stringify(localSigner), JSON.stringify(standalone), 'write the folder once, insert it into both collections');
});

test('every wallet variable the folder uses is declared in both environment templates', () => {
  const used = new Set(JSON.stringify(walletFolder(loadCollection('standalone'))).match(/\{\{wallet_[a-z_]+\}\}/g).map((token) => token.slice(2, -2)));
  for (const [profile, file] of Object.entries(ENVIRONMENT_TEMPLATES)) {
    const declared = JSON.parse(fs.readFileSync(path.join(POSTMAN_DIR, file), 'utf8')).values;
    const names = new Set(declared.map((variable) => variable.key));
    assert.deepEqual([...used].filter((name) => !names.has(name)), [], `${profile} template`);
    for (const secret of ['wallet_integrity_hash', 'wallet_nonce', 'wallet_payment_code']) {
      assert.equal(declared.find((variable) => variable.key === secret).type, 'secret', `${profile}: ${secret} is a secret`);
    }
  }
});

for (const profile of ['standalone', 'local-signer']) {
  test(`${profile}: the Wallet folder has exactly one request per WALLET_ROUTES route`, () => {
    const entries = walletEntries(loadCollection(profile));
    const routes = entries.map((entry) => walletRouteOf(entry.item));
    assert.equal(entries.length, Object.keys(WALLET_ROUTES).length, 'one request per route, no extras');
    assert.deepEqual([...routes].sort(), Object.keys(WALLET_ROUTES).sort(), 'every route once');
    for (const [index, entry] of entries.entries()) {
      const route = WALLET_ROUTES[routes[index]];
      const url = createRequest(entry.item).url;
      const query = url.includes('?') ? url.split('?')[1].split('&').map((pair) => pair.split('=')[0]) : [];
      assert.deepEqual(query.filter((key) => !(route.query || []).includes(key)), [], `${routes[index]}: query parameters the route accepts`);
      const header = (entry.item.request.header || []).find((h) => h.key.toLowerCase() === 'idempotency-key');
      assert.equal(Boolean(header), route.idempotencyKey, `${routes[index]}: Idempotency-Key header iff the gateway requires it`);
      const hasFields = Boolean(route.required || route.optional);
      assert.equal(Boolean(entry.item.request.body), hasFields, `${routes[index]}: a body iff the route takes fields`);
      if (hasFields) checkWalletBody(routes[index], JSON.parse(entry.item.request.body.raw.replace(/\{\{[^{}]+\}\}/g, 'x')));
      assert.ok(scriptOf(entry.item, 'test'), `${routes[index]}: has a 2xx test`);
    }
  });

  test(`${profile}: Wallet requests are signed, keyed, whitelisted and chained`, async () => {
    const { gateway, environment, teardown } = await setUp(profile);
    try {
      const collection = loadCollection(profile);
      const entries = walletEntries(collection);
      const routes = entries.map((entry) => walletRouteOf(entry.item));
      const tests = [];
      for (const entry of entries) tests.push(...(await runItem(collection, entry, environment)).tests);

      // (b) every request reached the gateway, signed the way SignatureGuard verifies it.
      const hits = gateway.received;
      assert.equal(hits.length, entries.length, 'every wallet request reached the stand-in once');
      hits.forEach((hit, index) => {
        const name = routes[index];
        const route = WALLET_ROUTES[name];
        assert.equal(hit.method, route.method, name);
        assert.equal(hit.verdict, 'OK', `${name}: the API-key signature must verify`);
        assert.ok(hit.bearer, `${name}: carries the minted access token`);
        // (c) Idempotency-Key on the wire iff required; the gateway trims it and takes 1-128.
        if (route.idempotencyKey) {
          const key = String(hit.idempotencyKey || '').trim();
          assert.ok(key.length >= 1 && key.length <= WALLET_IDEMPOTENCY_KEY_MAX && key === hit.idempotencyKey, `${name}: Idempotency-Key is required, got ${hit.idempotencyKey}`);
        } else {
          assert.equal(hit.idempotencyKey, undefined, `${name}: no Idempotency-Key`);
        }
        // (d) the resolved body has only fields the DTO accepts and all it requires.
        if (route.required || route.optional) checkWalletBody(name, JSON.parse(hit.raw));
        else assert.equal(hit.raw, '', `${name}: sends no body`);
      });
      assert.deepEqual(tests.filter((t) => t.error), [], "the folder's own assertions pass (2xx, QR image type)");
      assert.ok(tests.some((t) => t.name === 'Get QR Image: 2xx image' && !t.error), 'the QR image is checked as an image');

      // (e) chaining: each request uses what the one before it answered.
      const hitOf = (name) => hits[routes.indexOf(name)];
      const bodyOf = (name) => JSON.parse(hitOf(name).raw);
      const store = environment.store;
      assert.equal(store.get('wallet_program_id'), WALLET_IDS.program);
      assert.equal(store.get('wallet_end_user_id'), WALLET_IDS.endUser);
      assert.equal(store.get('wallet_no'), WALLET_IDS.walletNo);
      assert.equal(store.get('wallet_account_id'), WALLET_IDS.account, 'the account in the environment currency');
      assert.equal(store.get('wallet_id'), WALLET_IDS.secondWallet, 'Create Wallet moves wallet_id to the new wallet');
      assert.equal(store.get('wallet_corporate_account_id'), WALLET_IDS.corporate);
      assert.equal(store.get('wallet_topup_operation_id'), WALLET_IDS.topup);
      assert.equal(store.get('wallet_qr_id'), WALLET_IDS.qr);
      assert.equal(store.get('wallet_qr_payload'), WALLET_IDS.qrPayload);
      assert.equal(store.get('wallet_bulk_batch_id'), WALLET_IDS.batch);
      assert.equal(store.get('wallet_deposit_reference'), WALLET_IDS.depositReference);
      assert.equal(bodyOf('createEndUser').programId, WALLET_IDS.program);
      assert.equal(hitOf('getBalances').url, `/api/v1/wallet/end-users/${WALLET_IDS.endUser}/balances`);
      assert.equal(hitOf('createWalletAccount').url, `/api/v1/wallet/wallets/${WALLET_IDS.secondWallet}/accounts`);
      assert.equal(bodyOf('createDepositInstruction').walletAccountId, WALLET_IDS.account);
      assert.equal(bodyOf('simulateInboundCredit').rawReference, WALLET_IDS.depositReference);
      assert.equal(bodyOf('simulateInboundCredit').creditedIban, WALLET_IDS.depositIban);
      assert.equal(hitOf('importCorporateEmployees').url, `/api/v1/wallet/corporate-accounts/${WALLET_IDS.corporate}/employees/import`);
      for (const [initiate, complete, segment] of [
        ['initiateW2W', 'completeW2W', 'transfers/w2w'],
        ['initiateW2Iban', 'completeW2Iban', 'transfers/w2iban'],
        ['initiateBankWithdrawal', 'completeBankWithdrawal', 'withdrawals/bank'],
      ]) {
        const issued = gateway.walletIssued.find((step) => step.route === `POST /${segment}`);
        assert.ok(routes.indexOf(initiate) < routes.indexOf(complete), `${initiate} runs before ${complete}`);
        assert.equal(hitOf(complete).url, `/api/v1/wallet/${segment}/${issued.id}/complete`, `${complete}: the operation its initiate opened`);
        assert.deepEqual(bodyOf(complete), { endUserId: WALLET_IDS.endUser, operationId: issued.id, integrityHash: issued.integrityHash, nonce: issued.nonce }, `${complete}: operationId in the body equals the path id`);
      }
      const withdrawal = gateway.walletIssued.find((step) => step.route === 'POST /withdrawals/bank');
      assert.equal(hitOf('getWithdrawal').url, `/api/v1/wallet/withdrawals/${withdrawal.id}`);
      assert.equal(hitOf('getOperationReceipt').url, `/api/v1/wallet/operations/${withdrawal.id}/receipt`);
      assert.equal(hitOf('getTopup').url, `/api/v1/wallet/topups/${WALLET_IDS.topup}`);
      assert.equal(hitOf('refundTopup').url, `/api/v1/wallet/topups/${WALLET_IDS.topup}/refund`);
      const payment = gateway.walletIssued.find((step) => step.route === 'POST /payments/buy');
      assert.equal(hitOf('approvePayment').url, `/api/v1/wallet/payments/${payment.id}/approve`);
      assert.deepEqual(bodyOf('approvePayment'), { buyerEndUserId: WALLET_IDS.endUser, integrityHash: payment.integrityHash, nonce: payment.nonce });
      assert.equal(hitOf('getPayment').url, `/api/v1/wallet/payments/${payment.id}`);
      assert.equal(hitOf('getQrImage').url, `/api/v1/wallet/qr/${WALLET_IDS.qr}/image?format=svg&scale=8`);
      assert.equal(bodyOf('parseQr').payload, WALLET_IDS.qrPayload);
      assert.equal(hitOf('revokeQr').url, `/api/v1/wallet/qr/${WALLET_IDS.qr}/revoke`);
      for (const name of ['getBulkPayout', 'submitBulkPayout', 'approveBulkPayout', 'processBulkPayout']) {
        assert.ok(hitOf(name).url.startsWith(`/api/v1/wallet/bulk-payouts/${WALLET_IDS.batch}`), `${name} targets the created batch`);
      }
      assert.equal(hitOf('freezeEndUser').url, `/api/v1/wallet/end-users/${WALLET_IDS.endUser}/freeze`);
      assert.equal(routes[routes.length - 1], 'freezeEndUser', 'freeze runs last: a frozen end user cannot move money');

      // Wallet answers carry `id`, `paymentId` (top-up) and `token`: none of them is a payment.
      assert.equal(store.get('payment_id'), '3f1c2a9e-5b7d-4c1e-9a2b-6d8e0f1a2b3c', 'payment_id is left alone');
      assert.equal(store.get('checkout_token'), 'ct_original', 'checkout_token is left alone');
      assert.equal(store.get('stored_card_token'), 'sc_lock', 'stored_card_token is left alone');
    } finally {
      await teardown();
    }
  });

  test(`${profile}: a wallet response chains wallet_* and leaves payment_id alone`, () => {
    const collection = loadCollection(profile);
    const folder = walletFolder(collection);
    const runTests = (method, url, envelope, nodes) => {
      const environment = createEnvironment({ payment_id: 'pi_original', checkout_token: 'ct_original', currency: 'TRY' });
      const pm = {
        test() {},
        expect: expectation,
        environment: { get: (k) => environment.store.get(k), set: (k, v) => environment.store.set(k, v) },
        request: { method, url: { toString: () => url } },
        response: { code: 201, json: () => envelope },
      };
      for (const node of nodes) {
        // eslint-disable-next-line no-new-func
        new Function(...SANDBOX_GLOBALS, scriptOf(node, 'test'))(...SANDBOX_GLOBALS.map((name) => (name === 'pm' ? pm : undefined)));
      }
      return environment.store;
    };
    const topup = runTests('POST', 'https://api-gateway.lunixi.com/api/v1/wallet/topups/card',
      { data: { operationId: 'op_topup', paymentId: 'pay_card', token: 'tok_x', storedCardToken: 'sc_x' } }, [collection, folder]);
    assert.equal(topup.get('payment_id'), 'pi_original', "a top-up's card payment is not the payment_id");
    assert.equal(topup.get('checkout_token'), 'ct_original');
    assert.equal(topup.get('stored_card_token'), undefined);
    assert.equal(topup.get('wallet_topup_operation_id'), 'op_topup');

    const endUser = runTests('POST', 'https://api-gateway.lunixi.com/api/v1/wallet/end-users',
      { data: { endUser: { id: 'eu_1' }, defaultWallet: { id: 'w_1', walletNo: '5810763412', accounts: [{ id: 'acc_1', currency: 'TRY' }] } } }, [collection, folder]);
    assert.equal(endUser.get('payment_id'), 'pi_original');
    assert.deepEqual(['wallet_end_user_id', 'wallet_id', 'wallet_no', 'wallet_account_id'].map((k) => endUser.get(k)), ['eu_1', 'w_1', '5810763412', 'acc_1']);

    const initiate = runTests('POST', 'https://api-gateway.lunixi.com/api/v1/wallet/transfers/w2w',
      { data: { operationId: 'op_1', integrityHash: 'a'.repeat(64), nonce: 'b'.repeat(64), otpRequired: false } }, [collection, folder]);
    assert.deepEqual(['wallet_operation_id', 'wallet_integrity_hash', 'wallet_nonce'].map((k) => initiate.get(k)), ['op_1', 'a'.repeat(64), 'b'.repeat(64)]);
    assert.equal(initiate.get('payment_id'), 'pi_original');

    const payment = runTests('GET', 'https://api-gateway.lunixi.com/api/v1/payments/pi_new', { data: { id: 'pi_new' } }, [collection]);
    assert.equal(payment.get('payment_id'), 'pi_new', 'payment responses still chain payment_id');
  });
}
