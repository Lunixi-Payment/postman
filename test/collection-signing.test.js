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
const STEP_UP_TARGETS = [
  /\/payments\/intents$/, /\/payments\/[^/]+\/capture$/,
  /\/payments\/direct\/payment$/, /\/payments\/[^/]+\/actions\/[^/]+\/confirm$/,
  /\/payments\/split$/, /\/payments\/split\/[^/]+\/refund$/,
];
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
        if (name === '$isoTimestamp') return new Date().toISOString();
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
  const methodIssued = [];
  const splitIssued = [];
  const insuranceIssued = { quotes: [], orders: [], leads: [] };
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
      if (req.url.startsWith('/api/v1/sanction/')) {
        const answer = sanctionReply(req.method, req.url.split('?')[0].slice('/api/v1/sanction'.length));
        return reply(200, { status: 'success', code: answer.code, data: answer.data, statusCode: 200, requestId: 'req_lock' });
      }
      if (req.url.startsWith('/api/v1/bank-connect/')) {
        const answer = bankConnectReply(req.method, req.url.split('?')[0].slice('/api/v1/bank-connect'.length));
        return reply(answer.status, { status: 'success', code: 'SUCCESS', data: answer.data, ...(answer.pageInfo ? { pageInfo: answer.pageInfo } : {}), requestId: 'req_lock' });
      }
      const noteAnswer = promissoryNoteReply(req.method, req.url.split('?')[0], raw);
      if (noteAnswer && noteAnswer.pdf) {
        res.writeHead(200, { 'Content-Type': 'application/pdf' });
        return res.end(noteAnswer.pdf);
      }
      if (noteAnswer) return reply(200, { status: 'success', code: 'SUCCESS', data: noteAnswer.data });
      if (req.method === 'GET' && req.url.startsWith('/api/v1/reference/tr-address/')) {
        return reply(200, { status: 'success', code: 'SUCCESS', data: { items: [] } });
      }
      const splitAnswer = splitReply(req.method, req.url, raw, req.headers['idempotency-key'], splitIssued);
      if (splitAnswer) return reply(splitAnswer.status, splitAnswer.body);
      if (req.url.startsWith('/api/v1/insurance/')) {
        const answer = insuranceReply(req.method, req.url.split('?')[0].slice('/api/v1/insurance'.length), raw, insuranceIssued);
        return reply(answer.status, { status: 'success', code: 'SUCCESS', data: answer.data, ...(answer.pageInfo ? { pageInfo: answer.pageInfo } : {}), requestId: 'req_lock' });
      }
      const methodAnswer = methodReply(req.method, req.url, raw, methodIssued);
      if (methodAnswer) return reply(methodAnswer.status, { status: methodAnswer.status === 200 ? 'success' : 'partial', code: 'OK', data: methodAnswer.data });
      return reply(200, { code: verdict, data: {} });
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return { url: `http://127.0.0.1:${server.address().port}`, received, issuedUploads, walletIssued, methodIssued, splitIssued, insuranceIssued, close: () => new Promise((r) => server.close(r)) };
}

// Payment-method answers (contract: gateway method-payment.response.ts, under the
// envelope's `data`). Every start and resend opens a fresh payment / action id, so a
// confirm that does not use the latest chained action is caught.
function methodReply(method, url, raw, issued) {
  const open = (paymentId, type, extra = {}) => {
    const action = { id: `act_${crypto.randomUUID()}`, type, expiresAt: new Date(Date.now() + 180000).toISOString(), ...extra };
    issued.push({ paymentId, action });
    return action;
  };
  if (method === 'GET' && url.split('?')[0] === '/api/v1/payments/methods') {
    const methods = [
      { paymentMethod: 'MOBILE_BILLING', blockName: 'mobileBilling', providerSelection: 'OPTIONAL', providerSelectionMode: 'PLATFORM', providers: [{ providerCode: 'PAYCELL_MOBILE_BILLING', splitEligible: true, splitBehavior: 'CAPTURE_IRREVERSIBLE' }], splitEligible: true, splitBehavior: 'CAPTURE_IRREVERSIBLE' },
      { paymentMethod: 'WALLET', blockName: 'wallet', providerSelection: 'REQUIRED', providerSelectionMode: 'BUYER', providers: [] },
    ];
    const only = new URL(url, 'http://stand-in').searchParams.get('paymentMethod');
    return { status: 200, data: { methods: only === null ? methods : methods.filter((entry) => entry.paymentMethod === only) } };
  }
  if (method === 'POST' && url === '/api/v1/payments/direct/payment') {
    const body = JSON.parse(raw);
    const paymentId = crypto.randomUUID();
    const base = { paymentId, orderId: body.orderId, paymentMethod: body.paymentMethod };
    // Senetle Ödeme: the notes are issued at once; no buyer action.
    if (body.paymentMethod === 'PROMISSORY_NOTE') return { status: 200, data: { ...base, status: 'CAPTURED', providerCode: 'EXAMPLE_PROVIDER' } };
    if (body.paymentMethod === 'CARD' && body.force3D !== true) return { status: 200, data: { ...base, status: body.preauth ? 'AUTHORIZED' : 'CAPTURED' } };
    const action = body.paymentMethod === 'CARD'
      ? open(paymentId, 'REDIRECT', { redirect: { url: `https://api-gateway.lunixi.com/api/v1/payments/3ds/${paymentId}` } })
      : open(paymentId, 'OTP', { otp: { maskedTarget: '+90532***0001' } });
    return { status: 202, data: { ...base, status: 'INITIATED', action } };
  }
  const actionRoute = /^\/api\/v1\/payments\/([^/]+)\/actions\/([^/]+)\/(confirm|resend)$/.exec(url);
  if (method === 'POST' && actionRoute) {
    const [, paymentId, , operation] = actionRoute;
    if (operation === 'resend') return { status: 202, data: { paymentId, status: 'INITIATED', paymentMethod: 'MOBILE_BILLING', action: open(paymentId, 'OTP') } };
    return { status: 200, data: { paymentId, status: 'CAPTURED', paymentMethod: 'MOBILE_BILLING' } };
  }
  return null;
}

// Split-payment answers (contract: payment-service merchantSplitPayload, under the
// envelope's `data`). A split with a non-card leg first waits for the leg's OTP and is
// answered like the gateway does while a split runs: HTTP 400, the split status as `code`.
// The same Idempotency-Key then continues it (`duplicate: true`) to COMPLETED. Ids are
// fresh per split, so a confirm or read that does not use the chained id is caught.
function splitReply(method, url, raw, idempotencyKey, issued) {
  const route = url.split('?')[0];
  if (method === 'POST' && route === '/api/v1/payments/split') {
    const body = JSON.parse(raw);
    const known = issued.find((entry) => entry.idempotencyKey === idempotencyKey);
    const split = known || {
      idempotencyKey,
      splitPaymentId: crypto.randomUUID(),
      legPaymentId: crypto.randomUUID(),
      actionId: `act_${crypto.randomUUID()}`,
      mixed: body.legs.some((leg) => leg.paymentMethod !== undefined && leg.paymentMethod !== 'CARD'),
    };
    if (!known) issued.push(split);
    const data = { splitPaymentId: split.splitPaymentId, duplicate: Boolean(known), needsReconciliation: false, lockContended: false, legs: [], expiresAt: null };
    if (split.mixed && !known) {
      const pendingStep = {
        legId: crypto.randomUUID(), sequence: 2, step: 'ACTION', paymentMethod: 'MOBILE_BILLING', providerCode: 'PAYCELL_MOBILE_BILLING',
        amount: 4000, paymentId: split.legPaymentId, actionId: split.actionId, redirectPath: null, action: null,
      };
      return { status: 400, body: { status: 'failure', code: 'AWAITING_ACTION', statusCode: 400, data: { ...data, status: 'AWAITING_ACTION', steps: [], pendingStep } } };
    }
    return { status: 200, body: { status: 'success', code: 'COMPLETED', data: { ...data, status: 'COMPLETED', steps: [], pendingStep: null } } };
  }
  const refund = /^\/api\/v1\/payments\/split\/([^/]+)\/refund$/.exec(route);
  if (method === 'POST' && refund) {
    return { status: 200, body: { status: 'success', code: 'SPLIT_REFUND_COMPLETED', data: { refundRequestId: crypto.randomUUID(), splitPaymentId: refund[1], status: 'COMPLETED', legs: [] } } };
  }
  const detail = /^\/api\/v1\/payments\/split\/([^/]+)$/.exec(route);
  if (method === 'GET' && detail) {
    return { status: 200, body: { status: 'success', code: 'SUCCESS', data: { id: detail[1], status: 'COMPLETED', legs: [], refund: { refundableAmount: 10000, nonRefundableAmount: 0, refundedAmount: 0 } } } };
  }
  if (method === 'GET' && route === '/api/v1/payments/split') {
    return { status: 200, body: { status: 'success', code: 'SUCCESS', data: { items: [], pageInfo: { hasNextPage: false, endCursor: null }, totalCount: null } } };
  }
  return null;
}

// Promissory-note answers (contract: gateway promissory-note.dto.ts, under the envelope's
// `data`). The open note's serial differs from the stale environment value, so a cancel
// that does not use the chained serial is caught.
const PROMISSORY_NOTE_SERIALS = { cancelled: 'NOTE-LOCK-0001', open: 'NOTE-LOCK-0002' };
function promissoryNoteReply(method, route, raw) {
  const match = /^\/api\/v1\/payments\/([^/]+)\/promissory-notes(\/cancel|\/document)?$/.exec(route);
  if (!match) return null;
  const [, paymentId, operation] = match;
  if (method === 'GET' && operation === '/document') return { pdf: '%PDF-1.7\n%lock\n' };
  const note = (serialNumber, sequence, status) => ({
    serialNumber, sequence, amount: 100000 * sequence, dueDate: `2030-0${sequence}-15`, status, paidAt: null, protestedAt: null, cancelledAt: null,
  });
  const data = {
    paymentId,
    providerCode: 'EXAMPLE_PROVIDER',
    documentType: 'PROMISSORY_NOTE',
    rowSerialNumber: 'ROW-LOCK-0001',
    currency: 'TRY',
    totalAmount: 300000,
    notes: [note(PROMISSORY_NOTE_SERIALS.cancelled, 1, 'CANCELLED'), note(PROMISSORY_NOTE_SERIALS.open, 2, 'ISSUED')],
  };
  if (method === 'POST' && operation === '/cancel') {
    const serialNumbers = raw ? JSON.parse(raw).serialNumbers : data.notes.map((entry) => entry.serialNumber);
    return { data: { ...data, cancelResults: serialNumbers.map((serialNumber) => ({ serialNumber, result: 'CANCELLED', errorCode: null })) } };
  }
  return method === 'GET' && !operation ? { data } : null;
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

// Bank-connect answers (contract: gateway bank-connect-api.mapper.ts, rows under `data.items`,
// paging in the top-level `pageInfo`) for the routes whose ids the Bank Accounts folder chains.
const BANK_IDS = {
  connection: '30000000-0000-4000-8000-000000000001',
  account: '30000000-0000-4000-8000-000000000002',
  transaction: '30000000-0000-4000-8000-000000000003',
  transfer: '30000000-0000-4000-8000-000000000004',
  quote: '30000000-0000-4000-8000-000000000005',
  order: '30000000-0000-4000-8000-000000000006',
};
function bankConnectReply(method, route) {
  const lastPage = { hasMore: false, nextCursor: null, totalCount: null };
  // Bank Transfers folder (contract: gateway bank-connect-transfer.mapper.ts / gateway service).
  if (method === 'POST' && route === '/transfers') return { status: 201, data: { transfer: { id: BANK_IDS.transfer, status: 'SUBMITTED' }, stepUp: null, replayed: false } };
  if (method === 'POST' && route === '/fx/quotes') return { status: 201, data: { id: BANK_IDS.quote, validForSeconds: 80 } };
  if (method === 'POST' && route === '/fx/orders') return { status: 201, data: { order: { id: BANK_IDS.order, status: 'SUBMITTED' }, replayed: false } };
  if (['/transfers', '/fx/orders'].includes(route)) return { status: 200, data: { items: [] }, pageInfo: lastPage };
  if (method === 'POST') return { status: 202, data: { accountId: route.split('/')[2], syncStatus: 'QUEUED', minSyncIntervalSeconds: 300 } };
  if (route === '/connections') return { status: 200, data: { items: [{ connectionId: BANK_IDS.connection, status: 'ACTIVE', accountCount: 1 }] }, pageInfo: lastPage };
  if (route === '/accounts') return { status: 200, data: { items: [{ accountId: BANK_IDS.account, connectionId: BANK_IDS.connection, currency: 'TRY' }] }, pageInfo: lastPage };
  if (route === '/transactions') return { status: 200, data: { items: [{ transactionId: BANK_IDS.transaction, accountId: BANK_IDS.account, amountMinor: 150000 }] }, pageInfo: lastPage };
  if (['/banks', '/balances'].includes(route)) return { status: 200, data: { items: [] }, pageInfo: lastPage };
  return { status: 200, data: {} };
}
const BANK_ENVIRONMENT = {
  bank_connection_id: '',
  bank_account_id: '',
  bank_transaction_id: '',
  bank_booked_from: '2026-09-01T00:00:00Z',
  bank_booked_to: '2026-10-01T00:00:00Z',
};
// The Bank Transfers folder runs after the Bank Accounts folder; the lock seeds the ids that
// folder would have filled, plus the values the user fills by hand.
const BANK_TRANSFER_ENVIRONMENT = {
  bank_receiver_iban: 'TR050006200000000000000146',
  bank_receiver_name: 'Örnek Tedarik A.Ş.',
  bank_fx_source_account_id: '30000000-0000-4000-8000-000000000012',
  bank_fx_target_account_id: '30000000-0000-4000-8000-000000000013',
  bank_transfer_id: '',
  bank_fx_quote_id: '',
  bank_fx_order_id: '',
};

// Sanction answers (contract: gateway sanction.service.ts, under the envelope's `data`). The
// screening id and the matched entity differ from the search result, so an entity request
// that does not use the chained screening match is caught.
const SANCTION_IDS = {
  screening: '40000000-0000-4000-8000-000000000001',
  matched: 'NK-lock-matched',
  searched: 'NK-lock-searched',
  pinned: 'NK-lock-pinned',
};
function sanctionReply(method, route) {
  if (method === 'POST' && route === '/screening/name') {
    return {
      code: 'sanction.screen_name.completed',
      data: { screeningRequestId: SANCTION_IDS.screening, coverageStatus: 'COMPLETE', matches: [{ hitId: 'hit_lock', entityId: SANCTION_IDS.matched, lists: [] }] },
    };
  }
  if (method === 'GET' && route === '/intelligence/entity-search') {
    return { code: 'sanction.entity_search.completed', data: { items: [{ id: SANCTION_IDS.searched, name: 'Kurgu' }] } };
  }
  return { code: 'sanction.lock.completed', data: { items: [] } };
}
const SANCTION_ENVIRONMENT = {
  sanction_screening_request_id: '',
  sanction_entity_id: '',
};

// Insurance answers (contract §2.8: gateway insurance-json.mapper.ts, under the envelope's
// `data`; lists in `data.items` with the top-level `pageInfo`). Every quote offers an option
// the insurer collects (PROVIDER) before the one you collect (MERCHANT), with fresh ids and
// terms, and every order gets its own id and premium, so a request that uses a stale or the
// wrong option or order is caught.
const INSURANCE_IDS = {
  cityCode: '35',
  policy: `insp_${'c'.repeat(32)}`,
};
const INSURANCE_SAMPLE_PREMIUM = 4900;
function insuranceReply(method, route, raw, issued) {
  const lastPage = { hasMore: false, nextCursor: null };
  const hex = () => crypto.randomBytes(16).toString('hex');
  const option = (premiumCollectedBy, premiumAmount) => ({
    quoteId: `insq_${hex()}`,
    insuranceType: 'TICKET_CANCELLATION',
    schemaVersion: 1,
    premiumAmount,
    currency: 'TRY',
    premiumCollectedBy,
    terms: { version: `v${issued.quotes.length + 1}`, sha256: crypto.randomBytes(32).toString('hex') },
    status: 'QUOTED',
    paymentIntentId: null,
  });
  if (method === 'POST' && route === '/quotes') {
    // A quote on a payment's recorded basket names the payment in its options.
    const paymentIntentId = JSON.parse(raw).paymentIntentId || null;
    const options = [option('PROVIDER', 3900), option('MERCHANT', INSURANCE_SAMPLE_PREMIUM)].map((entry) => ({ ...entry, paymentIntentId }));
    issued.quotes.push(options[1]);
    return { status: 201, data: { insuranceType: 'TICKET_CANCELLATION', schemaVersion: 1, options } };
  }
  if (method === 'POST' && route === '/orders') {
    const order = {
      orderId: `inso_${hex()}`,
      quoteId: JSON.parse(raw).quoteId,
      insuranceType: 'TICKET_CANCELLATION',
      surface: 'MERCHANT_API',
      status: 'CREATED',
      paymentMode: 'NO_PAYMENT',
      premiumCollectedBy: 'MERCHANT',
      premiumAmount: INSURANCE_SAMPLE_PREMIUM + issued.orders.length * 100,
      currency: 'TRY',
      paymentIntentId: null,
      policies: [],
    };
    issued.orders.push(order);
    return { status: 201, data: order };
  }
  if (method === 'POST' && route === '/leads') {
    // A lead answers with its own fresh id, so a read that does not pick it up is caught.
    const body = JSON.parse(raw);
    const lead = {
      leadId: `insl_${hex()}`,
      insuranceType: body.insuranceType,
      schemaVersion: 1,
      status: 'SUBMITTED',
      errorCode: null,
      requestMasked: {},
      submittedAt: new Date().toISOString(),
    };
    issued.leads.push(lead);
    return { status: 201, data: lead };
  }
  if (method === 'GET' && /^\/leads\/[^/]+$/.test(route)) {
    return { status: 200, data: issued.leads.find((lead) => route.endsWith(`/${lead.leadId}`)) || {} };
  }
  const orderRoute = /^\/orders\/([^/]+)(?:\/[a-z-]+)?$/.exec(route);
  if (orderRoute) {
    // Any later read or action answers the order with an issued policy, so the document
    // request has a policy to use. The order carries the payment as `paymentIntentId`.
    const order = issued.orders.find((candidate) => candidate.orderId === orderRoute[1]) || { orderId: orderRoute[1] };
    return { status: 200, data: {
      ...order,
      paymentIntentId: '40000000-0000-4000-8000-000000000001',
      policyStatus: 'ISSUED',
      policies: [{ policyId: INSURANCE_IDS.policy, basketItemId: 'ticket-1', policyNumber: 'POL-LOCK', policyStatus: 'ISSUED', documentStatus: 'AVAILABLE' }],
    } };
  }
  if (method === 'GET' && route === '/reference/CITY') {
    return { status: 200, data: { items: [{ code: INSURANCE_IDS.cityCode, label: { tr: 'İzmir', en: 'Izmir' }, parentCode: null }] }, pageInfo: lastPage };
  }
  if (method === 'GET' && (route === '/orders' || route === '/reconciliation/orders' || route === '/leads' || route.startsWith('/reference/'))) {
    return { status: 200, data: { items: [] }, pageInfo: lastPage };
  }
  return { status: 200, data: {} };
}
// Values a user has before running the folder. The chained ones differ from what the
// stand-in answers, so a request that does not pick up the chained value is caught. The
// amounts are valid numbers so every body is valid JSON before anything is chained.
const INSURANCE_ENVIRONMENT = {
  insurance_type: 'TICKET_CANCELLATION',
  insurance_merchant_order_id: 'postman-insurance-001',
  insurance_ticket_item_id: 'ticket-1',
  insurance_ticket_price_minor: '100000',
  insurance_departure_at: '2027-06-15T09:30:00+03:00',
  insurance_insured_identity_type: 'TCKN',
  insurance_insured_identity_number: 'identity-lock',
  insurance_insured_birth_date: '1990-01-01',
  insurance_insured_email: 'insured@example.com',
  insurance_insured_phone: '+905320000001',
  insurance_ticket_pnr: 'PNRLOCK',
  insurance_ticket_number: 'TICKET-LOCK',
  insurance_city_code: '',
  insurance_quote_id: `insq_${'0'.repeat(32)}`,
  insurance_terms_version: 'stale',
  insurance_terms_sha256: '0'.repeat(64),
  insurance_order_id: `inso_${'0'.repeat(32)}`,
  insurance_premium_amount: '1',
  insurance_payment_amount: '1',
  insurance_policy_id: '',
  insurance_period_from: '2026-10-01T00:00:00Z',
  insurance_period_to: '2026-11-01T00:00:00Z',
  insurance_lead_type: 'MOTOR_THIRD_PARTY_LIABILITY',
  insurance_vehicle_plate: 'PLATE-LOCK',
  insurance_vehicle_registration_serial: 'SERIAL-LOCK',
  insurance_vehicle_registration_number: 'NUMBER-LOCK',
  insurance_lead_id: `insl_${'0'.repeat(32)}`,
};

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
    method_gsm_number: '+905320000001',
    method_wallet_provider_code: 'PAYCELL_WALLET',
    method_mobile_billing_provider_code: 'PAYCELL_MOBILE_BILLING',
    split_order_id: 'split-lock-0001',
    split_second_card_token: 'sc_lock_2',
    split_payment_id: 'split-stale',
    split_leg_payment_id: 'leg-stale',
    split_leg_action_id: 'act_stale_leg',
    payment_action_id: 'act_stale',
    payment_action_redirect_url: '',
    payment_otp: '123456',
    promissory_note_due_date_1: '2030-01-15',
    promissory_note_due_date_2: '2030-02-15',
    promissory_note_count: '3',
    promissory_note_province_code: '06',
    promissory_note_district_code: '1001',
    promissory_note_neighborhood_code: '2001',
    promissory_note_serial_number: 'NOTE-STALE-0000',
    ...WALLET_ENVIRONMENT,
    ...BANK_ENVIRONMENT,
    ...BANK_TRANSFER_ENVIRONMENT,
    ...SANCTION_ENVIRONMENT,
    ...INSURANCE_ENVIRONMENT,
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

// --- Bank Accounts folder ---------------------------------------------------------------

// The query fields the gateway DTOs accept (forbidNonWhitelisted), from the SDK, so the
// collection and the SDKs cannot drift apart. No route takes a body.
const { BANK_CONNECT_FILTERS } = require('../../node/src/bank-connect/bank-connect-values');
const BANK_ROUTE_FILTERS = {
  'GET /api/v1/bank-connect/banks': BANK_CONNECT_FILTERS.listBanks,
  'GET /api/v1/bank-connect/connections': BANK_CONNECT_FILTERS.listConnections,
  'GET /api/v1/bank-connect/connections/:id': [],
  'GET /api/v1/bank-connect/accounts': BANK_CONNECT_FILTERS.listAccounts,
  'GET /api/v1/bank-connect/accounts/:id': [],
  'GET /api/v1/bank-connect/balances': BANK_CONNECT_FILTERS.listBalances,
  'GET /api/v1/bank-connect/transactions': BANK_CONNECT_FILTERS.listTransactions,
  'GET /api/v1/bank-connect/transactions/:id': [],
  'POST /api/v1/bank-connect/accounts/:id/sync': [],
};

function bankRoute(hit) {
  const pathOnly = hit.url.split('?')[0]
    .replace(/^(\/api\/v1\/bank-connect\/(?:connections|accounts|transactions))\/[^/]+/, '$1/:id');
  return `${hit.method} ${pathOnly}`;
}

function bankAccountsFolder(collection) {
  const folder = collection.item.find((node) => node.name === 'Bank Accounts');
  assert.ok(folder, 'the collection has a Bank Accounts folder');
  return folder;
}

test('the Bank Accounts folder is the same in both payment collections', () => {
  const [standalone, localSigner] = ['standalone', 'local-signer'].map((profile) => bankAccountsFolder(loadCollection(profile)));
  assert.deepEqual(localSigner, standalone);
});

test('every bank variable the folder uses is declared in both environment templates', () => {
  const used = new Set(JSON.stringify(bankAccountsFolder(loadCollection('standalone'))).match(/\{\{bank_[a-z_]+\}\}/g).map((token) => token.slice(2, -2)));
  assert.deepEqual([...used].sort(), Object.keys(BANK_ENVIRONMENT).sort());
  for (const template of Object.values(ENVIRONMENT_TEMPLATES)) {
    const declared = new Set(JSON.parse(fs.readFileSync(path.join(POSTMAN_DIR, template), 'utf8')).values.map((v) => v.key));
    for (const name of used) assert.ok(declared.has(name), `${template} declares ${name}`);
  }
});

test('the Bank Accounts example responses are fake, masked and in the gateway envelope', () => {
  const folder = bankAccountsFolder(loadCollection('standalone'));
  for (const item of folder.item) {
    assert.ok(item.response.length > 0, `${item.name} has an example response`);
    for (const example of item.response) {
      const where = `${item.name} › ${example.name}`;
      const body = JSON.parse(example.body);
      assert.equal(body.statusCode, example.code, where);
      if (example.code < 300) {
        assert.equal(body.status, 'success', where);
        assert.ok(body.data && typeof body.data === 'object', where);
      } else {
        assert.equal(body.status, 'failure', where);
        assert.match(body.code, /^(bank_connect\.[a-z_]+\.[a-z_]+|RATE_LIMITED)$/, where);
      }
      // A TR IBAN appears only masked; no provider, owner or holder field.
      assert.doesNotMatch(example.body, /TR\d{24}/, `${where} carries an unmasked IBAN`);
      assert.doesNotMatch(example.body, /providerCode|ownerId|holderName|"iban"/, where);
    }
  }
});

for (const profile of ['standalone', 'local-signer']) {
  test(`${profile}: Bank Accounts requests are signed, body-less, whitelisted and chained`, async () => {
    const { gateway, environment, teardown } = await setUp(profile);
    try {
      const collection = loadCollection(profile);
      const folder = bankAccountsFolder(collection);
      const tests = [];
      for (const item of folder.item) tests.push(...(await runItem(collection, { item, trail: [folder] }, environment)).tests);

      const hits = gateway.received;
      assert.equal(hits.length, folder.item.length, 'every request of the folder reached the stand-in');
      assert.deepEqual(hits.map(bankRoute).sort(), Object.keys(BANK_ROUTE_FILTERS).sort(), 'one request per bank-connect route');
      for (const hit of hits) {
        const route = bankRoute(hit);
        assert.equal(hit.verdict, 'OK', `${route}: the API-key signature must verify`);
        assert.equal(hit.raw, '', `${route}: no body`);
        assert.equal(hit.idempotencyKey, undefined, `${route}: no Idempotency-Key`);
        const query = new URL(hit.url, 'http://stand-in').searchParams;
        const unknown = [...query.keys()].filter((key) => !BANK_ROUTE_FILTERS[route].includes(key));
        assert.deepEqual(unknown, [], `${route}: query fields the gateway would reject with 400`);
        for (const [key, value] of query) assert.notEqual(value, '', `${route}: ${key} is sent empty`);
      }

      // The ids the list answers carry are used by the requests after them.
      assert.ok(hits.some((hit) => hit.url === `/api/v1/bank-connect/connections/${BANK_IDS.connection}`), 'Get Connection uses the listed connection');
      assert.ok(hits.some((hit) => hit.url === `/api/v1/bank-connect/accounts/${BANK_IDS.account}`), 'Get Account uses the listed account');
      assert.ok(hits.some((hit) => hit.url === `/api/v1/bank-connect/accounts/${BANK_IDS.account}/sync`), 'the sync request uses the listed account');
      assert.ok(hits.some((hit) => hit.url === `/api/v1/bank-connect/transactions/${BANK_IDS.transaction}`), 'Get Transaction uses the listed transaction');
      const transactions = hits.find((hit) => bankRoute(hit) === 'GET /api/v1/bank-connect/transactions');
      const window = new URL(transactions.url, 'http://stand-in').searchParams;
      const days = (Date.parse(window.get('bookedTo')) - Date.parse(window.get('bookedFrom'))) / 86400000;
      assert.ok(days > 0 && days <= 92, `the default window is within 92 days (${days})`);
      assert.deepEqual(tests.filter((t) => t.error), [], "the folder's own assertions pass");
    } finally {
      await teardown();
    }
  });

  test(`${profile}: a pinned bank id is kept and bank answers leave payment_id alone`, () => {
    const collection = loadCollection(profile);
    const folder = bankAccountsFolder(collection);
    const runTests = (url, envelope, values) => {
      const environment = createEnvironment({ payment_id: 'pi_original', ...values });
      const pm = {
        test() {},
        environment: { get: (k) => environment.store.get(k), set: (k, v) => environment.store.set(k, v) },
        request: { url: { toString: () => url } },
        response: { code: 200, json: () => envelope },
      };
      for (const node of [collection, folder]) {
        // eslint-disable-next-line no-new-func
        new Function(...SANDBOX_GLOBALS, scriptOf(node, 'test'))(...SANDBOX_GLOBALS.map((name) => (name === 'pm' ? pm : undefined)));
      }
      return environment.store;
    };
    const page = { data: { items: [{ accountId: 'acc_listed', connectionId: 'conn_listed' }] } };
    const pinned = runTests('https://api-gateway.lunixi.com/api/v1/bank-connect/accounts?limit=20', page, { bank_account_id: 'acc_pinned' });
    assert.equal(pinned.get('bank_account_id'), 'acc_pinned', 'a value set by the user is not overwritten');
    const filled = runTests('https://api-gateway.lunixi.com/api/v1/bank-connect/accounts?limit=20', page, { bank_account_id: '' });
    assert.equal(filled.get('bank_account_id'), 'acc_listed');
    assert.equal(filled.get('payment_id'), 'pi_original', 'a bank answer is not a payment');
    const detail = runTests('https://api-gateway.lunixi.com/api/v1/bank-connect/accounts/acc_pinned', { data: { accountId: 'acc_pinned' } }, { bank_connection_id: '' });
    assert.equal(detail.get('bank_connection_id'), '', 'a detail answer fills nothing');
  });
}

// --- Bank Transfers folder -------------------------------------------------------------

// Routes, body fields, query fields and the Idempotency-Key rule come from the Node SDK
// (BANK_TRANSFER_ROUTES), so the collection and the SDKs cannot drift apart.
const { BANK_TRANSFER_ROUTES } = require('../../node/src/bank-connect/bank-connect-values');

function bankTransferFolder(collection) {
  const folder = collection.item.find((node) => node.name === 'Bank Transfers');
  assert.ok(folder, 'the collection has a Bank Transfers folder');
  return folder;
}

function transferRouteOf(hit) {
  const pathOnly = hit.url.split('?')[0];
  const name = Object.keys(BANK_TRANSFER_ROUTES).find((routeName) => {
    const route = BANK_TRANSFER_ROUTES[routeName];
    return route.method === hit.method && new RegExp(`^${route.path.replace(/:[A-Za-z]+/g, '[^/]+')}$`).test(pathOnly);
  });
  assert.ok(name, `${hit.method} ${pathOnly} is a BANK_TRANSFER_ROUTES route`);
  return name;
}

test('the Bank Transfers folder is the same in both payment collections', () => {
  const [standalone, localSigner] = ['standalone', 'local-signer'].map((profile) => bankTransferFolder(loadCollection(profile)));
  assert.deepEqual(localSigner, standalone);
});

test('every variable the Bank Transfers folder uses is declared in both environment templates', () => {
  const used = new Set(JSON.stringify(bankTransferFolder(loadCollection('standalone'))).match(/\{\{bank_[a-z_]+\}\}/g).map((token) => token.slice(2, -2)));
  for (const template of Object.values(ENVIRONMENT_TEMPLATES)) {
    const declared = new Set(JSON.parse(fs.readFileSync(path.join(POSTMAN_DIR, template), 'utf8')).values.map((v) => v.key));
    for (const name of used) assert.ok(declared.has(name), `${template} declares ${name}`);
  }
});

test('the Bank Transfers example responses are fake, masked and in the gateway envelope', () => {
  const folder = bankTransferFolder(loadCollection('standalone'));
  for (const item of folder.item) {
    assert.ok(item.response.length > 0, `${item.name} has an example response`);
    for (const example of item.response) {
      const where = `${item.name} › ${example.name}`;
      const body = JSON.parse(example.body);
      assert.equal(body.statusCode, example.code, where);
      if (example.code < 300) {
        assert.equal(body.status, 'success', where);
        assert.ok(body.data && typeof body.data === 'object', where);
      } else {
        assert.equal(body.status, 'failure', where);
        assert.match(body.code, /^(bank_connect\.[a-z_]+\.[a-z_]+|RATE_LIMITED)$/, where);
      }
      assert.doesNotMatch(example.body, /TR\d{24}/, `${where} carries an unmasked IBAN`);
      assert.doesNotMatch(example.body, /providerCode|ownerId|holderName|"iban"|"receiverIban"/, where);
    }
  }
});

for (const profile of ['standalone', 'local-signer']) {
  test(`${profile}: Bank Transfers requests are signed, keyed, whitelisted and chained`, async () => {
    const { gateway, environment, teardown } = await setUp(profile);
    try {
      environment.store.set('bank_connection_id', BANK_IDS.connection);
      environment.store.set('bank_account_id', BANK_IDS.account);
      const collection = loadCollection(profile);
      const folder = bankTransferFolder(collection);
      const tests = [];
      for (const item of folder.item) tests.push(...(await runItem(collection, { item, trail: [folder] }, environment)).tests);

      const hits = gateway.received;
      assert.equal(hits.length, folder.item.length, 'every request of the folder reached the stand-in');
      assert.deepEqual(hits.map(transferRouteOf).sort(), Object.keys(BANK_TRANSFER_ROUTES).sort(), 'one request per transfer route');
      for (const hit of hits) {
        const name = transferRouteOf(hit);
        const route = BANK_TRANSFER_ROUTES[name];
        assert.equal(hit.verdict, 'OK', `${name}: the API-key signature must verify`);
        if (route.idempotencyKey) assert.match(hit.idempotencyKey || '', /^[\x21-\x7E]{8,200}$/, `${name}: Idempotency-Key`);
        else assert.equal(hit.idempotencyKey, undefined, `${name}: no Idempotency-Key`);
        const query = new URL(hit.url, 'http://stand-in').searchParams;
        const unknown = [...query.keys()].filter((key) => !(route.query || []).includes(key));
        assert.deepEqual(unknown, [], `${name}: query fields the gateway would reject with 400`);
        for (const [key, value] of query) assert.notEqual(value, '', `${name}: ${key} is sent empty`);
        if (route.method === 'GET') {
          assert.equal(hit.raw, '', `${name}: no body`);
          continue;
        }
        const body = JSON.parse(hit.raw);
        const allowed = [...route.required, ...route.optional];
        assert.deepEqual(Object.keys(body).filter((key) => !allowed.includes(key)), [], `${name}: body fields the gateway would reject with 400`);
        assert.deepEqual(route.required.filter((key) => body[key] === undefined || body[key] === ''), [], `${name}: required body fields`);
        assert.doesNotMatch(hit.raw, /\{\{/, `${name}: every variable is resolved`);
        for (const key of ['amountMinor', 'sourceAmountMinor', 'targetAmountMinor']) {
          if (body[key] !== undefined) assert.ok(Number.isSafeInteger(body[key]) && body[key] > 0, `${name}: ${key} is a positive integer`);
        }
        if (name === 'createFxQuote') {
          assert.equal((body.sourceAmountMinor === undefined) !== (body.targetAmountMinor === undefined), true, 'exactly one quote amount');
        }
      }

      // The ids the create answers carry are used by the requests after them.
      assert.ok(hits.some((hit) => hit.url === `/api/v1/bank-connect/transfers/${BANK_IDS.transfer}`), 'Get Transfer uses the created transfer');
      assert.ok(hits.some((hit) => hit.method === 'POST' && hit.url === '/api/v1/bank-connect/fx/orders' && JSON.parse(hit.raw).quoteId === BANK_IDS.quote), 'Create FX Order uses the quote');
      assert.ok(hits.some((hit) => hit.url === `/api/v1/bank-connect/fx/orders/${BANK_IDS.order}`), 'Get FX Order uses the created order');
      assert.ok(hits.some((hit) => hit.url === `/api/v1/bank-connect/transfer-purposes?connectionId=${BANK_IDS.connection}`), 'purposes use the listed connection');
      assert.equal(environment.store.get('payment_id'), '3f1c2a9e-5b7d-4c1e-9a2b-6d8e0f1a2b3c', 'a transfer, quote or order id is not a payment');
      assert.deepEqual(tests.filter((t) => t.error), [], "the folder's own assertions pass");
    } finally {
      await teardown();
    }
  });
}

// --- Sanction folder ------------------------------------------------------------------

// The routes, body fields, nested fields and value sets are the Node SDK's (gateway
// sanction.controller.ts + sanction.proto), so the collection and the SDKs cannot drift apart.
const { SANCTION_ROUTES, SANCTION_NESTED_FIELDS, SANCTION_VALUE_SETS } = require('../../node/src/sanction/sanction-values');

function sanctionFolder(collection) {
  const folder = collection.item.find((node) => node.name === 'Sanction');
  assert.ok(folder, 'the collection has a Sanction folder');
  return folder;
}

function sanctionRouteOf(method, pathOnly) {
  const names = Object.keys(SANCTION_ROUTES).filter((routeName) => {
    const route = SANCTION_ROUTES[routeName];
    return route.method === method && new RegExp(`^${route.path.replace(/:[A-Za-z]+/g, '[^/]+')}$`).test(pathOnly);
  });
  assert.equal(names.length, 1, `${method} ${pathOnly} is exactly one SANCTION_ROUTES route`);
  return names[0];
}

function checkSanctionBody(routeName, body) {
  const route = SANCTION_ROUTES[routeName];
  const allowed = [...(route.required || []), ...(route.optional || [])];
  assert.deepEqual(Object.keys(body).filter((key) => !allowed.includes(key)), [], `${routeName}: body fields the route does not take`);
  assert.deepEqual((route.required || []).filter((key) => body[key] === undefined || body[key] === ''), [], `${routeName}: required body fields`);
  if (route.anyOf) {
    assert.ok(route.anyOf.some((key) => body[key] !== undefined && body[key] !== '' && !(Array.isArray(body[key]) && body[key].length === 0)), `${routeName}: one of ${route.anyOf}`);
  }
  for (const [key, value] of Object.entries(body)) {
    const nested = SANCTION_NESTED_FIELDS[`${routeName}.${key}`];
    if (nested) {
      assert.ok(Array.isArray(value), `${routeName}.${key} is a list`);
      value.forEach((row, index) => {
        const rowAllowed = [...nested.required, ...nested.optional];
        assert.deepEqual(Object.keys(row).filter((field) => !rowAllowed.includes(field)), [], `${routeName}.${key}[${index}]: fields`);
        assert.deepEqual(nested.required.filter((field) => row[field] === undefined || row[field] === ''), [], `${routeName}.${key}[${index}]: required fields`);
      });
    }
    const values = SANCTION_VALUE_SETS[`${routeName}.${key}`];
    if (values) {
      for (const entry of Array.isArray(value) ? value : [value]) assert.ok(values.includes(entry), `${routeName}.${key}: ${entry} is one of ${values}`);
    }
  }
}

test('the Sanction folder is the same in both payment collections', () => {
  const [standalone, localSigner] = ['standalone', 'local-signer'].map((profile) => sanctionFolder(loadCollection(profile)));
  assert.equal(JSON.stringify(localSigner), JSON.stringify(standalone), 'write the folder once, insert it into both collections');
});

test('every variable the Sanction folder uses is declared in both environment templates', () => {
  const used = new Set(JSON.stringify(sanctionFolder(loadCollection('standalone'))).match(/\{\{sanction_[a-z_]+\}\}/g).map((token) => token.slice(2, -2)));
  assert.deepEqual([...used].sort(), ['sanction_entity_id', 'sanction_screening_request_id']);
  for (const template of Object.values(ENVIRONMENT_TEMPLATES)) {
    const declared = new Set(JSON.parse(fs.readFileSync(path.join(POSTMAN_DIR, template), 'utf8')).values.map((v) => v.key));
    for (const name of used) assert.ok(declared.has(name), `${template} declares ${name}`);
  }
});

test('the Sanction folder has one request per route and envelope examples with sanction codes', () => {
  const folder = sanctionFolder(loadCollection('standalone'));
  const routes = folder.item.map((item) => sanctionRouteOf(item.request.method, createRequest(item).url.replace(/^\{\{base_url\}\}/, '').split('?')[0]));
  assert.deepEqual([...routes].sort(), Object.keys(SANCTION_ROUTES).sort(), 'every route once, no extras');
  assert.ok(!JSON.stringify(folder).includes('/report'), 'the screening report PDF is panel-session only');
  for (const item of folder.item) {
    assert.ok(item.response.length > 0, `${item.name} has an example response`);
    assert.ok(scriptOf(item, 'test'), `${item.name}: has a 2xx test`);
    assert.equal((item.request.header || []).some((h) => h.key.toLowerCase() === 'idempotency-key'), false, `${item.name}: no Idempotency-Key`);
    for (const example of item.response) {
      const where = `${item.name} › ${example.name}`;
      const body = JSON.parse(example.body);
      assert.equal(body.statusCode, example.code, where);
      assert.match(body.code, /^sanction\.[a-z_.]+$/, where);
      if (example.code < 300) {
        assert.equal(body.status, 'success', where);
        assert.ok(body.data && typeof body.data === 'object', where);
        assert.equal(Object.prototype.hasOwnProperty.call(body.data, 'requestId'), false, `${where}: the screening id travels as screeningRequestId`);
      } else {
        assert.equal(body.status, 'failure', where);
        assert.equal(body.data, undefined, where);
      }
    }
  }
});

for (const profile of ['standalone', 'local-signer']) {
  test(`${profile}: Sanction requests carry the token, take only route fields and are chained`, async () => {
    const { gateway, environment, teardown } = await setUp(profile);
    try {
      const collection = loadCollection(profile);
      const folder = sanctionFolder(collection);
      const tests = [];
      for (const item of folder.item) tests.push(...(await runItem(collection, { item, trail: [folder] }, environment)).tests);

      const hits = gateway.received;
      assert.equal(hits.length, folder.item.length, 'every request of the folder reached the stand-in');
      for (const hit of hits) {
        const pathOnly = hit.url.split('?')[0];
        const name = sanctionRouteOf(hit.method, pathOnly);
        const route = SANCTION_ROUTES[name];
        assert.ok(hit.bearer, `${name}: carries the minted access token`);
        assert.equal(hit.idempotencyKey, undefined, `${name}: no Idempotency-Key`);
        const query = new URL(hit.url, 'http://stand-in').searchParams;
        assert.deepEqual([...query.keys()].filter((key) => !(route.query || []).includes(key)), [], `${name}: query fields the route does not take`);
        for (const [key, value] of query) assert.notEqual(value, '', `${name}: ${key} is sent empty`);
        assert.doesNotMatch(hit.url, /\{\{|\/\//, `${name}: every path variable is resolved`);
        if (route.method === 'GET') {
          assert.equal(hit.raw, '', `${name}: no body`);
          continue;
        }
        assert.doesNotMatch(hit.raw, /\{\{/, `${name}: every variable is resolved`);
        checkSanctionBody(name, JSON.parse(hit.raw));
      }

      // The entity requests read the entity the name screening matched (not the later search
      // result) and the profile is read on that screening's publication.
      assert.ok(hits.some((hit) => hit.url === `/api/v1/sanction/intelligence/entity-profiles/${SANCTION_IDS.matched}?screeningRequestId=${SANCTION_IDS.screening}`), 'Get Entity Profile uses the chained ids');
      for (const route of ['entity-graph', 'indirect-exposure', 'ownership-aggregation']) {
        assert.ok(hits.some((hit) => hit.url.startsWith(`/api/v1/sanction/intelligence/${route}/${SANCTION_IDS.matched}?`)), `${route} uses the matched entity`);
      }
      assert.equal(environment.store.get('sanction_entity_id'), SANCTION_IDS.matched, 'the search does not replace a filled entity id');
      assert.equal(environment.store.get('payment_id'), '3f1c2a9e-5b7d-4c1e-9a2b-6d8e0f1a2b3c', 'a sanction id is not a payment');
      assert.deepEqual(tests.filter((t) => t.error), [], "the folder's own assertions pass");
    } finally {
      await teardown();
    }
  });

  test(`${profile}: a pinned sanction_entity_id is kept`, async () => {
    const { gateway, environment, teardown } = await setUp(profile);
    try {
      environment.store.set('sanction_entity_id', SANCTION_IDS.pinned);
      const collection = loadCollection(profile);
      const folder = sanctionFolder(collection);
      for (const item of folder.item) await runItem(collection, { item, trail: [folder] }, environment);
      assert.equal(environment.store.get('sanction_entity_id'), SANCTION_IDS.pinned);
      assert.ok(gateway.received.some((hit) => hit.url.startsWith(`/api/v1/sanction/intelligence/entity-graph/${SANCTION_IDS.pinned}?`)), 'the pinned entity is read');
    } finally {
      await teardown();
    }
  });
}

// --- Payment Methods folder -----------------------------------------------------------

// The body fields of POST /payments/direct/payment and of the confirm endpoint are the
// Node SDK's (gateway DirectMethodPaymentDto / ConfirmPaymentActionDto, forbidNonWhitelisted),
// so the collection and the SDKs cannot drift apart.
const {
  DIRECT_METHOD_PAYMENT_FIELDS,
  METHOD_BLOCK_FIELDS,
  CARD_ONLY_FIELDS,
  PAYMENT_ACTION_CONFIRM_FIELDS,
  blockNameOf,
} = require('../../node/src/payment/payment-method-values');
const { REMOVED_AMOUNT_FIELDS } = require('../../node/src/payment/dto');

function paymentMethodsFolder(collection) {
  const folder = collection.item.find((node) => node.name === 'Payment Methods');
  assert.ok(folder, 'the collection has a Payment Methods folder');
  return folder;
}

function methodRoute(hit) {
  return `${hit.method} ${hit.url.split('?')[0].replace(/\/payments\/[^/]+\/actions\/[^/]+\//, '/payments/:id/actions/:actionId/')}`;
}

function checkDirectMethodBody(body, label) {
  assert.deepEqual(Object.keys(body).filter((key) => !DIRECT_METHOD_PAYMENT_FIELDS.includes(key)), [], `${label}: fields the gateway would reject with 400`);
  for (const field of ['paymentMethod', 'amount', 'currency', 'orderId']) {
    assert.notEqual(body[field], undefined, `${label}: ${field} is required`);
  }
  assert.ok(Number.isSafeInteger(body.amount) && body.amount >= 1, `${label}: amount is an integer in minor units`);
  assert.deepEqual(REMOVED_AMOUNT_FIELDS.filter((field) => body[field] !== undefined), [], `${label}: price / paidPrice were removed`);
  const own = blockNameOf(body.paymentMethod);
  assert.ok(body[own] && typeof body[own] === 'object', `${label}: the ${own} block is present`);
  assert.deepEqual([...METHOD_BLOCK_FIELDS, 'card'].filter((block) => block !== own && body[block] !== undefined), [], `${label}: only the method's own block`);
  if (body.paymentMethod !== 'CARD') {
    assert.deepEqual(CARD_ONLY_FIELDS.filter((field) => body[field] !== undefined), [], `${label}: card-only fields`);
  }
  for (const flag of ['preauth', 'force3D']) {
    if (body[flag] !== undefined) assert.equal(typeof body[flag], 'boolean', `${label}: ${flag} is a JSON boolean`);
  }
}

test('the Payment Methods folder is the same in both payment collections', () => {
  const [standalone, localSigner] = ['standalone', 'local-signer'].map((profile) => paymentMethodsFolder(loadCollection(profile)));
  assert.equal(JSON.stringify(localSigner), JSON.stringify(standalone), 'write the folder once, insert it into both collections');
});

test('every variable the Payment Methods folder uses is declared in both environment templates', () => {
  const folder = JSON.stringify(paymentMethodsFolder(loadCollection('standalone')));
  const used = new Set(folder.match(/\{\{(?:method|payment)_[a-z_]+\}\}/g).map((token) => token.slice(2, -2)));
  used.add('payment_action_redirect_url');
  for (const [profile, file] of Object.entries(ENVIRONMENT_TEMPLATES)) {
    const declared = JSON.parse(fs.readFileSync(path.join(POSTMAN_DIR, file), 'utf8')).values;
    const names = new Set(declared.map((variable) => variable.key));
    assert.deepEqual([...used].filter((name) => !names.has(name)), [], `${profile} template`);
    assert.equal(declared.find((variable) => variable.key === 'payment_otp').type, 'secret', `${profile}: payment_otp is a secret`);
  }
});

test('pre-authorization examples use the typed preauth field; nothing sends metadata.autoCapture', () => {
  for (const profile of ['standalone', 'local-signer']) {
    const collection = loadCollection(profile);
    const entries = requestItems(collection.item);
    for (const name of ['Create Checkout Intent (Pre-authorization)', 'Direct Payment - Card Pre-authorization']) {
      const entry = entries.find((e) => e.item.name === name);
      assert.ok(entry, `${profile}: ${name} exists`);
      const body = JSON.parse(entry.item.request.body.raw.replace(/\{\{[^{}]+\}\}/g, '1'));
      assert.equal(body.preauth, true, `${profile}: ${name} sends preauth: true`);
    }
    assert.doesNotMatch(JSON.stringify(collection), /autoCapture/, `${profile}: no request uses metadata.autoCapture`);
  }
});

// K17: `amount` is the only amount field of the checkout, marketplace and direct/payment
// bodies; `price` / `paidPrice` get 400 payment.amount.field_removed.
const AMOUNT_BODY_ROUTE = /\/api\/v1\/payments\/(?:intents|marketplace\/(?:intents|2d|3d)|direct\/payment)$/;
const SAMPLE_AMOUNT = 10050;

test('every payment body sends amount equal to its basket total and no removed amount field', () => {
  for (const profile of ['standalone', 'local-signer']) {
    const checked = new Set();
    for (const { item } of requestItems(loadCollection(profile).item)) {
      const url = typeof item.request.url === 'string' ? item.request.url : item.request.url.raw;
      const route = url.split('?')[0].replace(/^\{\{base_url\}\}/, '');
      if (item.request.method !== 'POST' || !AMOUNT_BODY_ROUTE.test(route)) continue;
      const label = `${profile}: ${item.name}`;
      // The insured checkout carries the ticket and the premium: its amount is the sum the
      // insurance order chained into insurance_payment_amount.
      const insured = /\{\{insurance_payment_amount\}\}/.test(item.request.body.raw);
      const ticketPrice = Number(INSURANCE_ENVIRONMENT.insurance_ticket_price_minor);
      const raw = item.request.body.raw
        .replace(/\{\{amount_minor\}\}/g, String(SAMPLE_AMOUNT))
        .replace(/\{\{insurance_ticket_price_minor\}\}/g, String(ticketPrice))
        .replace(/\{\{insurance_premium_amount\}\}/g, String(INSURANCE_SAMPLE_PREMIUM))
        .replace(/\{\{insurance_payment_amount\}\}/g, String(ticketPrice + INSURANCE_SAMPLE_PREMIUM))
        .replace(/\{\{[^{}]+\}\}/g, '1');
      const body = JSON.parse(raw);
      const schedule = body.promissoryNote && Array.isArray(body.promissoryNote.schedule) ? body.promissoryNote.schedule : null;
      if (schedule) {
        // A promissory-note schedule carries literal note amounts; amount is their total.
        assert.ok(Number.isSafeInteger(body.amount) && body.amount >= 1, `${label}: amount is an integer in minor units`);
        assert.equal(schedule.reduce((sum, row) => sum + row.amount, 0), body.amount, `${label}: the schedule adds up to amount`);
      } else if (insured) {
        assert.equal(body.amount, ticketPrice + INSURANCE_SAMPLE_PREMIUM, `${label}: amount is {{insurance_payment_amount}}, an integer`);
      } else {
        assert.equal(body.amount, SAMPLE_AMOUNT, `${label}: amount is {{amount_minor}}, an integer`);
      }
      assert.deepEqual(REMOVED_AMOUNT_FIELDS.filter((field) => body[field] !== undefined), [], `${label}: price / paidPrice were removed`);
      if (Array.isArray(body.basketItems) && body.basketItems.length > 0) {
        assert.equal(body.basketItems.reduce((sum, basketItem) => sum + basketItem.price, 0), body.amount, `${label}: basket total equals amount`);
      }
      if (Array.isArray(body.sellers)) {
        assert.equal(body.sellers.reduce((sum, seller) => sum + Number(seller.amountMinor), 0), body.amount, `${label}: seller legs add up to amount`);
      }
      checked.add(route);
    }
    // An empty match must not pass: the routes the collections are known to carry are checked.
    for (const route of ['/api/v1/payments/intents', '/api/v1/payments/direct/payment']) {
      assert.ok(checked.has(route), `${profile}: a ${route} body was checked`);
    }
  }
});

// The direct 2D/3D card endpoints were removed from the gateway: a card is paid from the
// server only through direct/payment (paymentMethod CARD, force3D for 3D Secure).
test('no payment request targets the removed direct 2D/3D card endpoints; cards go through direct/payment', () => {
  for (const profile of ['standalone', 'local-signer']) {
    const collection = loadCollection(profile);
    const entries = requestItems(collection.item);
    assert.ok(entries.length > 0, `${profile}: the collection has requests`);
    const removed = entries.filter(({ item }) => {
      const url = typeof item.request.url === 'string' ? item.request.url : item.request.url.raw;
      return /\/api\/v1\/payments\/direct\/(?:2d|3d)(?:[/?]|$)/.test(url);
    });
    assert.deepEqual(removed.map(({ item }) => item.name), [], `${profile}: requests on the removed endpoints`);
    assert.equal(collection.item.some((node) => node.name === 'Payments / Direct'), false, `${profile}: the Payments / Direct folder is gone`);

    const cards = paymentMethodsFolder(collection).item
      .filter((item) => item.request.method === 'POST' && /\/api\/v1\/payments\/direct\/payment$/.test(item.request.url))
      .map((item) => ({ name: item.name, body: JSON.parse(item.request.body.raw.replace(/\{\{[^{}]+\}\}/g, '1')) }))
      .filter(({ body }) => body.paymentMethod === 'CARD');
    assert.deepEqual(cards.map(({ name }) => name), [
      'Direct Payment - Card',
      'Direct Payment - Card (3D Secure)',
      'Direct Payment - Card Pre-authorization',
    ], `${profile}: card examples under direct/payment`);
    const [plain, secure, preauth] = cards.map(({ body }) => body);
    assert.equal(plain.force3D, undefined, `${profile}: the plain card example is without 3D Secure`);
    assert.equal(secure.force3D, true, `${profile}: the 3D Secure example sends force3D: true`);
    assert.equal(preauth.preauth, true, `${profile}: the pre-authorization example sends preauth: true`);
    for (const { name, body } of cards) {
      assert.ok(body.card && body.card.cardNumber, `${profile}: ${name} carries the card block`);
    }
  }
});

for (const profile of ['standalone', 'local-signer']) {
  test(`${profile}: Payment Methods requests are signed, keyed, whitelisted and chained`, async () => {
    const { gateway, environment, teardown } = await setUp(profile);
    try {
      const collection = loadCollection(profile);
      const folder = paymentMethodsFolder(collection);
      const tests = [];
      for (const item of folder.item) tests.push(...(await runItem(collection, { item, trail: [folder] }, environment)).tests);

      const hits = gateway.received;
      assert.equal(hits.length, folder.item.length, 'every request of the folder reached the stand-in once');
      assert.deepEqual(hits.map(methodRoute), [
        'GET /api/v1/payments/methods',
        'GET /api/v1/payments/methods',
        'POST /api/v1/payments/direct/payment',
        'POST /api/v1/payments/:id/actions/:actionId/resend',
        'POST /api/v1/payments/:id/actions/:actionId/confirm',
        'POST /api/v1/payments/direct/payment',
        'POST /api/v1/payments/direct/payment',
        'POST /api/v1/payments/direct/payment',
        'POST /api/v1/payments/direct/payment',
      ], 'run order: list, list one method, start, resend, confirm, then the other methods');
      for (const hit of hits) {
        const route = methodRoute(hit);
        assert.equal(hit.verdict, 'OK', `${route}: the API-key signature must verify`);
        assert.ok(hit.bearer, `${route}: carries the minted access token`);
        if (route === 'POST /api/v1/payments/direct/payment') {
          assert.ok(typeof hit.idempotencyKey === 'string' && hit.idempotencyKey.trim().length > 0 && hit.idempotencyKey.length <= 200, `${route}: Idempotency-Key is required`);
          checkDirectMethodBody(JSON.parse(hit.raw), route);
        } else {
          assert.equal(hit.idempotencyKey, undefined, `${route}: no Idempotency-Key`);
        }
      }
      assert.equal(hits[0].raw, '', 'the list is a read without a body');
      assert.equal(hits[0].url, '/api/v1/payments/methods', 'the full list carries no filter');
      assert.equal(hits[1].raw, '', 'the one-method list is a read without a body');
      assert.equal(hits[1].url, '/api/v1/payments/methods?paymentMethod=MOBILE_BILLING', 'the filter is sent as ?paymentMethod= and signed with the path');
      assert.equal(hits[3].raw, '', 'resend sends no body');
      const confirmBody = JSON.parse(hits[4].raw);
      assert.deepEqual(Object.keys(confirmBody).filter((key) => !PAYMENT_ACTION_CONFIRM_FIELDS.includes(key)), [], 'confirm: never token / checkoutSessionProof');
      assert.deepEqual(confirmBody, { otp: '123456' });
      assert.deepEqual(hits.slice(2).filter((hit) => hit.method === 'POST' && hit.url.endsWith('/direct/payment')).map((hit) => JSON.parse(hit.raw).paymentMethod),
        ['MOBILE_BILLING', 'WALLET', 'CARD', 'CARD', 'CARD']);

      // Chaining: resend targets the action the start opened, confirm the one resend opened.
      const [started, resent] = gateway.methodIssued;
      assert.equal(hits[3].url, `/api/v1/payments/${started.paymentId}/actions/${started.action.id}/resend`);
      assert.equal(hits[4].url, `/api/v1/payments/${resent.paymentId}/actions/${resent.action.id}/confirm`);
      const redirect = gateway.methodIssued.find((entry) => entry.action.type === 'REDIRECT');
      assert.equal(environment.store.get('payment_action_redirect_url'), redirect.action.redirect.url, 'the card 3D Secure page is chained');
      assert.deepEqual(tests.filter((t) => t.error), [], "the folder's own assertions pass");
      assert.equal(tests.filter((t) => / OTP action returned$/.test(t.name)).length, 2, 'start and resend are checked for an OTP action');
    } finally {
      await teardown();
    }
  });
}

// Faturana Yansıt: the example sends the provider chained from List Payment Methods; in
// the API it may be left out (PLATFORM), so the list chains it only when none is set.
test('the Faturana Yansıt example sends providerCode chained from List Payment Methods', async () => {
  for (const profile of ['standalone', 'local-signer']) {
    const folder = paymentMethodsFolder(loadCollection(profile));
    const example = folder.item.find((item) => item.name === 'Direct Payment - Faturana Yansıt');
    const body = JSON.parse(example.request.body.raw.replace(/\{\{amount_minor\}\}/g, '1'));
    assert.equal(body.mobileBilling.providerCode, '{{method_mobile_billing_provider_code}}', `${profile}: providerCode is sent`);
  }
  const { environment, teardown } = await setUp('standalone');
  try {
    const collection = loadCollection('standalone');
    const folder = paymentMethodsFolder(collection);
    const list = folder.item.find((item) => item.name === 'List Payment Methods');
    environment.store.set('method_mobile_billing_provider_code', '');
    await runItem(collection, { item: list, trail: [folder] }, environment);
    assert.equal(environment.store.get('method_mobile_billing_provider_code'), 'PAYCELL_MOBILE_BILLING', 'an empty provider is chained from the list');
    environment.store.set('method_mobile_billing_provider_code', 'PINNED_PROVIDER');
    await runItem(collection, { item: list, trail: [folder] }, environment);
    assert.equal(environment.store.get('method_mobile_billing_provider_code'), 'PINNED_PROVIDER', 'a provider you set is kept');
  } finally {
    await teardown();
  }
});

// --- Split Payments folder ----------------------------------------------------------------

// Body fields and leg rules of POST /payments/split are the Node SDK's (gateway
// SplitPaymentDto / SplitPaymentLegDto), so the collection and the SDKs cannot drift apart.
const {
  SPLIT_PAYMENT_FIELDS,
  SPLIT_PAYMENT_LEG_FIELDS,
  assertSplitPaymentPayload,
} = require('../../node/src/payment/split-payment-values');

function splitPaymentsFolder(collection) {
  const folder = collection.item.find((node) => node.name === 'Split Payments');
  assert.ok(folder, 'the collection has a Split Payments folder');
  return folder;
}

const SPLIT_SAMPLE_VALUES = {
  currency: 'TRY',
  card_user_key: 'postman-user-001',
  stored_card_token: 'sc_1',
  split_second_card_token: 'sc_2',
  method_mobile_billing_provider_code: 'PAYCELL_MOBILE_BILLING',
  method_gsm_number: '+905320000001',
};

test('the Split Payments folder is the same in both payment collections', () => {
  const [standalone, localSigner] = ['standalone', 'local-signer'].map((profile) => splitPaymentsFolder(loadCollection(profile)));
  assert.equal(JSON.stringify(localSigner), JSON.stringify(standalone), 'write the folder once, insert it into both collections');
});

test('every variable the Split Payments folder uses is declared in both environment templates', () => {
  const folder = JSON.stringify(splitPaymentsFolder(loadCollection('standalone')));
  const used = new Set(folder.match(/\{\{[a-z_]+\}\}/g).map((token) => token.slice(2, -2)));
  for (const [profile, file] of Object.entries(ENVIRONMENT_TEMPLATES)) {
    const names = new Set(JSON.parse(fs.readFileSync(path.join(POSTMAN_DIR, file), 'utf8')).values.map((variable) => variable.key));
    assert.deepEqual([...used].filter((name) => !names.has(name)), [], `${profile} template`);
    assert.notEqual(
      JSON.parse(fs.readFileSync(path.join(POSTMAN_DIR, file), 'utf8')).values.find((variable) => variable.key === 'split_order_id').value,
      '',
      `${profile}: split_order_id has a value, so the split Idempotency-Key is never empty`,
    );
  }
});

test('split payment bodies are whitelisted and follow the leg rules', () => {
  for (const profile of ['standalone', 'local-signer']) {
    const folder = splitPaymentsFolder(loadCollection(profile));
    const creates = folder.item.filter((item) => item.request.method === 'POST' && /\/api\/v1\/payments\/split$/.test(item.request.url));
    assert.deepEqual(creates.map((item) => item.name), [
      'Create Split Payment - Stored Cards',
      'Create Split Payment - Card and Faturana Yansıt',
      'Continue Split Payment',
    ], `${profile}: create and continue requests`);
    for (const item of creates) {
      const label = `${profile}: ${item.name}`;
      const raw = item.request.body.raw.replace(/\{\{([a-z_]+)\}\}/g, (match, name) => SPLIT_SAMPLE_VALUES[name] ?? `x-${name}`);
      const body = JSON.parse(raw);
      assert.deepEqual(Object.keys(body).filter((key) => !SPLIT_PAYMENT_FIELDS.includes(key)), [], `${label}: fields the gateway would reject`);
      for (const leg of body.legs) {
        assert.deepEqual(Object.keys(leg).filter((key) => !SPLIT_PAYMENT_LEG_FIELDS.includes(key)), [], `${label}: leg fields`);
      }
      assert.doesNotThrow(() => assertSplitPaymentPayload(body), label);
      const key = item.request.header.find((h) => h.key === 'Idempotency-Key');
      assert.ok(key && key.value.trim() !== '', `${label}: Idempotency-Key is required`);
    }
    const [, mixed, resume] = creates;
    assert.equal(resume.request.body.raw, mixed.request.body.raw, `${profile}: continue sends the same body`);
    assert.equal(
      resume.request.header.find((h) => h.key === 'Idempotency-Key').value,
      mixed.request.header.find((h) => h.key === 'Idempotency-Key').value,
      `${profile}: continue sends the same Idempotency-Key`,
    );
  }
});

for (const profile of ['standalone', 'local-signer']) {
  test(`${profile}: Split Payments requests are signed, keyed and chained`, async () => {
    const { gateway, environment, teardown } = await setUp(profile);
    try {
      const collection = loadCollection(profile);
      const folder = splitPaymentsFolder(collection);
      const tests = [];
      const paymentIds = [];
      for (const item of folder.item) {
        tests.push(...(await runItem(collection, { item, trail: [folder] }, environment)).tests);
        paymentIds.push(environment.store.get('payment_id'));
      }

      const hits = gateway.received;
      assert.equal(hits.length, folder.item.length, 'every request of the folder reached the stand-in once');
      const splitRoute = (hit) => `${hit.method} ${hit.url.split('?')[0]
        .replace(/\/payments\/[^/]+\/actions\/[^/]+\//, '/payments/:id/actions/:actionId/')
        .replace(/\/payments\/split\/[^/]+/, '/payments/split/:id')}`;
      assert.deepEqual(hits.map(splitRoute), [
        'POST /api/v1/payments/split',
        'POST /api/v1/payments/split',
        'POST /api/v1/payments/:id/actions/:actionId/confirm',
        'POST /api/v1/payments/split',
        'GET /api/v1/payments/split/:id',
        'GET /api/v1/payments/split',
        'POST /api/v1/payments/split/:id/refund',
      ], 'run order: two creates, confirm, continue, read, list, refund');
      for (const hit of hits) {
        assert.equal(hit.verdict, 'OK', `${hit.method} ${hit.url}: the API-key signature must verify`);
        assert.ok(hit.bearer, `${hit.method} ${hit.url}: carries the minted access token`);
        if (hit.method === 'POST' && !hit.url.includes('/actions/')) {
          assert.ok(typeof hit.idempotencyKey === 'string' && hit.idempotencyKey.trim().length > 0 && hit.idempotencyKey.length <= 200, `${hit.url}: Idempotency-Key is required`);
        }
      }

      // The mixed split waits for the leg's OTP; confirm targets that leg, continue reuses the key.
      const mixed = gateway.splitIssued.find((entry) => entry.mixed);
      assert.equal(hits[1].idempotencyKey, 'split:split-lock-0001');
      assert.equal(hits[2].url, `/api/v1/payments/${mixed.legPaymentId}/actions/${mixed.actionId}/confirm`);
      assert.deepEqual(JSON.parse(hits[2].raw), { otp: '123456' });
      assert.equal(hits[3].idempotencyKey, hits[1].idempotencyKey, 'continue reuses the Idempotency-Key');
      assert.equal(hits[3].raw, hits[1].raw, 'continue sends the same body');
      assert.equal(hits[4].url, `/api/v1/payments/split/${mixed.splitPaymentId}`, 'the read uses the chained split id');
      assert.equal(hits[5].url, '/api/v1/payments/split?status=COMPLETED&limit=10');
      assert.equal(hits[6].url, `/api/v1/payments/split/${mixed.splitPaymentId}/refund`);
      assert.deepEqual(JSON.parse(hits[6].raw), { amount: 1500, reason: 'postman-test' });
      assert.equal(environment.store.get('split_payment_id'), mixed.splitPaymentId);

      // A split id never lands in payment_id (the split detail carries it in `id`).
      for (const value of paymentIds) {
        assert.ok(!gateway.splitIssued.some((entry) => entry.splitPaymentId === value), 'payment_id is not a split id');
      }
      assert.deepEqual(tests.filter((t) => t.error), [], "the folder's own assertions pass");
      assert.equal(tests.filter((t) => / split payment answered$/.test(t.name)).length, 3, 'create, create and continue are checked');
    } finally {
      await teardown();
    }
  });
}

// --- Promissory Notes and Reference folders ----------------------------------------------

const {
  PROMISSORY_NOTE_MAX_SCHEDULE_ITEMS,
  requirePromissoryNoteSchedule,
  requireNoteCount,
} = require('../../node/src/payment/promissory-note-values');

function folderNamed(collection, name) {
  const folder = collection.item.find((node) => node.name === name);
  assert.ok(folder, `the collection has a ${name} folder`);
  return folder;
}

function noteRoute(hit) {
  return `${hit.method} ${hit.url.split('?')[0].replace(/\/payments\/[^/]+\/promissory-notes/, '/payments/:id/promissory-notes')}`;
}

test('the Promissory Notes and Reference folders are the same in both payment collections', () => {
  for (const name of ['Promissory Notes', 'Reference']) {
    const [standalone, localSigner] = ['standalone', 'local-signer'].map((profile) => folderNamed(loadCollection(profile), name));
    assert.equal(JSON.stringify(localSigner), JSON.stringify(standalone), `${name}: write the folder once, insert it into both collections`);
  }
});

test('every variable the Promissory Notes and Reference folders use is declared in both environment templates', () => {
  const collection = loadCollection('standalone');
  const folders = JSON.stringify([folderNamed(collection, 'Promissory Notes'), folderNamed(collection, 'Reference')]);
  const used = new Set(folders.match(/\{\{[a-z_0-9]+\}\}/g).map((token) => token.slice(2, -2)));
  for (const [profile, file] of Object.entries(ENVIRONMENT_TEMPLATES)) {
    const names = new Set(JSON.parse(fs.readFileSync(path.join(POSTMAN_DIR, file), 'utf8')).values.map((variable) => variable.key));
    assert.deepEqual([...used].filter((name) => !names.has(name)), [], `${profile} template`);
  }
});

test('promissory-note bodies follow the plan rules and use no provider code', () => {
  const folder = folderNamed(loadCollection('standalone'), 'Promissory Notes');
  const bodies = folder.item
    .filter((item) => item.request.method === 'POST' && !item.request.url.endsWith('/cancel'))
    .map((item) => ({ name: item.name, url: item.request.url, body: JSON.parse(item.request.body.raw.replace(/\{\{amount_minor\}\}/g, String(SAMPLE_AMOUNT)).replace(/\{\{promissory_note_due_date_1\}\}/g, '2030-01-15').replace(/\{\{promissory_note_due_date_2\}\}/g, '2030-02-15').replace(/\{\{promissory_note_count\}\}/g, '3').replace(/\{\{[^{}]+\}\}/g, '1')) }));
  assert.equal(bodies.length, 3, 'intent, note-count and schedule examples');
  for (const { name, url, body } of bodies) {
    assert.equal(body.paymentMethod, 'PROMISSORY_NOTE', `${name}: pinned to PROMISSORY_NOTE`);
    assert.equal(body.currency, 'TRY', `${name}: notes are in TRY`);
    const block = body.promissoryNote;
    assert.ok(block && typeof block === 'object', `${name}: carries the promissoryNote block`);
    assert.equal(block.providerCode, undefined, `${name}: the provider is read from GET /payments/methods, not hard-coded`);
    if (url.endsWith('/intents')) {
      assert.deepEqual(Object.keys(block), ['schedule'], `${name}: an intent carries only the schedule`);
    } else {
      checkDirectMethodBody(body, name);
      assert.notEqual(block.schedule === undefined, block.noteCount === undefined, `${name}: exactly one of schedule or noteCount`);
    }
    if (block.schedule !== undefined) {
      const schedule = requirePromissoryNoteSchedule(block.schedule);
      assert.ok(schedule.length <= PROMISSORY_NOTE_MAX_SCHEDULE_ITEMS);
      assert.equal(schedule.reduce((sum, row) => sum + row.amount, 0), body.amount, `${name}: the schedule adds up to amount`);
    } else if (block.noteCount !== undefined) {
      assert.equal(requireNoteCount(block.noteCount), block.noteCount, `${name}: noteCount is a digit string`);
    }
  }
});

for (const profile of ['standalone', 'local-signer']) {
  test(`${profile}: Promissory Notes and Reference requests are signed, keyed and chained`, async () => {
    const { gateway, environment, teardown } = await setUp(profile);
    try {
      const collection = loadCollection(profile);
      const tests = [];
      for (const name of ['Promissory Notes', 'Reference']) {
        const folder = folderNamed(collection, name);
        for (const item of folder.item) tests.push(...(await runItem(collection, { item, trail: [folder] }, environment)).tests);
      }

      const hits = gateway.received;
      assert.deepEqual(hits.map(noteRoute), [
        'POST /api/v1/payments/intents',
        'POST /api/v1/payments/direct/payment',
        'POST /api/v1/payments/direct/payment',
        'GET /api/v1/payments/:id/promissory-notes',
        'GET /api/v1/payments/:id/promissory-notes/document',
        'POST /api/v1/payments/:id/promissory-notes/cancel',
        'GET /api/v1/reference/tr-address/provinces',
        'GET /api/v1/reference/tr-address/districts',
        'GET /api/v1/reference/tr-address/neighborhoods',
      ], 'run order: intent, the two payments, list, document, cancel, then the address reference');
      for (const hit of hits) {
        const route = noteRoute(hit);
        assert.equal(hit.verdict, 'OK', `${route}: the API-key signature must verify`);
        assert.ok(hit.bearer, `${route}: carries the minted access token`);
        if (hit.method === 'POST' && route !== 'POST /api/v1/payments/:id/promissory-notes/cancel') {
          assert.ok(typeof hit.idempotencyKey === 'string' && hit.idempotencyKey.trim().length > 0, `${route}: Idempotency-Key is required`);
        }
        if (hit.method === 'GET') assert.equal(hit.raw, '', `${route}: a read without a body`);
      }

      // The list, the document and the cancel target the payment the schedule example started.
      const scheduled = gateway.received.filter((hit) => hit.url === '/api/v1/payments/direct/payment').at(-1);
      const startedOrderId = JSON.parse(scheduled.raw).orderId;
      assert.match(startedOrderId, /^promissory-note-pm-/, 'the schedule example ran last among the payments');
      const notePaths = hits.slice(3, 6).map((hit) => hit.url.split('?')[0].split('/')[4]);
      assert.equal(new Set(notePaths).size, 1, 'list, document and cancel use one chained payment_id');
      assert.equal(environment.store.get('payment_id'), notePaths[0]);
      assert.equal(hits[4].url.split('?')[1], 'locale=tr-TR');
      assert.equal(hits[7].url, '/api/v1/reference/tr-address/districts?provinceCode=06');
      assert.equal(hits[8].url, '/api/v1/reference/tr-address/neighborhoods?districtCode=1001');

      // Cancel sends the open note the list chained, not the stale environment value.
      assert.deepEqual(JSON.parse(hits[5].raw), { serialNumbers: [PROMISSORY_NOTE_SERIALS.open] });
      assert.deepEqual(tests.filter((t) => t.error), [], "the folders' own assertions pass");
    } finally {
      await teardown();
    }
  });
}

// --- Insurance folder -----------------------------------------------------------------

// The body fields and query filters the gateway DTOs accept (forbidNonWhitelisted) and the
// Idempotency-Key format, from the Node SDK, so the collection and the SDKs cannot drift apart.
const {
  INSURANCE_QUOTE_FIELDS,
  INSURANCE_LEAD_FIELDS,
  INSURANCE_PRODUCT_SEARCH_FIELDS,
  INSURANCE_ORDER_FIELDS,
  INSURANCE_CONSENT_FIELDS,
  INSURANCE_EXTERNAL_PAYMENT_FIELDS,
  INSURANCE_EXTERNAL_REFUND_FIELDS,
  INSURANCE_FILTERS,
  INSURANCE_IDEMPOTENCY_KEY_PATTERN,
} = require('../../node/src/insurance/insurance-values');

// The Merchant API insurance routes (contract §2.8, I1–I17): whether the Idempotency-Key is
// required, optional or absent, the top-level body fields and the query filters.
const INSURANCE_ROUTES = {
  'GET /products': { key: 'none', query: INSURANCE_FILTERS.listProducts },
  'POST /products': { key: 'none', body: INSURANCE_PRODUCT_SEARCH_FIELDS },
  'GET /reference/:kind': { key: 'none', query: INSURANCE_FILTERS.listReferenceValues },
  'POST /quotes': { key: 'optional', body: INSURANCE_QUOTE_FIELDS },
  'GET /quotes/:quoteId': { key: 'none' },
  'POST /orders': { key: 'required', body: INSURANCE_ORDER_FIELDS },
  'GET /orders': { key: 'none', query: INSURANCE_FILTERS.listOrders },
  'GET /orders/:orderId': { key: 'none' },
  'POST /orders/:orderId/bind-payment': { key: 'optional', body: ['paymentIntentId'] },
  'POST /orders/:orderId/confirm-payment': { key: 'required', body: ['payment'] },
  'POST /orders/:orderId/issue-policy': { key: 'required' },
  'POST /orders/:orderId/cancel': { key: 'required' },
  'POST /orders/:orderId/refund-premium': { key: 'required', body: ['externalRefund'] },
  'GET /policies/:policyId/document': { key: 'none' },
  'GET /reconciliation/summary': { key: 'none', query: INSURANCE_FILTERS.getReconciliationSummary },
  'GET /reconciliation/orders': { key: 'none', query: INSURANCE_FILTERS.listReconciliationOrders },
  'GET /reconciliation/export': { key: 'none', query: INSURANCE_FILTERS.exportReconciliation },
  'POST /leads': { key: 'required', body: INSURANCE_LEAD_FIELDS },
  'GET /leads': { key: 'none', query: INSURANCE_FILTERS.listLeads },
  'GET /leads/:leadId': { key: 'none' },
};
// The insured person, the ticket and the vehicle of a lead: personal data, so secret and empty in the templates.
const INSURANCE_PERSONAL_VARIABLES = [
  'insurance_insured_identity_number', 'insurance_insured_birth_date', 'insurance_insured_email',
  'insurance_insured_phone', 'insurance_ticket_pnr', 'insurance_ticket_number',
  'insurance_vehicle_plate', 'insurance_vehicle_registration_serial', 'insurance_vehicle_registration_number',
];
const ZONED_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;

function insuranceRouteOf(hit) {
  const pathOnly = hit.url.split('?')[0];
  if (!pathOnly.startsWith('/api/v1/insurance/')) return null;
  const route = pathOnly.slice('/api/v1/insurance'.length)
    .replace(/^\/reference\/[^/]+$/, '/reference/:kind')
    .replace(/^\/quotes\/[^/]+$/, '/quotes/:quoteId')
    .replace(/^\/orders\/[^/]+/, '/orders/:orderId')
    .replace(/^\/policies\/[^/]+/, '/policies/:policyId')
    .replace(/^\/leads\/[^/]+$/, '/leads/:leadId');
  return `${hit.method} ${route}`;
}

function insuranceFolder(collection) {
  const folder = collection.item.find((node) => node.name === 'Insurance');
  assert.ok(folder, 'the collection has an Insurance folder');
  return folder;
}

function assertPastZonedTime(value, label) {
  assert.match(value, ZONED_TIME, `${label}: ISO 8601 with a time zone`);
  assert.ok(Date.parse(value) <= Date.now(), `${label}: not in the future`);
}

test('the insuranceData checkout sends one made-up type object for the item and nothing the quote merges twice', () => {
  for (const profile of ['standalone', 'local-signer']) {
    const checkout = loadCollection(profile).item.find((node) => node.name === 'Payments / Checkout');
    const item = checkout.item.find((node) => node.name === 'Create Checkout Intent (Insured Item + insuranceData)');
    assert.ok(item, `${profile}: the Payments / Checkout folder has the insuranceData example`);
    assert.equal(item.request.url, '{{base_url}}/api/v1/payments/intents', `${profile}: Checkout Form intent only`);
    const body = JSON.parse(item.request.body.raw.replace(/\{\{amount_minor\}\}/g, String(SAMPLE_AMOUNT)).replace(/\{\{[^{}]+\}\}/g, 'x'));
    const [ticket] = body.basketItems;
    assert.equal(ticket.insuranceCategory, 'TICKET', `${profile}: insuranceData needs insuranceCategory`);
    assert.deepEqual(Object.keys(ticket.insuranceData).sort(), ['insured', 'tickets'], `${profile}: root fields of the quote body`);
    assert.ok(!Array.isArray(ticket.insuranceData.tickets), `${profile}: the list type object is one object for the item`);
    assert.equal(ticket.insuranceData.tickets.basketItemId, undefined, `${profile}: no basketItemId, the item id is used`);
    assert.equal(ticket.insuranceData.tickets.priceAmount, ticket.price, `${profile}: the ticket price is the item price`);
    // Made-up values only: a passport number of zeros and sample ticket references.
    assert.deepEqual(ticket.insuranceData.insured.map(({ identityType, identityNumber }) => [identityType, identityNumber]), [['PASSPORT', 'P0000000']]);
    assert.match(ticket.insuranceData.tickets.pnr, /^SAMPLE/);
    assert.match(ticket.insuranceData.tickets.ticketNumber, /^SAMPLE/);
  }
});

test('the Insurance folder is the same in both payment collections', () => {
  const [standalone, localSigner] = ['standalone', 'local-signer'].map((profile) => insuranceFolder(loadCollection(profile)));
  assert.equal(JSON.stringify(localSigner), JSON.stringify(standalone), 'write the folder once, insert it into both collections');
});

test('every insurance variable the folder uses is declared in both environment templates', () => {
  const used = new Set(JSON.stringify(insuranceFolder(loadCollection('standalone'))).match(/\{\{insurance_[a-z0-9_]+\}\}/g).map((token) => token.slice(2, -2)));
  assert.deepEqual([...used].sort(), Object.keys(INSURANCE_ENVIRONMENT).sort());
  for (const [profile, file] of Object.entries(ENVIRONMENT_TEMPLATES)) {
    const declared = JSON.parse(fs.readFileSync(path.join(POSTMAN_DIR, file), 'utf8')).values;
    const names = new Set(declared.map((variable) => variable.key));
    assert.deepEqual([...used].filter((name) => !names.has(name)), [], `${profile} template`);
    for (const name of INSURANCE_PERSONAL_VARIABLES) {
      const variable = declared.find((candidate) => candidate.key === name);
      assert.equal(variable.type, 'secret', `${profile}: ${name} is a secret`);
      assert.equal(variable.value, '', `${profile}: ${name} is empty in the template`);
    }
  }
});

for (const profile of ['standalone', 'local-signer']) {
  test(`${profile}: Insurance requests are signed, keyed, whitelisted and chained`, async () => {
    const { gateway, environment, teardown } = await setUp(profile);
    try {
      const collection = loadCollection(profile);
      const folder = insuranceFolder(collection);
      const entries = requestItems(folder.item, [folder]);
      const paymentId = environment.store.get('payment_id');
      const tests = [];
      for (const entry of entries) tests.push(...(await runItem(collection, entry, environment)).tests);

      // Every request reached the gateway once, signed, and every Merchant API route is covered.
      const hits = gateway.received;
      assert.equal(hits.length, entries.length, 'every request of the folder reached the stand-in once');
      assert.deepEqual([...new Set(hits.map(insuranceRouteOf).filter(Boolean))].sort(), Object.keys(INSURANCE_ROUTES).sort(), 'every insurance route is in the folder');
      for (const hit of hits) {
        const route = insuranceRouteOf(hit) || `${hit.method} ${hit.url}`;
        assert.equal(hit.verdict, 'OK', `${route}: the API-key signature must verify`);
        assert.ok(hit.bearer, `${route}: carries the minted access token`);
        const spec = INSURANCE_ROUTES[route];
        if (!spec) continue;
        if (spec.key === 'required') assert.match(String(hit.idempotencyKey), INSURANCE_IDEMPOTENCY_KEY_PATTERN, `${route}: Idempotency-Key is required`);
        if (spec.key === 'none') assert.equal(hit.idempotencyKey, undefined, `${route}: no Idempotency-Key`);
        if (hit.idempotencyKey !== undefined) assert.match(hit.idempotencyKey, INSURANCE_IDEMPOTENCY_KEY_PATTERN, `${route}: Idempotency-Key format`);
        const query = new URL(hit.url, 'http://stand-in').searchParams;
        assert.deepEqual([...query.keys()].filter((name) => !(spec.query || []).includes(name)), [], `${route}: query fields the gateway would reject with 400`);
        for (const [name, value] of query) assert.notEqual(value, '', `${route}: ${name} is sent empty`);
        if (!spec.body) {
          assert.equal(hit.raw, '', `${route}: no body`);
          continue;
        }
        const body = JSON.parse(hit.raw);
        assert.deepEqual(Object.keys(body).filter((name) => !spec.body.includes(name)), [], `${route}: fields the gateway would reject with 400`);
      }

      const sent = (name) => {
        const index = entries.findIndex((entry) => entry.item.name === name);
        assert.notEqual(index, -1, `the folder has ${name}`);
        return { url: hits[index].url, body: hits[index].raw ? JSON.parse(hits[index].raw) : null };
      };
      const [lunixiQuote, externalQuote] = gateway.insuranceIssued.quotes.filter((quote) => quote.paymentIntentId === null);
      const [lunixiOrder, externalOrder] = gateway.insuranceIssued.orders;
      assert.ok(lunixiQuote && externalQuote && lunixiOrder && externalOrder, 'two quotes from context.items and two orders were created');

      // Quote on a payment's recorded insurance data (OV-06): nothing but type, currency and the payment.
      assert.deepEqual(sent('Create Insurance Quote (paymentIntentId, merchant data)').body, {
        insuranceType: INSURANCE_ENVIRONMENT.insurance_type,
        currency: environment.store.get('currency'),
        paymentIntentId: paymentId,
      }, 'an empty body on the payment: the recorded insurance data is merged by Lunixi');
      assert.deepEqual(gateway.insuranceIssued.quotes.filter((quote) => quote.paymentIntentId !== null).map((quote) => quote.paymentIntentId), [paymentId]);

      // Quote: the basket comes from context.items and each ticket points at its item.
      for (const name of ['Create Insurance Quote', 'Create Insurance Quote (External Payment)']) {
        const { body } = sent(name);
        assert.equal(body.paymentIntentId, undefined, `${name}: one basket source, context.items`);
        assert.equal(body.tickets[0].basketItemId, body.context.items[0].id, `${name}: the ticket points at its basket item`);
        assert.equal(body.tickets[0].priceAmount, body.context.items[0].price, `${name}: the ticket price is the item price`);
      }

      // Order: the MERCHANT option of the quote just made, its terms sent back unchanged.
      for (const [name, quote] of [['Create Insurance Order', lunixiQuote], ['Create Insurance Order (External Payment)', externalQuote]]) {
        const { body } = sent(name);
        assert.equal(body.quoteId, quote.quoteId, `${name}: the MERCHANT option of the latest quote`);
        assert.deepEqual(Object.keys(body.consent).filter((field) => !INSURANCE_CONSENT_FIELDS.includes(field)), [], `${name}: consent fields`);
        assert.equal(body.consent.termsVersion, quote.terms.version, `${name}: terms version`);
        assert.equal(body.consent.termsSha256, quote.terms.sha256, `${name}: terms digest`);
        assertPastZonedTime(body.consent.acceptedAt, `${name}: consent.acceptedAt`);
      }

      // The payment carries the ticket exactly as quoted plus the premium item of the order.
      const intent = sent('Create Checkout Intent (Ticket + Premium)').body;
      assert.deepEqual(intent.basketItems[0], sent('Create Insurance Quote').body.context.items[0], 'the ticket is the quoted item');
      assert.deepEqual(intent.basketItems[1], {
        id: lunixiOrder.orderId,
        price: lunixiOrder.premiumAmount,
        name: 'Ticket cancellation insurance',
        category1: 'insurance',
        itemType: 'VIRTUAL',
      }, 'the premium item: id = orderId, VIRTUAL, price = premium, no insurance field');
      assert.equal(intent.amount, intent.basketItems[0].price + lunixiOrder.premiumAmount, 'amount is ticket + premium');

      // Each flow acts on its own order; the bind uses the payment, which insurance answers never overwrite.
      const lunixiPath = `/api/v1/insurance/orders/${lunixiOrder.orderId}`;
      const externalPath = `/api/v1/insurance/orders/${externalOrder.orderId}`;
      assert.equal(sent('Bind Payment to Insurance Order').url, `${lunixiPath}/bind-payment`);
      assert.deepEqual(sent('Bind Payment to Insurance Order').body, { paymentIntentId: paymentId });
      assert.equal(sent('Get Insurance Order').url, lunixiPath);
      assert.equal(sent('Cancel Policy').url, `${lunixiPath}/cancel`);
      assert.equal(sent('Refund Premium').url, `${lunixiPath}/refund-premium`);
      assert.deepEqual(sent('Refund Premium').body, {}, 'a premium paid in a Lunixi payment is refunded with an empty body');
      assert.equal(environment.store.get('payment_id'), paymentId, 'insurance answers leave payment_id alone');

      const confirm = sent('Confirm External Premium Payment');
      assert.equal(confirm.url, `${externalPath}/confirm-payment`);
      assert.deepEqual(Object.keys(confirm.body.payment).filter((field) => !INSURANCE_EXTERNAL_PAYMENT_FIELDS.includes(field)), [], 'payment fields');
      assert.equal(confirm.body.payment.paidAmount, externalOrder.premiumAmount, 'paidAmount is the premium of this order');
      assert.match(confirm.body.payment.externalPaymentId, /^[\x21-\x7E]{1,128}$/);
      assertPastZonedTime(confirm.body.payment.paidAt, 'payment.paidAt');
      assert.equal(sent('Issue Policy').url, `${externalPath}/issue-policy`);
      assert.equal(sent('Get Insurance Order (External Payment)').url, externalPath);
      assert.equal(sent('Cancel Policy (External Payment)').url, `${externalPath}/cancel`);
      const externalRefund = sent('Refund Premium (External Payment)');
      assert.equal(externalRefund.url, `${externalPath}/refund-premium`);
      assert.deepEqual(Object.keys(externalRefund.body.externalRefund).filter((field) => !INSURANCE_EXTERNAL_REFUND_FIELDS.includes(field)), [], 'externalRefund fields');
      assert.match(externalRefund.body.externalRefund.externalRefundId, /^[\x21-\x7E]{1,128}$/);
      assertPastZonedTime(externalRefund.body.externalRefund.refundedAt, 'externalRefund.refundedAt');

      // Insurance sold without a basket item: the product list asks without a payment.
      const standaloneProducts = new URL(sent('List Insurance Products Sold Without a Basket Item').url, 'http://stand-in').searchParams;
      assert.deepEqual([...standaloneProducts.keys()], ['currency'], 'no paymentIntentId: the types sold without a basket item');

      // Chained reads: the district list uses the listed city, the documents the policy an order answered.
      assert.equal(new URL(sent('List Districts').url, 'http://stand-in').searchParams.get('parentCode'), INSURANCE_IDS.cityCode);
      for (const name of ['Get Policy Document', 'Get Policy Document (External Payment)']) {
        assert.equal(sent(name).url, `/api/v1/insurance/policies/${INSURANCE_IDS.policy}/document`, `${name}: the policy an order answered`);
      }

      // Lead: the person and the vehicle of the lead type, no sale fields; the read uses the lead just submitted.
      const [lead] = gateway.insuranceIssued.leads;
      assert.ok(lead, 'one lead was submitted');
      const leadBody = sent('Submit Insurance Lead').body;
      assert.equal(leadBody.insuranceType, INSURANCE_ENVIRONMENT.insurance_lead_type);
      for (const field of ['currency', 'paymentIntentId', 'context', 'merchantOrderId']) {
        assert.equal(leadBody[field], undefined, `a lead carries no ${field}`);
      }
      assert.deepEqual(leadBody.vehicle, {
        plate: INSURANCE_ENVIRONMENT.insurance_vehicle_plate,
        registrationDocument: {
          serial: INSURANCE_ENVIRONMENT.insurance_vehicle_registration_serial,
          number: INSURANCE_ENVIRONMENT.insurance_vehicle_registration_number,
        },
      });
      assert.equal(sent('Get Insurance Lead').url, `/api/v1/insurance/leads/${lead.leadId}`, 'the lead the submit answered');
      assert.deepEqual(tests.filter((t) => t.error), [], "the folder's own assertions pass");
    } finally {
      await teardown();
    }
  });

  test(`${profile}: a quote without a MERCHANT option stores nothing and a pinned city code is kept`, () => {
    const collection = loadCollection(profile);
    const folder = insuranceFolder(collection);
    const runTests = (method, url, envelope, values) => {
      const environment = createEnvironment({ payment_id: 'pi_original', ...values });
      const results = [];
      const pm = {
        test(name, assertion) {
          try { assertion(); results.push({ name, error: null }); } catch (error) { results.push({ name, error: error.message }); }
        },
        expect: expectation,
        environment: { get: (k) => environment.store.get(k), set: (k, v) => environment.store.set(k, v) },
        request: { method, url: { toString: () => url } },
        response: { code: 200, json: () => envelope },
      };
      for (const node of [collection, folder]) {
        // eslint-disable-next-line no-new-func
        new Function(...SANDBOX_GLOBALS, scriptOf(node, 'test'))(...SANDBOX_GLOBALS.map((name) => (name === 'pm' ? pm : undefined)));
      }
      return { store: environment.store, results };
    };
    const base = 'https://api-gateway.lunixi.com/api/v1/insurance';
    const providerOnly = { data: { options: [{ quoteId: `insq_${'1'.repeat(32)}`, status: 'QUOTED', premiumCollectedBy: 'PROVIDER', terms: { version: 'v1', sha256: '1'.repeat(64) } }] } };
    const declined = runTests('POST', `${base}/quotes`, providerOnly, { insurance_quote_id: 'insq_previous' });
    assert.equal(declined.store.get('insurance_quote_id'), 'insq_previous', 'a PROVIDER option is not stored');
    assert.ok(declined.results.some((result) => result.error), 'the folder reports that no MERCHANT option came back');

    const cities = { data: { items: [{ code: '06', label: { tr: 'Ankara', en: 'Ankara' }, parentCode: null }] } };
    assert.equal(runTests('GET', `${base}/reference/CITY?limit=100`, cities, { insurance_city_code: '35' }).store.get('insurance_city_code'), '35', 'a city code set by the user is kept');
    assert.equal(runTests('GET', `${base}/reference/CITY?limit=100`, cities, { insurance_city_code: '' }).store.get('insurance_city_code'), '06');

    const order = { data: { orderId: `inso_${'2'.repeat(32)}`, premiumAmount: 4900, paymentIntentId: '40000000-0000-4000-8000-000000000001', policies: [] } };
    const created = runTests('POST', `${base}/orders`, order, { insurance_ticket_price_minor: '100000' }).store;
    assert.equal(created.get('insurance_order_id'), order.data.orderId);
    assert.equal(created.get('insurance_premium_amount'), '4900');
    assert.equal(created.get('insurance_payment_amount'), '104900', 'ticket + premium');
    assert.equal(created.get('payment_id'), 'pi_original', 'an insurance order is not a payment');
  });
}
