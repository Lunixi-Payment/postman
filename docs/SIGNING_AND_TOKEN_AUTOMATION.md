# Signing And Token Automation

Lunixi merchant API authentication has two phases:

1. The merchant signs `POST /api/v1/auth/token` with its Ed25519 private key.
2. The gateway returns a short-lived merchant access token.
3. Normal API calls use `Authorization: Bearer <access_token>`.

The Postman workspace automates this so users do not copy-paste tokens manually.

## Canonical Signature Format

For bodyless token mint:

```text
POST
/api/v1/auth/token
X-Date:<iso-date>
X-Nonce:<uuid-or-random>
```

For requests with a body, a digest line is appended:

```text
Digest:SHA-256=<base64-sha256-body>
```

The signature is Ed25519 over the UTF-8 canonical string and is sent as Base64 in:

```text
X-Signature
```

Required auth headers:

```text
X-Key-Id
X-Date
X-Nonce
X-Signature
```

## Local Signer Profile

The local signer is the recommended Postman profile.

Why it exists:

- Postman does not expose Node's native `crypto.sign` API.
- Ed25519 PEM parsing inside a collection is possible but harder to support.
- A local helper uses the same crypto primitives as the Node SDK.
- The private key stays on the developer machine.

Flow:

1. Postman checks `access_token` and `access_token_expires_at`.
2. If token is missing or expired, Postman calls:

```text
POST {{signer_url}}/token
```

3. The local signer signs `/api/v1/auth/token`, calls the gateway, and returns:

```json
{
  "accessToken": "...",
  "expiresIn": 3600,
  "expiresAt": 1786840000000,
  "rawResponse": {}
}
```

4. Postman stores the token and sends the original API request.

Run:

```bash
cd /Users/selimdestanci/Desktop/Fintech/entegrasyon/postman
node tools/signer-server.js
```

Override key source:

```bash
LUNIXI_PRIVATE_KEY_PATH=/absolute/path/private.pem node tools/signer-server.js
```

or:

```bash
LUNIXI_PRIVATE_KEY='-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----' node tools/signer-server.js
```

Health check:

```bash
curl http://127.0.0.1:8787/health
```

## Standalone Profile

The standalone collection avoids the local helper.

Required environment variables:

```text
base_url
auth_token_path
key_id
private_key_pem
access_token
access_token_expires_at
```

How it works:

1. Postman runs the embedded TweetNaCl Ed25519 signer.
2. The pre-request script parses `private_key_pem`.
3. It signs the token canonical string.
4. It calls `/api/v1/auth/token`.
5. It stores the returned access token.
6. It sends the original request.

Supported private key formats:

- PKCS#8 Ed25519 PEM
- raw 32-byte seed encoded as Base64
- 64-byte Ed25519 secret key encoded as Base64

Important support note:

Standalone no longer depends on Postman's npm package runtime. The signer code is embedded in the collection to avoid `Cannot find package 'npm:tweetnacl'` errors in locked-down or older Postman workspaces.

## Customer Guidance

Recommended wording:

```text
For production integration, use the official PHP or Node SDK.
For API exploration in Postman, use the Local Signer collection.
If your organization cannot run a local helper, use the Standalone collection.
```

## Security Notes

- Never paste production private keys into shared Postman workspaces.
- Use sandbox/test merchant keys for shared QA collections.
- Treat `private_key_pem`, `access_token`, `checkout_token`, and `stored_card_token` as secrets.
- Rotate keys if a private key is accidentally shared.
