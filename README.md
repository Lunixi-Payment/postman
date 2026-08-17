# Lunixi Postman Workspace

Professional Postman workspace for Lunixi payment integrations.

This folder has two integration profiles:

## 1. Local Signer Profile

Recommended for serious API testing.

Files:

- `local-signer/Lunixi-Payment-Gateway.local-signer.postman_collection.json`
- `local-signer/environments/lunixi.local-signer.template.postman_environment.json`
- `tools/signer-server.js`

How it works:

- Postman sends requests normally.
- A small local signer helper mints merchant access tokens.
- The private key never goes into the Postman collection.
- Tokens are cached in the Postman environment until expiry.
- Raw API responses are visible in the Postman response panel.

Start the signer:

```bash
cd /postman
node tools/signer-server.js
```

Then import the collection and environment into Postman.

## 2. Standalone Profile

For teams that cannot run a local helper.

Files:

- `standalone/Lunixi-Payment-Gateway.standalone.postman_collection.json`
- `standalone/environments/lunixi.standalone.template.postman_environment.json`

How it works:

- The private key is entered into Postman as `private_key_pem`.
- The collection pre-request script signs `/api/v1/auth/token` inside Postman.
- It embeds a small TweetNaCl Ed25519 signer, so it does not need Postman's npm package runtime.
- Tokens are cached in the Postman environment until expiry.

This profile is convenient, but the local signer profile is more robust across Postman versions and better for support/debugging.

## Which One Should We Give Customers?

Give both:

- Use **Local Signer** as the recommended collection.
- Use **Standalone** as the no-terminal fallback.
- Use SDKs for production implementation.

## Docs

- `docs/SIGNING_AND_TOKEN_AUTOMATION.md`
- `standalone/THIRD_PARTY_NOTICES.md`
