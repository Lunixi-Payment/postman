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
- A small local signer helper mints merchant access tokens and signs every request
  (see [Request Signing](#request-signing)).
- The private key never goes into the Postman collection.
- Tokens are cached in the Postman environment until expiry.
- Raw API responses are visible in the Postman response panel.

Start the signer:

```bash
cd /Users/selimdestanci/Desktop/Fintech/entegrasyon/postman
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
- The collection pre-request script mints the access token from `/api/v1/auth/token`
  and signs every request inside Postman (see [Request Signing](#request-signing)).
- It embeds a small TweetNaCl Ed25519 signer, so it does not need Postman's npm package runtime.
- Tokens are cached in the Postman environment until expiry.

This profile is convenient, but the local signer profile is more robust across Postman versions and better for support/debugging.

## Request Signing

Both payment collections sign **every request** in the collection-level pre-request
script, on top of the bearer token: `X-Key-Id`, `X-Date`, `X-Nonce`, `X-Signature`
and, when the request has a body, `Digest`. Step-up endpoints (create payment
intent, direct 2D/3D payment, capture) return `401` without this signature. The
canonical string is described in `docs/SIGNING_AND_TOKEN_AUTOMATION.md`.

Before signing, the script fixes what is sent, so the signature covers exactly what
the gateway receives:

- **URL**: `{{variables}}` are resolved and the path and query are percent-encoded
  once. That exact string is signed and sent.
- **Body**: `{{variables}}` (including `{{$guid}}` and `{{$timestamp}}`) are resolved
  and the JSON is sent without whitespace. The gateway computes the `Digest` over the
  JSON it parsed, re-serialised without whitespace, so an indented body would not
  match. A body that is not valid JSON after variable resolution fails the
  pre-request script with an error naming the JSON problem, and the request is not
  signed.
- **Freshness**: every send gets a new `X-Nonce` and `X-Date`, so sending a request
  again is fine. The gateway accepts an `X-Date` within 5 minutes of its clock.

With the local signer profile, the signer's `POST /sign` endpoint signs each request,
so the signer must keep running while you use the collection, not only for the first
token.

A request marked `X-Lunixi-Skip-Auto-Auth: true` is left alone: it gets neither the
token nor a signature. Two kinds of request carry it: the local signer's own
endpoints, and the payment-link image upload, which goes to the storage host rather
than the gateway (see [Payment Links](#payment-links)).

Every request has a `request is authenticated` test. A `401` means the access token
or the request signature was rejected. The Postman Console shows the signed headers.

## Payment Links

Both payment collections have a **Payment Links** folder for
`/api/v1/payments/links`: create (a fixed single-use link and an itemized
multi-use link), list, get, update, pause, resume, send, QR, attempts, payments,
a link image and deactivate.

- These routes accept the **API-key signature only**. The collection signs every
  gateway request (see [Request Signing](#request-signing)); an unsigned request is
  `401 AUTH_HEADERS_MISSING`.
- The key needs the `payment-link:create`, `payment-link:view`,
  `payment-link:manage` and `payment-link:send` scopes, otherwise `403
  API_INSUFFICIENT_SCOPE`. Keys created before payment links do not have them.
- The key decides the environment: with a TEST key (`mk_test_…`) you create and
  see only TEST links, and no money is taken on them.
- Create and send carry a fresh `Idempotency-Key` on every send. To test a replay,
  pin the header to a fixed value and send twice: the second answer is `200` with
  `replayed: true`.
- Create, get, update and the actions store the link in `payment_link_id` and its
  `rowVersion` in `payment_link_row_version`. Update and the actions send that
  `rowVersion` back as `expectedRowVersion`, so run them in folder order; a stale
  value is `409 payment_link.link.version_conflict`.
- `Send Payment Link` uses `payment_link_recipient_email`; leave it empty to send
  to the link's own recipient. The links this folder creates have no recipient,
  so set the variable first. With a TEST key only your organisation's own
  verified member addresses receive messages: use your own login e-mail.
- **Link image**: `Create Payment Link Image Upload` declares the file (edit
  `fileName`, `contentType` and `sizeBytes` in its body: PNG, JPEG or WebP, at most
  2 MiB), `Upload Payment Link Image to Storage` sends it (select the file under
  Body → binary, before the returned `expiresAt`, 15 minutes by default) and
  `Confirm Payment Link Image` publishes it.
  `Set Payment Link Image` then shows it on the link. The requests chain
  `payment_link_image_asset_id`, `payment_link_image_upload_url` and
  `payment_link_image_content_type`. Both image routes need the
  `payment-link:create` scope (the set-image update needs `payment-link:manage`).
- The upload request goes to the **storage host**, not the gateway. It is `No Auth`
  and carries `X-Lunixi-Skip-Auto-Auth: true`, so the collection script neither adds
  the access token nor signs it: the token and the signature must not leave for
  another host, and storage refuses a request that has an `Authorization` header next
  to its presigned URL. It sends only the `Content-Type` the URL was signed for.
- `Deactivate Payment Link` is last on purpose: a deactivated link cannot be
  reopened.

A payment-link response carries the link id in `id`; the collection does not copy
it into `payment_id`.

## Wallet

Both payment collections have a **Wallet** folder for the merchant wallet API
(`/api/v1/wallet/*`): one request per route, 60 in all, in sub-folders by area
and in run order: Programs, End users, Wallets & accounts, Deposits, Corporate,
Fees, Transfers W2W, Transfers IBAN, Bank withdrawals, Operations, Top-ups,
Payments, QR, Bulk payouts, End-user lifecycle. The folder is the same in both
collections.

- **Signed on every request**, reads included: every wallet route is behind
  `SignatureGuard`. The collection signs every gateway request (see
  [Request Signing](#request-signing)); nothing is needed per request.
- **The key needs** the `WALLET_SERVICE` product (otherwise `403
  PRODUCT_NOT_ENABLED`) and the permission behind the route (otherwise `403
  WALLET_INSUFFICIENT_SCOPE`):

  | Permission | For |
  |---|---|
  | `wallet:*:read` (`wallet:program:read`, `wallet:enduser:read`, `wallet:operation:read`, `wallet:qr:read`, …) | reads, quotes, QR parse |
  | `wallet:program:manage`, `wallet:enduser:manage` (set-up: `wallet:program\|enduser\|limit\|fee:manage`) | ping, collection anchor, end users, wallets and accounts, wallet lookup, deposit instructions, freeze |
  | `wallet:operation:intervene` | money inside the wallet: W2W, card and agent top-ups, top-up refund, payments |
  | `wallet:bank-payout:operate` | IBAN transfers, bank withdrawals, the simulated inbound credit (GROWTH plan) |
  | `wallet:qr:manage` | create and revoke QR |
  | `wallet:bulk:create` | corporate accounts, employee import and offboard, create and reject bulk payouts |
  | `wallet:bulk:approve` | submit, approve, process and retry bulk payouts |
  | `wallet:enduser:kyc-override` | update the KYC level |

  Payment request and collect also need a **wallet terminal bound to the signing
  key** (`403 WALLET_TERMINAL_*` without one).
- **Bodies** contain only fields the gateway accepts: an unknown field is `400`.
  **Amounts are minor units as digit strings** (`"12550"` is 125.50 TRY).
- **Idempotency-Key** (`wallet-<route>-{{$guid}}`) is on exactly the routes that
  require it, fresh on every send. Pin it to a fixed value to test a replay.
- **Two-step money**: W2W, IBAN transfer and bank withdrawal are initiate +
  complete, payment is request + approve. The first step stores `operationId`
  (payment: `requestId`), `integrityHash` and `nonce` in `wallet_operation_id`
  (payment: `wallet_payment_operation_id`), `wallet_integrity_hash` and
  `wallet_nonce`; the second step sends them back, and complete bodies also carry
  `operationId` equal to the path id. When the first step answers
  `otpRequired: true`, add `"otpCode"` to the second step's body (an empty one is
  `400`, so it is not there by default).
- **Chained variables**: `List My Programs` fills `wallet_program_id` when it is
  empty; `Create End User` sets `wallet_end_user_id`, `wallet_id`, `wallet_no`
  and `wallet_account_id`; `Create Wallet` moves `wallet_id` to the new wallet;
  the folder also chains `wallet_deposit_reference`, `wallet_deposit_iban`,
  `wallet_corporate_account_id`, `wallet_topup_operation_id`, `wallet_qr_id`,
  `wallet_qr_payload` and `wallet_bulk_batch_id`. Wallet responses never
  overwrite `payment_id`, `checkout_token` or `stored_card_token`.
- **Set before running**: `wallet_destination_wallet_no` (another end user's
  wallet number: run `Create End User` with another `wallet_phone` and
  `wallet_external_customer_id` and copy `defaultWallet.walletNo`),
  `wallet_business_end_user_id` (a BUSINESS end user: collection anchor,
  corporate owner, commission), `wallet_rail_id` (a bank integration that
  supports simulation), `wallet_agent_id` and, for collect, `wallet_payment_code`
  (the code the buyer's app shows). `wallet_iban` and `wallet_beneficiary_name`
  are sample values.
- `Simulate Inbound Credit` is **test only**: it funds the account through a bank
  integration that supports simulation, so the transfers have money to move. A
  real provider rejects it.
- **Bulk payouts are maker-checker**: a different key approves than the one that
  created and submitted the batch. Before `Approve Bulk Payout`, switch to the
  approver key (`key_id` and its private key or signer) and empty `access_token`
  so a new token is minted. `Reject Bulk Payout` is the alternative to approve:
  after the batch was approved it answers `409`.
- `Refund Top-up` needs a top-up whose card payment completed; `Freeze End User`
  is last on purpose: a frozen end user cannot move money, and the merchant API
  has no unfreeze.
- `Get QR Image` answers an image (`image/svg+xml` or `image/png`), not JSON.

## Which One Should We Give Customers?

Give both:

- Use **Local Signer** as the recommended collection.
- Use **Standalone** as the no-terminal fallback.
- Use SDKs for production implementation.

## Fraud

The fraud surface has its own collection per profile:

- `fraud/local-signer/Lunixi-Fraud.local-signer.postman_collection.json`
- `fraud/local-signer/environments/lunixi-fraud.local-signer.template.postman_environment.json`
- `fraud/standalone/Lunixi-Fraud.standalone.postman_collection.json`
- `fraud/standalone/environments/lunixi-fraud.standalone.template.postman_environment.json`

Folders: Auth, Decision, Event Ingest, Decision Logs, Negative.

Only the customer fraud surface is covered. Panel routes (`/fraud/admin/*`,
`/fraud/flows/*`) are not part of the customer API and are deliberately absent.

Two things differ from the payment collections:

- **Event ingest is signed by its own request scripts**, not by the collection
  script. `POST /fraud/events/transactions(/batch)`
  is authenticated by the Ed25519 signature, not by the bearer token alone. The
  body is materialised into `fraud_event_body` before signing — a body still
  containing `{{$guid}}` would re-resolve at send time and stop matching the
  `Digest`. It is serialised without whitespace, because the gateway computes the
  `Digest` over the parsed body re-serialised that way.
  - *Standalone*: signs inline, in one pre-request step.
  - *Local signer*: signing is a **prepare-then-send pair**. Run
    `Prepare Signed Event` before `Record Transaction Event`, and the same for the
    batch pair.
- **Environments default to a TEST key** (`mk_test_sk_…`). There is one base URL;
  the key decides the environment.

The Negative folder asserts 400s (channel spoofing, a reserved product context, a
non-standalone integration mode, an unknown field), so those requests are expected
to fail against anything that does not enforce the real validation.

### A note on `data` in test scripts

`data` is a **predefined object** in the Postman/newman sandbox. A top-level
`const data = …` in a test script is a `SyntaxError` that kills the whole script
silently — assertions never run and no variable gets chained. Use another name
(`payload`, `envelope`) or wrap the script in an IIFE. The test below fails on any
such script.

## Tests

```bash
cd postman
node --test
```

`test/collection-signing.test.js` uses only Node's built-in test runner, no packages.
It runs the payment collections and the fraud Event Ingest folders the way newman
does (pre-request scripts, send, test scripts), sends every request to a local
stand-in that verifies the signature the way the gateway does, and checks that every
script in every collection compiles in the Postman sandbox scope. For the Payment
Links folder it also checks the required `Idempotency-Key`s, that every body field is
one the gateway accepts (the field list is the Node SDK's
`node/src/payment/payment-link-values.js`), that a link response never lands in
`payment_id`, and that the image upload reaches a storage stand-in with the selected
file and the signed `Content-Type` but without the access token or the signature.
For the Wallet folder it reads the Node SDK's route table
(`node/src/wallet/wallet-values.js`, `WALLET_ROUTES` and `WALLET_NESTED_FIELDS`) and
checks, per collection: exactly one request per route (method and path), every
request signed, the `Idempotency-Key` present exactly where the gateway requires
it, every body field (and every bulk item / employee row field) one the gateway
accepts with all required ones present, that each request uses the ids the one
before it answered while `payment_id` stays untouched, and that the folder is the
same in both collections and its variables are declared in both environment
templates.

## Docs

- `docs/SIGNING_AND_TOKEN_AUTOMATION.md`
- `standalone/THIRD_PARTY_NOTICES.md`
