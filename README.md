<p align="center">
  <a href="https://lunixi.com">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/Lunixi-Payment/postman/main/.github/assets/lunixi-logo-dark.svg">
      <img src="https://raw.githubusercontent.com/Lunixi-Payment/postman/main/.github/assets/lunixi-logo.svg" alt="Lunixi" height="64">
    </picture>
  </a>
</p>

# Lunixi Postman Workspace

[![CI](https://github.com/Lunixi-Payment/postman/actions/workflows/ci.yml/badge.svg)](https://github.com/Lunixi-Payment/postman/actions/workflows/ci.yml) [![Postman](https://img.shields.io/badge/Postman-collection%20v2.1-FF6C37?logo=postman&logoColor=white)](https://learning.postman.com/collection-format/getting-started/overview/) [![Download](https://img.shields.io/badge/download-zip-informational)](https://github.com/Lunixi-Payment/postman/archive/refs/heads/main.zip) [![Docs](https://img.shields.io/badge/docs-docs.lunixi.com-FF6B35)](https://docs.lunixi.com/sdks/postman)

**[Documentation](https://docs.lunixi.com/sdks/postman) · [Issues](https://github.com/Lunixi-Payment/postman/issues) · [Security](https://github.com/Lunixi-Payment/postman/blob/main/SECURITY.md)**

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

Start the signer from this folder with your private key file:

```bash
LUNIXI_PRIVATE_KEY_PATH=/absolute/path/private.pem node tools/signer-server.js
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
intent, `direct/payment`, capture) return `401` without this signature. The
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

## Payment Methods

Both payment collections have a **Payment Methods** folder for payments with any
payment method from the merchant server (Faturana Yansıt, wallets, card):

- `List Payment Methods` — `GET /api/v1/payments/methods`: the methods open for
  your account, in the order set in your form settings, each provider's
  `inputFields`, `preauth` support and `splitEligible` / `splitBehavior`.
  `providerSelectionMode` is the API behaviour: `BUYER` (send `providerCode` when
  more than one provider is connected) or `PLATFORM` (`providerCode` may be left
  out; the platform picks a connected provider, 422
  `payment.provider.none_eligible` when none can take the payment). In the
  Checkout Form the buyer always picks the provider. A provider turned off only in
  the checkout form stays in the list and can be used through the API. When
  `method_mobile_billing_provider_code` is empty the request stores the first
  Faturana Yansıt provider in it.
- `List Payment Methods - One Method` — the same list with
  `?paymentMethod=MOBILE_BILLING`: that method only, `{ methods: [] }` when it is
  not open, 400 `payment.method.unknown` for an unknown code.
- `Direct Payment - Faturana Yansıt`, `- Wallet`, `- Card`, `- Card (3D Secure)`,
  `- Card Pre-authorization` — `POST /api/v1/payments/direct/payment`, each with an
  `Idempotency-Key`. The body has `paymentMethod` and only that method's block.
- `Resend Payment Action` and `Confirm Payment Action` —
  `POST /api/v1/payments/{paymentId}/actions/{actionId}/resend|confirm`.

Run order: List → Faturana Yansıt → (Resend) → Confirm. The folder stores
`data.action.id` in `payment_action_id` (the collection stores `paymentId` in
`payment_id`); put the code the buyer received in `payment_otp` before Confirm.
For the card 3D Secure request, open `payment_action_redirect_url` in a browser.
Set `method_gsm_number` (the line to bill) and `method_wallet_provider_code` (from
the list) in the environment. The Faturana Yansıt example sends
`method_mobile_billing_provider_code`, the provider your buyer picked.

## Split Payments

Both payment collections have a **Split Payments** folder: one payment funded by
stored cards and, when split payments with other methods are enabled in your form
settings, non-card methods.

- `Create Split Payment - Stored Cards` and
  `Create Split Payment - Card and Faturana Yansıt` — `POST /api/v1/payments/split`
  with an `Idempotency-Key`. A card leg is `{ cardToken, amount }`; a non-card leg
  carries `paymentMethod` and the same block as `direct/payment`, with
  `providerCode` required. Leg amounts add up to `totalAmount`.
- `Confirm Split Leg Action` — the OTP of the non-card leg the payment waits for
  (`split_leg_payment_id`, `split_leg_action_id`, stored from `pendingStep`).
- `Continue Split Payment` — the same body with the same `Idempotency-Key`
  (`split:{{split_order_id}}`): the payment continues where it stopped.
- `Get Split Payment`, `List Split Payments`, `Refund Split Payment` —
  `GET /api/v1/payments/split/{id}`, `GET /api/v1/payments/split`,
  `POST /api/v1/payments/split/{id}/refund`.

While a split payment runs the gateway answers `400` with the split status
(`AWAITING_ACTION`, `AWAITING_3DS` …) as `code` and the split in `data`. Set
`stored_card_token`, `split_second_card_token` and a new `split_order_id` for each
new split payment. `List Payments (Split Legs)` in **Payments / Checkout** shows
`includeLegs=true`.

A card is paid from the server only here: `paymentMethod: CARD` with the `card`
block, `force3D: true` for 3D Secure (a stored card: `cardUserKey` + `cardToken` in
`card`). The former **Payments / Direct** folder and the direct 2D/3D card endpoints
were removed; the Checkout Form card flow is unchanged.
`Create Checkout Intent (Pre-authorization)` and
`Direct Payment - Card Pre-authorization` show the typed `preauth: true` field.

## Promissory Notes and Reference

Both payment collections have a **Promissory Notes** folder for Senetle Ödeme
(`paymentMethod: PROMISSORY_NOTE`) and a **Reference** folder for the Türkiye
address codes its `ADDRESS` fields use:

- `Create Checkout Intent (Promissory Note Schedule)` — `POST /api/v1/payments/intents`
  pinned to `PROMISSORY_NOTE` with `promissoryNote.schedule`: the hosted form shows
  the plan instead of a note-count choice.
- `Direct Payment - Promissory Note (Note Count, Corporate)` and
  `Direct Payment - Promissory Note (Schedule)` — `POST /api/v1/payments/direct/payment`
  with an `Idempotency-Key`. The `promissoryNote` block carries the provider's
  `inputFields` (debtor, address, guarantors) and the plan: `noteCount` **or**
  `schedule`. The answer is `200` / `CAPTURED` without an action.
- `List Promissory Notes`, `Download Promissory Notes (PDF)`, `Cancel Promissory Notes` —
  `GET|POST /api/v1/payments/{paymentId}/promissory-notes[/document|/cancel]`. The
  folder stores the first open note in `promissory_note_serial_number` for Cancel.
- `List Provinces`, `List Districts`, `List Neighborhoods` —
  `GET /api/v1/reference/tr-address/...`; public data, an empty list means that
  level is not published yet.

Set `promissory_note_district_code` and `promissory_note_neighborhood_code` from the
Reference folder and keep `promissory_note_due_date_1/2` in the future. The
provider is not hard-coded: it comes from `List Payment Methods`. All example values
are synthetic.

## Amounts

Every payment body (checkout intent, `direct/payment`) has one amount
field: `amount`, the basket total in minor units as an integer
(`{{amount_minor}}`, `10050` is 100.50 TRY). The basket items' `price` values add
up to it. A promissory-note schedule example carries literal note amounts and its
`amount` is their total. `price` and `paidPrice` are no longer body fields; the gateway answers
them with `400 payment.amount.field_removed`. An installment fee is never part of
`amount`: the system adds it when an installment quote is bound.

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

## Bank Accounts

Both payment collections have a **Bank Accounts** folder for
`/api/v1/bank-connect`: List Banks, List Connections, Get Connection, List
Accounts, Get Account, List Balances, List Transactions, Get Transaction and
Request Account Sync. The folder is the same in both collections, and every
request carries example responses (fake, masked values).

- **The API reads.** Connecting a bank and entering bank credentials happen in
  the Lunixi dashboard; there is no request for them.
- **Signed on every request**, reads included; the collection signs every gateway
  request. Unsigned is `401 AUTH_HEADERS_MISSING`.
- **The key needs** the `BANK_CONNECT` product (otherwise `403
  PRODUCT_NOT_ENABLED`), `bank-connect:view` for banks, connections, accounts and
  the sync request, and `bank-connect:transactions:view` for balances and
  transactions (otherwise `403 API_INSUFFICIENT_SCOPE`).
- **The key decides the environment**: a TEST key (`mk_test_…`) reads only
  test-environment accounts.
- **No body, no `Idempotency-Key`** on any request. A query field the route does
  not take (`environment`, `merchantId`, …) is `400 VALIDATION_ERROR`.
- **Chained variables**: `List Connections`, `List Accounts` and `List
  Transactions` store the first row's id in `bank_connection_id`,
  `bank_account_id` and `bank_transaction_id` when the variable is empty; set one
  yourself to read another record. Run the folder in order.
- **Transaction window**: `bank_booked_from` / `bank_booked_to` (bank date,
  ISO-8601 with a time zone, at most 92 days apart; a wider window is `400
  bank_connect.validation.invalid` with `details.reason: range_too_large`). Write
  an offset as `%2B03:00` or use `Z`: a bare `+` in a query string reads as a
  space.
- `Request Account Sync` answers `202` with `syncStatus` `QUEUED` or `SCHEDULED`
  (`scheduledAt`); it never reads earlier than the bank's minimum interval. Too
  many sync requests for one key in a minute is `429 RATE_LIMITED` with
  `Retry-After`; a connection that is not `ACTIVE` or `DEGRADED` is `409
  bank_connect.connection.not_active`.
- New transactions arrive by the `bank_account.transaction.received` webhook
  (subscribe a `BANK_CONNECT` endpoint to `bank_account.*`).

## Sanction

Both payment collections have a **Sanction** folder for `/api/v1/sanction`, one
request per API-key route (the Node SDK's `SANCTION_ROUTES`,
`node/src/sanction/sanction-values.js`): Screen Name, Screen Wallet, Screen
Account, Screen Transaction, Screen Public Procurement Ban, Screen Adverse Media,
Evaluate Behavioral Alert, List Screening History, Register Monitoring, List
Monitoring Alerts, List Monitored Entities, List Monitoring Matches, Get Dataset
Freshness, Search Entities, Get Entity Profile, Get Entity Graph, Get Indirect
Exposure, Get Ownership Aggregation and List Blacklist Entries. The folder is the
same in both collections, every request carries example responses, and the names
in the bodies are fictional.

- **Auth:** the access token minted from the key. The collection signs every
  request anyway; the sanction routes do not need the signature.
- **The key needs** the `SANCTION_SERVICE` product and `sanction:view_results`
  (otherwise `403`).
- **Matches, not verdicts.** An empty `matches` / `hits` is clear only when
  `status` is `success` and `coverageStatus` is `COMPLETE`. A screening that
  cannot run (no list publication) is `503` with `status: "failure"`; never read
  it as "no match". Public procurement ban screening is `PARTIAL` while the
  Turkish KİK list is unpublished (`uncoveredSources`).
- **Ids:** the top-level `requestId` is the HTTP request's;
  `data.screeningRequestId` is the screening's.
- **Chained variables:** `Screen Name` stores `data.screeningRequestId` in
  `sanction_screening_request_id` and, when `sanction_entity_id` is empty, the
  first match's `entityId`; `Search Entities` fills `sanction_entity_id` when it
  is empty. The entity requests read `sanction_entity_id`.
- Not in the folder: the screening report PDF (panel session only), adding
  deny-list entries, analyst decisions and case assignment (permissions an API
  key does not carry) and the list-source syncs.

## Insurance

Both payment collections have an **Insurance** folder for `/api/v1/insurance`
(product `INSURANCE_SERVICE`): one request for every Merchant API insurance route,
in five sub-folders and in run order. The folder is the same in both collections.

- **Products & Reference Values**: `Search Insurance Products` (before the payment
  exists, from the items it will carry), `List Insurance Products for a Payment`
  (from the basket recorded with `payment_id`), `List Insurance Products Sold
  Without a Basket Item` (no `paymentIntentId`; quote these with neither
  `paymentIntentId` nor `context`), `List Cities` and `List Districts` (Lunixi
  reference codes). An empty product list means insurance is not offered; it is
  not an error. A quote names the insurance company of each option
  (`underwriter`) and lists the companies it could not price
  (`excludedOptions`). `Create Insurance Quote (paymentIntentId, merchant data)`
  prices the payment's recorded basket with only `insuranceType`, `currency` and
  `paymentIntentId`: the items' `insuranceContext` and `insuranceData` (from
  `Payments / Checkout › Create Checkout Intent (Insured Item + insuranceData)`)
  are merged by Lunixi; products answer `prefill`, `providedFields` (masked),
  `quoteReady` and `insuranceDataIssues`.
- **Premium in Your Lunixi Payment**: quote → order → `Create Checkout Intent
  (Ticket + Premium)` (the ticket exactly as quoted plus the premium item: `id` =
  the order id, `itemType: VIRTUAL`, `price` = the premium; `amount` is the sum) →
  bind → order, policy document, cancel, refund premium (empty body). Pay in the
  Checkout Form with `checkout_token`; the policy is requested once the premium is
  captured.
- **Premium Collected Outside Lunixi**: quote → order → confirm payment → issue
  policy → order, policy document, cancel, refund premium (`externalRefund`).
- **Orders & Reconciliation**: list orders, the reconciliation summary, its rows and
  the CSV export.
- **Leads**: `Submit Insurance Lead` → `List Insurance Leads`, `Get Insurance Lead`,
  for the insurance types sold by request only (no quote, premium, order or
  policy). The body is the person and the type object of the lead schema; the
  example is a Trafik / Kasko lead (`insurance_lead_type`
  `MOTOR_THIRD_PARTY_LIABILITY`, or `MOTOR_COMPREHENSIVE`) with `vehicle`. The
  answer is `SUBMITTED` or `UNKNOWN` (not sent again); an insurer refusal is
  `422 insurance.lead.rejected`.

- **Signed on every request**, reads included; the collection signs every gateway
  request. Unsigned is `401 AUTH_HEADERS_MISSING`; without the `INSURANCE_SERVICE`
  product `403 PRODUCT_NOT_ENABLED`. The insurer connection is set up in the Lunixi
  dashboard. A TEST key (`mk_test_…`) works on test insurance orders only.
- **Idempotency-Key** (`insurance-…-{{$guid}}`, fresh on every send) is on create
  order, confirm payment, issue policy, cancel, refund premium and submit lead, where
  the gateway requires it, and on bind payment, where it is optional. Pin it to a fixed value to
  test a replay.
- **Set before running**: `insurance_insured_identity_type`,
  `insurance_insured_identity_number`, `insurance_insured_birth_date`,
  `insurance_insured_email`, `insurance_insured_phone`, `insurance_ticket_pnr` and
  `insurance_ticket_number`: the insured person and the ticket, as your checkout
  collects them; for a lead also `insurance_vehicle_plate`,
  `insurance_vehicle_registration_serial` and
  `insurance_vehicle_registration_number` (the lead's person is the insured above).
  They are secret and empty in the templates; keep real personal data
  out of shared workspaces. The policy-stage fields (PNR, ticket number, e-mail,
  phone) go into the quote: there is no later request for them.
- **Chained variables**: `List Cities` fills `insurance_city_code` when it is empty;
  a quote stores its first `QUOTED` option whose premium you collect
  (`premiumCollectedBy: MERCHANT`) in `insurance_quote_id`, `insurance_terms_version`
  and `insurance_terms_sha256`; an order stores `insurance_order_id`,
  `insurance_premium_amount` and `insurance_payment_amount` (ticket + premium); an
  order answer with a policy stores `insurance_policy_id`; a lead stores
  `insurance_lead_id`. Each flow acts on the order it created. Insurance answers never overwrite `payment_id`.
- **Results arrive by webhook** (subscribe an `INSURANCE_SERVICE` endpoint to
  `insurance.*`): `insurance.policy.issued`, `insurance.policy.failed`,
  `insurance.refund.required`, `insurance.policy.document_ready`,
  `insurance.policy.cancelled`, `insurance.refund.completed`; for a lead
  `insurance.lead.submitted` (a lead summary, no personal data). The policy document,
  cancel and refund work once the policy is issued.
- `Get Policy Document` answers a PDF and `Export Reconciliation (CSV)` a CSV file;
  use **Send and Download**. The reconciliation period is `insurance_period_from` /
  `insurance_period_to` (with a time zone, at most 366 days; write an offset as
  `%2B03:00` or use `Z`).
- An insurer that collects the premium itself (`premiumCollectedBy: PROVIDER`) cannot
  be completed through this API yet; the folder always picks an option you collect.

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
templates. For the Bank Accounts folder it checks, per collection: one request per
bank-connect route, every request signed, no body and no `Idempotency-Key`, only
query fields the gateway accepts (the Node SDK's `BANK_CONNECT_FILTERS` in
`node/src/bank-connect/bank-connect-values.js`), that the detail and sync requests
use the ids the lists answered, that a pinned id is not overwritten and
`payment_id` stays untouched, that the example responses use the gateway envelope
and carry no unmasked IBAN, and that the folder is the same in both collections
with its variables declared in both environment templates.
For the Payment Methods folder it checks, per collection: every request signed,
`Idempotency-Key` on every `direct/payment` and on no action request, every body
field one the gateway accepts (the Node SDK's `DIRECT_METHOD_PAYMENT_FIELDS` and
`PAYMENT_ACTION_CONFIRM_FIELDS`, `node/src/payment/payment-method-values.js`) with
only the method's own block, that resend targets the action the payment opened and
confirm the one resend opened, and that the folder is the same in both collections.
The pre-authorization examples send the typed `preauth` field and no request uses
`metadata.autoCapture`. Every checkout and direct payment body carries an integer
`amount` equal to its basket total and neither `price` nor `paidPrice` (the Node
SDK's `REMOVED_AMOUNT_FIELDS`); a promissory-note schedule adds up to `amount`.
For the Promissory Notes and Reference folders it checks, per collection: every
request signed, `Idempotency-Key` on the intent and on both `direct/payment`
requests, bodies the gateway accepts with exactly one of `schedule` / `noteCount`
and no hard-coded `providerCode` (the Node SDK's plan rules,
`node/src/payment/promissory-note-values.js`), that list, document and cancel use
the payment the schedule example started and cancel sends the open note the list
answered, and that the folders are the same in both collections with their
variables declared in both environment templates.
For the Sanction folder it reads the Node SDK's `SANCTION_ROUTES`,
`SANCTION_NESTED_FIELDS` and `SANCTION_VALUE_SETS` and checks, per collection:
exactly one request per route, every request carrying the minted access token and
no `Idempotency-Key`, only query and body fields the route takes with the required
ones (and one of each `anyOf` group) present, nested parties, accounts and
identifiers and value sets (risk domains, modes, subject types) as the SDK checks
them, that the entity requests use the entity and screening ids the screening
answered while `payment_id` stays untouched, that the example responses use the
gateway envelope with `sanction.*` codes, and that the folder is the same in both
collections with its variables declared in both environment templates.
For the Insurance folder it checks, per collection: every Merchant API insurance route
is in the folder and every request is signed; the `Idempotency-Key` is present where the
gateway requires it, absent where the route takes none, and in the gateway's format;
every body field and query field is one the gateway accepts (the Node SDK's
`node/src/insurance/insurance-values.js`); the order uses the option the quote just
answered with its terms sent back unchanged; the payment carries the quoted ticket and
the premium item of the order, and `amount` is their sum; each flow acts on its own order;
the documents use the policy an order answered; the lead carries no sale field and its
read uses the lead the submit answered; `payment_id` stays untouched; the folder
is the same in both collections; and its variables are declared in both environment
templates, with the insured person's, the ticket's and the lead vehicle's fields secret
and empty.

## Docs

- `docs/SIGNING_AND_TOKEN_AUTOMATION.md`
- `standalone/THIRD_PARTY_NOTICES.md`
