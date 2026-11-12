# Changelog

## Unreleased

- Payments / Checkout: the basket item of **Create Checkout Intent** in both payment collections carries the optional `productCategory: "MOBILE_PHONE"` (Lunixi product category; unknown values 400, omitting it changes nothing).
- Payments / Checkout: add **Create Checkout Intent (Enabled Installments)** to both payment collections (`enabledInstallments: [1, 2, 3]`, stable `Idempotency-Key` `checkout-installments:{{order_id}}`, `orderId` `installments-{{order_id}}`): the hosted form offers at most 3 installments for that payment.
- Physical POS: add **Start Meal Card Sale** to the Terminal Providers subfolder (`instrument: MEAL_CARD`, `interaction: CODE_DISPLAY`, `terminalProviderId: {{pos_terminal_provider_id}}`, stable `Idempotency-Key` `pos-meal-sale:{{pos_order_ref}}`; stores `pos_payment_id`).
- Physical POS: add an **End of Day** subfolder to both payment collections (Start End-of-Day with a stable `Idempotency-Key` from `pos_device_id` + `pos_settlement_ref`, List / Get End-of-Day Run, account / store / device settlement policy get-set-clear, Preview Effective Policy, List Stores) and a **Terminal Providers** subfolder (List Terminals, List / Add / Update Terminal Provider; add takes a stable `Idempotency-Key` from `pos_terminal_id` + `pos_provider_ref`). New environment template variables: `pos_settlement_run_id`, `pos_settlement_ref`, `pos_store_id`, `pos_terminal_id`, `pos_terminal_provider_id`, `pos_vendor_account_id`, `pos_provider_ref`.
- Physical POS: add a **Device Identity** subfolder to both payment collections (List Device Keys, Revoke Device Key, Revert Device Enrollment, Revoke Activation Code; signed, no `Idempotency-Key`) and the `pos_device_key_id` variable to both environment templates.

## 2026-11-01

- Align public payment and Physical POS request/response examples with canonical minor-unit string amounts. Quantities and rates remain numeric.
- Publish the current collection snapshots and signing documentation; Postman collections do not use SDK package version tags.
