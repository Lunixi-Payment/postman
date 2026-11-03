# Changelog

## Unreleased

- Physical POS: add a **Device Identity** subfolder to both payment collections (List Device Keys, Revoke Device Key, Revert Device Enrollment, Revoke Activation Code; signed, no `Idempotency-Key`) and the `pos_device_key_id` variable to both environment templates.

## 2026-11-01

- Align public payment and Physical POS request/response examples with canonical minor-unit string amounts. Quantities and rates remain numeric.
- Publish the current collection snapshots and signing documentation; Postman collections do not use SDK package version tags.
