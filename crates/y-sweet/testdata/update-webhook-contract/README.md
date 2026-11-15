# Update webhook contract fixtures

These files are the wire contract between the update webhook sender (this repo,
`crates/y-sweet/src/update_webhook.rs`) and its receiver.

| File | What it is |
| --- | --- |
| `batch.json` | The exact request body the dispatcher sends for a batch of three events (seq 41 to 43) with `gap_before: true`: one actor with both fields, one with `user_id: null`, one `actor: null`. |
| `empty-gap-batch.json` | The exact request body of an empty batch that only carries the gap flag. |
| `signature.json` | The `X-Y-Sweet-Signature` value for each body, for the given `secret` and `X-Y-Sweet-Timestamp`. |

The bodies are byte-exact: no trailing newline, because the sender emits none. Verify signatures
against the raw bytes.

The receiver repo keeps a byte-identical copy in
`apps/web/lib/domain/models/y-sweet-updates/contract/`. **A format change must update both.**

The test `contract_fixtures_match_what_the_sender_produces` builds these through the real
`prepare()` and `sign()` and fails if any file differs by a byte. To regenerate after an
intended format change:

```sh
UPDATE_CONTRACT_FIXTURES=1 cargo test -p y-sweet contract_fixtures
```

Then copy the directory to the receiver repo and update its tests.
