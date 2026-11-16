# Update webhook contract fixtures

These files are the wire contract between the update webhook sender (this repo,
`crates/y-sweet/src/update_webhook.rs`) and its receiver.

| File | What it is |
| --- | --- |
| `batch.json` | The exact request body the dispatcher sends for a batch of three events (seq 41 to 43) with `gap_before: true`: one actor with both fields, one with `user_id: null`, one `actor: null`. |
| `empty-gap-batch.json` | The exact request body of an empty batch that only carries the gap flag. |
| `signature.json` | The `X-Y-Sweet-Signature` value for each body, for the given `secret` and `X-Y-Sweet-Timestamp`. |
| `CHECKSUMS.sha256` | The SHA-256 of each of the three files above, in `sha256sum` format. Not a fixture itself: it is what keeps the two copies of the fixtures the same (below). |

The bodies are byte-exact: no trailing newline, because the sender emits none. Verify signatures
against the raw bytes.

## Two copies, kept the same by `CHECKSUMS.sha256`

The receiver repo keeps a byte-identical copy of the three fixture files **and of
`CHECKSUMS.sha256`** in `apps/web/lib/domain/models/y-sweet-updates/contract/`. Nothing copies
one repo into the other, so the checksum file is the link between them:

- Each repo has a test that recomputes the SHA-256 of its fixture files and compares them with
  its `CHECKSUMS.sha256`. Here it is `contract_fixtures_match_their_checksums`; the receiver
  repo carries the same test over its copy.
- So a fixture cannot change in either repo without that repo's `CHECKSUMS.sha256` changing in
  the same commit, or its test fails.
- And the two `CHECKSUMS.sha256` files must be identical. A change to one is the signal, in
  review and to whoever makes it, that the other repo needs the same change. Compare them with
  `diff`, or check a copy from anywhere with `sha256sum -c CHECKSUMS.sha256`.

**A format change must update both repos**: the fixtures, the checksum file, and the code on
each side.

## What checks the fixtures against the sender

The test `contract_fixtures_match_what_the_sender_produces` builds the bodies through the real
`prepare()` and `sign()` and fails if any file differs by a byte. To regenerate the fixtures and
`CHECKSUMS.sha256` after an intended format change:

```sh
UPDATE_CONTRACT_FIXTURES=1 cargo test -p y-sweet contract_fixtures
```

(`CHECKSUMS.sha256` is the output of `sha256sum batch.json empty-gap-batch.json signature.json`
run in this directory.) Then copy the three fixture files and `CHECKSUMS.sha256` to the receiver
repo and update its code and tests.
