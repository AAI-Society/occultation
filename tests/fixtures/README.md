# Test fixtures

Licence and upstream provenance for every file here are in
[`PROVENANCE.txt`](PROVENANCE.txt). This file is about what each fixture is
*for*, and — more usefully — what it makes reachable and what it does not.

| File | What it is | What it makes reachable |
| --- | --- | --- |
| `tdx-quote.bin` | A real Intel TDX quote off real hardware. FMSPC `b0c06f000000`. | `Quote::parse`, FMSPC extraction, and — with the clock pinned — a genuine full-chain `Verified`. |
| `tdx-quote-collateral.json` | The Intel-issued collateral bundle for that platform. Issued 2025-06-19, **expires 2025-07-19**. | The only route to a real `Verified` verdict anywhere in this crate. |
| `sgx-quote.bin` | A real SGX enclave quote, a different platform. FMSPC `00a067110000`. | The `Report::SgxEnclave` parse path, and "a genuine quote for a platform we hold no collateral for". |

## Why the fixtures have to be real

A fabricated quote cannot carry a PCK certificate chain, so
`intel::quote_fmspc` fails on it and every test built on one stops at
`Invalid` without ever reaching the cache lookup, the collateral logic or the
verifier. A hand-built buffer is a test of `Quote::parse`'s first few bytes
and nothing else.

That is not a hypothetical. Two rewrites on this branch were caused by hostile
inputs that failed earlier than their author expected — `[0u8; 64]`, which
dies on the version field, and `127.0.0.1:1`, which is refused in microseconds
on loopback rather than modelling an unresponsive service. Both looked like
thorough tests and proved nothing.

## The expired collateral, and what it costs

The bundle expired on 2025-07-19. Against a real clock the chain check fails,
so **the only way to obtain a `Verified` verdict is to pin the clock inside
the bundle's validity window** — `verify.rs`'s private `verify_at` takes the
timestamp for exactly this reason, and its tests pass
`NOW_INSIDE_COLLATERAL_WINDOW`.

This has one consequence worth stating plainly, because it bounds what a
whole test file can claim:

> **No integration test can reach `dcap_qvl::verify::verify`.**

`verify_at` is private and `CollateralCache::insert_for_test` is `#[cfg(test)]
pub(crate)`, so from `tests/` there is no way to warm the cache short of a
live provisioning service. Every quote in `tests/gateway_hostile.rs` therefore
bottoms out at `Unverified { why: "no collateral cached …" }`, by
construction rather than by choice.

The chain check against hostile bytes is pinned in-crate instead, where the
clock can be held: see `verify.rs`'s
`a_tampered_quote_fails_the_chain_inside_the_collateral_window`, which
tampers with five distinct signed structures, and
`every_truncation_of_a_real_quote_is_refused_without_panicking`.

## One thing the tampering test learned the hard way

The last 71 bytes of `tdx-quote.bin` (offsets 4935–5006) are zero padding
after the PEM certificate chain. They are outside every signed structure, so
flipping a byte there leaves the quote **verifying** — correctly. The first
draft of the tampering test used `len - 8` as "the signature at the tail" on
the assumption that late meant signed, and asserted a rejection that never
came.

If you add a tampering site, confirm two things: that the pristine quote
verifies under the same clock, and that the tampered one does not. Do not
assume an offset is covered because it is late in the buffer.

## The hardware identifier

`tdx-quote.bin` carries a PPID — a unique per-platform hardware serial — in
the PCK certificate, and `dcap-qvl` surfaces it on every successful
verification. It is **not written down anywhere in this repository**,
including in comments, and the tests that check it does not leak recover it
from the fixture at runtime rather than comparing against a literal. Anyone
who needs the value can extract it from the committed quote; writing it into
a source file is the exact habit `src/gateway/verify.rs` exists to refuse.
