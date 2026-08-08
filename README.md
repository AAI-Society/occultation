# occultation

Measures what verifiable unlinkability costs at agent action rates.

Supporting tool for **P05 — Accountable but Unlinkable Agent Identity**.

## What is real and what is modelled

Read this before trusting any number this tool prints.

### Modelled — no security whatsoever

**ECDAA** (`ModelledEcdaa`) and **threshold ElGamal escrow**
(`ModelledThresholdElGamal`) are stubs. They carry the correct interface and a
representative cost profile. They provide **no anonymity, no soundness, no
confidentiality, and no accountability.** They exist so that the cost of the
composed path can be estimated, and for nothing else. Using them for anything
that matters would be a serious mistake.

They never execute without `--allow-modelled`: plain `occultation bench` omits
them and says so in the table's footer. Explicitly asking for one without
accepting it is different from merely omitting the flag — `bench --composed
--with-escrow` requests the modelled escrow tag, and without `--allow-modelled`
alongside it the tool exits 3 and explains why, rather than silently running a
component that provides no security. With `--allow-modelled`, every invocation
logs a warning and every number these components produce is printed with
`MODELLED` beside it.

### Real but not interoperable

**BBS+** key generation, signing, verification, presentation and proof
verification are implemented over `blstrs` BLS12-381 against
`draft-irtf-cfrg-bbs-signatures`. This is genuine cryptography with genuine
security properties: forged signatures fail, tampered proofs fail, and
undisclosed attributes stay undisclosed. Each of those is asserted by test.

It is **not validated against the draft's test vectors**, so its wire encoding
will not interoperate with another BBS+ implementation. The cost profile is
what this tool is for; interoperability is not claimed.

### Real

The Ed25519 baseline, the BLS12-381 group and pairing arithmetic, the
pre-computation pool, the anonymity-set calculator, and the timing harness.

## Where the numbers come from

Every figure `bench` prints is tagged. `measured here (n=…)` was timed on the
host that produced the output. `PUBLISHED — …` was read from a publication and
was **not** measured on this stack; the citation is printed with it.
`bench --composed` has a third tag, `ESTIMATED`, for exactly one row: nothing
in this tool measures a pooled presentation's online phase directly yet
(`occultation pool` included — see `pool`'s `--online` default, which is this
same estimate), so that row is derived from a cheaper proxy instead, and says
so in its own note and in its `origin.kind` in `--format json`.

This tagging scheme is `bench`'s. `pool` and `anonymity` print their own
figures untagged: nothing about them is published or estimated, they are a
plain measurement of a burst simulation and a plain partition of the fleet
file you gave them, and tagging would say nothing a reader doesn't already
know from the command that produced them.

## Commands

| Command | What it does |
| --- | --- |
| `occultation bench` | primitive costs against the Ed25519 baseline |
| `occultation bench --composed` | presentation **and** verification against the 15 ms budget |
| `occultation pool --burst <rate>` | the pre-computation pool under load |
| `occultation anonymity --fleet <f.toml>` | anonymity set size given TCB diversity |

Exit codes: `0` success, `1` policy violation (`--min-set`, `--max-stall`),
`2` bad input, `3` a modelled component was requested without
`--allow-modelled`.

## Two things this tool exists to say

**The naive construction does not fit the latency budget.** The desk study
assessed BBS+ presentation (~13.8 ms) and verification (~4.2 ms) separately
against a 15 ms budget and found each acceptable. Their sum is 18 ms. With
cached pairings it is 14.9 ms — under the limit with 100 microseconds to
spare, which leaves nothing for the application, the network, or writing
evidence. `bench --composed` reproduces this. Pre-computation is load-bearing,
not an optimization.

Measured on modern hardware the absolute figures are roughly an order of
magnitude smaller, and the tool prints those beside the published ones with
the divergence stated. The correction stands regardless: it is an error in
arithmetic, not in hardware.

**Pool exhaustion has exactly two available behaviours and one of them is
catastrophic.** This tool stalls. It never reuses, and reuse is not
configurable. Two presentations sharing one blinding factor are linkable on
sight, and anyone who sees both transcripts recovers the signature scalar and
every undisclosed attribute by subtraction — the repository contains a test
that performs the extraction. Stalling is not free either: `pool` reports the
amplification factor, which is how much of an agent's load an observer can
read off its response latency.

## Benchmarks: two of them, on purpose

`occultation bench` is the artifact the paper cites: one process, seeded RNG,
median-of-n, output committed under `results/`. `cargo bench` runs criterion
microbenchmarks for developers optimizing the code. They will not agree
exactly and are not meant to.

## Reproducing

```bash
cargo test                          # includes the four acceptance tests
./scripts/regen-results.sh          # regenerates everything the paper cites
```

## Licence

Apache-2.0 throughout, code and paper alike. See `LICENSE` and `NOTICE`.
