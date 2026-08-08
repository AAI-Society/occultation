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

They require `--allow-modelled`. Without it the tool exits 3 and explains why.
With it, every invocation logs a warning and every number they produce is
printed with `MODELLED` beside it.

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

Every figure the tool prints is tagged. `measured here (n=…)` was timed on the
host that produced the output. `PUBLISHED — …` was read from a publication and
was **not** measured on this stack; the citation is printed with it. There is
no third state and no untagged number.

## Licence

Apache-2.0 throughout, code and paper alike. See `LICENSE` and `NOTICE`.
