<p align="center">
  <img src="assets/banner.svg" alt="occultation — what does unlinkability cost per action, and what breaks when it runs out?" width="100%">
</p>

<p align="center">
  <img alt="Rust 2021" src="https://img.shields.io/badge/rust-2021%20%C2%B7%201.90%2B-CFFF04?style=flat-square&labelColor=0A0A0A">
  <img alt="364 tests" src="https://img.shields.io/badge/tests-364%20passing-CFFF04?style=flat-square&labelColor=0A0A0A">
  <img alt="Apache 2.0" src="https://img.shields.io/badge/licence-Apache--2.0-CFFF04?style=flat-square&labelColor=0A0A0A">
  <img alt="paper included" src="https://img.shields.io/badge/paper-included-CFFF04?style=flat-square&labelColor=0A0A0A">
</p>

---

## "Both halves fit the budget"

A desk study costed anonymous credentials for autonomous agents against a
15 ms per-action budget. BBS+ presentation: about 13.8 ms. Verification: about
4.2 ms. Each one is under 15 ms, so each was marked acceptable, and the
construction was declared viable.

An action pays for both.

```console
$ occultation bench --composed

PUBLISHED — not measured on this stack. Source: research/Accountable Unlinkable Agent Identity.md
  COMPOSITION                              PRESENT    VERIFY     TOTAL  VERDICT
  naive (no pool, no cached pairings)     13.80 ms   4.20 ms  18.00 ms  MISSES by 3.00 ms
  cached pairings only                    13.80 ms   1.10 ms  14.90 ms  MARGINAL — 0.10 ms spare, which is not headroom
  pre-computation pool + cached pairings   2.80 ms   1.10 ms   3.90 ms  fits, 11.10 ms spare
```

18 ms against a 15 ms budget. The middle row is the more interesting failure:
cached pairings bring it to 14.9 ms, which is *under* the limit — by 100 µs,
with nothing left for the application, the network, or writing the evidence
record. This tool reports that as `MARGINAL` rather than a pass, because
calling it a pass is how the original error was made twice.

The mistake is in the addition, not in the silicon. Our hardware is much
faster — the composed path costs about 14× less here — and that changes
nothing about the arithmetic.

## What that turns into

Only one composition fits, and it is the one that depends on a pool of
pre-computed blinding factors. So a performance question becomes a security
question: **what happens when the pool runs out under burst?**

There are two available behaviours. Stall, or reuse. This tool stalls, and
reuse is not configurable — because we can show exactly what reuse costs.

Two presentations sharing one blinding factor have the same `Abar` and `D`, so
a relying party links them on sight. Worse, the two transcripts carry different
challenges over the same commitments, so the witness falls out by subtraction:

```
e    = (ê₁ − ê₂) / (c₁ − c₂)
m_j  = (m̂_j₁ − m̂_j₂) / (c₁ − c₂)
```

The signature scalar and every undisclosed attribute, recovered by anyone who
sees both. Reuse does not weaken unlinkability. It hands over the credential.
The test suite performs that extraction against known values rather than
asserting it.

Stalling is not free either:

```console
$ occultation pool --burst 5000 --duration 2s --refill 700us --online 60us

  requests             10000
  served from pool     89
  stalled              9911

  POOL EXHAUSTED

  idle response        60.000 µs
  amplification        82591.0x  (peak over this 2.0s window)

  duration-invariant figures (do not move with --duration):
  overload factor      3.50x arrivals over refill
  growth per request   8.33x idle-response added to each successive stall
  onset request        89

  distinct blinding factors issued   10000
  blinding-factor reuse events       0
  real pool exhaustions              9913
```

The pool empties after 89 requests and every one of the remaining 9,911 waits.
The delay does not plateau — it grows for as long as the burst lasts, so an
observer reads the agent's load, and the burst's duration, off response latency
alone. That is a side channel the design has to answer for, and nobody had
asked the question.

## And the anonymity set may not be there at all

Unlinkable credentials are worth nothing if the hardware underneath is
distinguishable. TDX quote collateral — TCB level, PCS chain, microcode — is
itself a fingerprint, so two agents on different patch levels are separable
*even under perfect ECDAA*.

```console
$ occultation anonymity --fleet examples/fleet-drifted.toml

  fleet size            120
  distinct TCB configs  5
  smallest set          1
  singletons            1
  effective set size    52.73
  entropy               1.470 bits

  SIZE   GROUPS
  71     us-east-pool-patched
  34     us-east-pool-pending
  11     eu-west-rack-7
  3      us-east-canary
  1      us-east-rebuilt-0419
```

120 identical hosts. Six weeks of entirely ordinary drift — a patch wave 60%
done, a rack that missed two maintenance windows, one machine rebuilt last
week — and the largest anonymity set is 71, with one host alone on its
configuration before any credential is presented. Nothing exotic happened.

**These fleets are synthetic, hand-authored fixtures, not telemetry from any
live deployment.** The tool partitions a fleet *description*. Point it at your
own — or put [the gateway](#the-gateway) in front of a real one and let it
partition the traffic instead.

The three things named above — TCB level, PCS chain, microcode — are the
**desk study's** vocabulary, written before anything was measured. What a real
DCAP quote actually exposes is a different and more specific list, and the
gateway names it exactly; see [Attribute names](#attribute-names-what-the-gateway-actually-partitions-on)
below. They are not silently the same list.

## What is real, and what is not

Read this before trusting any number this tool prints. It is the first thing
in this file for a reason.

### Modelled — no security whatsoever

**ECDAA** (`ModelledEcdaa`) and **threshold ElGamal escrow**
(`ModelledThresholdElGamal`) are stubs. They carry the correct interface and a
representative cost profile. They provide **no anonymity, no soundness, no
confidentiality, and no accountability.** They exist so the cost of the
composed path can be estimated, and for nothing else. Using them for anything
that matters would be a serious mistake.

Four independent barriers, each asserted by test, stop one being mistaken for
the real thing:

1. They cannot be constructed without a `ModelledPermit`, which only
   `--allow-modelled` produces.
2. `AttestationVerdict::Valid` is unreachable from a modelled implementation —
   it returns `ModelledNoSecurity` for every input, including its own honest
   output.
3. Every invocation logs a warning.
4. Every value carries `Provenance::Modelled`, and every number they produce
   prints with `MODELLED` beside it, in the table and in the JSON.

Asking for one is different from accepting what it is: `bench --composed
--with-escrow` requests the modelled escrow tag, and without `--allow-modelled`
alongside it the tool exits 3 and explains why.

### Real, but not interoperable

**BBS+** key generation, signing, verification, presentation and proof
verification, over `blstrs` BLS12-381 against `draft-irtf-cfrg-bbs-signatures`.
Genuine cryptography with genuine security properties — forged signatures fail,
tampered proofs fail, undisclosed attributes stay undisclosed, and each is
asserted by test, including a total-forgery bypass and a replay the test suite
had to be rewritten to catch.

It is **not validated against the draft's test vectors**, so its wire encoding
will not interoperate with another BBS+ implementation. The cost profile is
what this tool is for. Interoperability is not claimed.

### Real

The Ed25519 baseline, the BLS12-381 group and pairing arithmetic, the
pre-computation pool, the anonymity-set calculator, and the timing harness.
`expand_message_xmd` is checked against all six RFC 9380 Appendix K.1 vectors,
plus two more at the length production actually uses, generated by a second
implementation written independently from the RFC.

### And one thing nothing here measures

**No command in this tool measures a pooled presentation's online phase.** The
pooled figure in `bench --composed` is an estimate — two hash-to-scalar
operations — and it is almost certainly too low: it implies a 99% reduction
where the desk study's own pooled figure implies 80%. `occultation pool` does
not measure it either; its default online cost is the same estimate. Every row
that carries it is labelled `ESTIMATED`.

## Where the numbers come from

Every figure is tagged. `measured here (n=…)` was timed on the host that
produced the output. `PUBLISHED — …` was read from a publication and was **not**
measured on this stack; the citation prints with it. `ESTIMATED` is derived
from a cheaper proxy and says what the proxy is.

`results/` is split. `deterministic/` is byte-identical on any host — CI
regenerates it and fails on a diff, so a stale number cannot outlive a code
change. `measured/` is wall-clock timing, regenerated and schema-checked but
not diffed, because failing a build over scheduler jitter teaches everyone to
ignore CI.

## Try it

```console
$ git clone https://github.com/Task-force-for-AI-agents-in-Healthcare/occultation
$ cd occultation
$ cargo test                                   # 364 tests, incl. the four acceptance tests
$ cargo run --release -- bench --composed      # the correction
$ cargo run --release -- pool --burst 5000     # exhaustion, and what it leaks
$ cargo run --release -- anonymity --fleet examples/fleet-drifted.toml
$ ./scripts/regen-results.sh                   # regenerate everything the paper cites
```

## The four commands

| Command | What it answers |
| --- | --- |
| `occultation bench` | What does each primitive cost against an Ed25519 sign-and-verify round trip? |
| `occultation bench --composed` | Does present **and** verify fit in 15 ms — as one path, not two? |
| `occultation pool --burst <rate>` | What happens when the pre-computation pool runs dry? |
| `occultation anonymity --fleet <f.toml>` | How large is the anonymity set once TCB configurations drift? |

Exit codes: `0` success, `1` policy violation (`--min-set`, `--max-stall`),
`2` bad input, `3` a modelled component requested without `--allow-modelled`.

## The gateway

`occultation anonymity` partitions a fleet *description*. `occultation-gateway`
partitions **live traffic**: it is a reverse proxy you put in front of an
agent-facing API, and it measures, request by request, how much a relying
party learns about the counterparties talking to it.

```console
$ occultation-gateway --listen 127.0.0.1:8080 \
                      --upstream http://api.internal:3000 \
                      --pccs-url https://pccs.example/sgx/certification/v4

agent authorized ✓   quote: VERIFIED (TDX 1.0, TCB UpToDate)
  anonymity set     3 of 1847 sessions
  varying           td_attributes, tee_tcb_svn
  session binding   NONE — the quote arrived in a header and is not bound to
                    this TLS session, so a captured quote is replayable
```

Three sentences on that output: the quote really was verified against Intel's
chain; three sessions in this measurement window presented that exact platform
configuration out of 1,847 total; and two attributes are doing the splitting.

### It never rejects

**Phase 1 has no `--enforce`, and it is not a flag someone forgot.** Every
request is forwarded, unconditionally, before any measurement runs — a
malformed quote, no quote, a revoked platform, a panicking verifier, all
forwarded. `forward` and `handle` return `Result<_, Infallible>`, so no `?`
and no `Err` can compile on the request path; the measurement hook runs
*after* the forward, on an owned snapshot, inside a `catch_unwind`; and every
pipeline stage has its own guard so one broken component costs its own
contribution and nothing else. `tests/gateway_failopen.rs` injects a fault at
each stage and asserts the upstream still answers; `tests/gateway_hostile.rs`
does the same with an agent misbehaving on purpose.

This is a measuring instrument in the request path of somebody else's revenue
API. It is allowed to be wrong about a quote. It is not allowed to be the
reason the API is down.

### The verification is real; `Unverified` is not a soft yes

Quote verification is genuine full-chain DCAP verification via
[`dcap-qvl`](https://github.com/Phala-Network/dcap-qvl) — signature, QE report,
PCK certificate chain, TCB status, against collateral fetched from a
provisioning service. Nothing here is modelled. The TCB-override entry points
that would let a caller rewrite TCB data after signature checking are never
called, and CI greps for the whole family of them on every push.

Three verdicts, and the middle one is the one that gets misread:

| | meaning |
| --- | --- |
| `VERIFIED` | the chain checked out. The only verdict that earns a checkmark. |
| `INVALID` | **the agent's** fault — not a quote, or the chain failed. |
| `UNVERIFIED` | **our** fault — we could not check. |

`Unverified` means the gateway could not perform the check: a cold collateral
cache, collateral past its TTL, an unreadable system clock, a platform we hold
no collateral for, a component that panicked. It is **never** a pass, it never
carries an anonymity number, and it never gets the checkmark — a rendering
that put an affirmative ✓ next to `UNVERIFIED` would be a pass signal no
parenthetical could cancel.

The distinction is load-bearing in both directions. Reporting a cold cache as
`Invalid` would blame a counterparty for our own provisioning gap; reporting a
forged signature as `Unverified` would file an attack in the counter an
operator watches for their own infrastructure, and would schedule a
provisioning-service fetch on the agent's say-so.

### The meter cannot tell you whether an agent has been here before

It is the first thing anyone asks for, and the answer is no — structurally, not
as a policy.

A tool that warns a relying party it is quietly building a profile of its
counterparties must not build that profile itself. So the meter keeps exactly
two structures and no third: salted counts of `H(salt ‖ configuration) →
sessions`, and per-attribute marginals of `H(salt ‖ value) → count`. There is
no session identifier anywhere in the module, no map from anything to a
configuration, and no joint distribution. The salt rotates on a configured
interval and rotation clears both structures, so correlation ages out by
construction rather than because somebody remembered to purge it.

What that costs is real and worth naming: **`set_size` counts sessions, not
agents.** One counterparty replaying one attestation twelve times is reported
identically to twelve agents sharing a configuration, and there is no way to
tell them apart without retaining exactly the thing this design refuses to
retain. `tests/gateway_hostile.rs` pins that behaviour rather than hiding it.
Read a set size as an **upper bound** on anonymity, never a measurement of it.

### Header transport does not bind the quote to the session

Phase 1's transport is a base64 quote in a request header. It works with any
client stack, and it is the weakest thing that works: **nothing ties the quote
to the TLS session it arrived on.** A quote captured once can be replayed
forever, and the gateway genuinely cannot detect it — the second presentation
is byte-identical to the first, so it is verified again from scratch and the
two findings are indistinguishable.

The gateway therefore says so, on every finding, on its own line
(`session binding   NONE — …`) and in the JSON as `binding.kind = "unbound"`.
RA-TLS is the answer and it is phase 1b; `AttestationSource` exists as a trait
so that lands as an implementation rather than a reshape.

### Two defences against a meaningless anonymity number, and what neither does

`set_size ≈ rotation × arrival_rate`. A set size is only a measurement of
anonymity when both factors are large enough, and the gateway has one defence
per factor:

- **`refresh::MIN_SALT_ROTATION = 1s`** refuses a rotation interval short
  enough that the store is cleared between observations, which would report
  every request as an anonymity set of one — a tool whose job is flagging low
  diversity claiming maximum anonymity forever. It sees the configured
  interval.
- **`finding::MIN_MEANINGFUL_SESSIONS = 10`** prints a `NOT EVIDENCE` line
  beside any number drawn from an epoch holding fewer than ten sessions,
  because `set_size` cannot exceed `total_sessions` and `1 of 1` reads exactly
  like the finding an operator most fears. It sees the corpus.

**Neither measures the arrival rate, and the honest check needs it.** A
sixty-second epoch is perfectly legal and still collapses every set at one
request a minute; a one-second epoch at a thousand requests a second holds a
thousand sessions and is an honest measurement. Nothing in this gateway
observes its own arrival rate and compares `set_size` against
`rotation × observed_rate`, which is the check that would actually be
correct. Both constants above are **judgement calls**, stated as such at their
definitions, not derived from anything.

Two further limits, both narrower than they sound and both real:

- **The `NOT EVIDENCE` caveat is render-only.** `Finding::to_json` emits
  `set_size` and `total_sessions` as raw numbers with **no flag of any kind**,
  so a dashboard built on the JSON can plot `1 of 1` as an anonymity set of
  one with nothing to warn it. The rendered finding says otherwise; the JSON
  does not. If you consume the JSON, apply the threshold yourself.
- **Rotation is also the only memory ceiling.** Between rotations the meter's
  two maps grow with the number of distinct configurations seen, and
  `td_attributes` and `xfam` are set at TD creation rather than fixed by the
  platform — so a counterparty able to launch TDs can grow them. Choosing a
  rotation interval is choosing a memory ceiling as well as a correlation
  window.

### Attribute names: what the gateway actually partitions on

The `varying` line and the fingerprint behind it are built **only** from
platform *configuration* fields read out of a verified report — never
per-instance measurements (`mr_td`, `mr_enclave`, `mr_signer`, the runtime
measurement registers, `report_data`), which identify a workload rather than a
platform and would collapse every anonymity set to one:

| Platform | Attributes |
| --- | --- |
| TDX 1.0 | `fmspc`, `tee_tcb_svn`, `mr_seam`, `mr_signer_seam`, `seam_attributes`, `td_attributes`, `xfam` |
| TDX 1.5 | the above, plus `tee_tcb_svn2` |
| SGX | `fmspc`, `cpu_svn`, `attributes`, `misc_select`, `isv_prod_id`, `isv_svn` |

**This is not the list further up this page, and the difference is not
cosmetic.** The desk study — and `docs/STANDARD-MAP.md`'s C5.1.4 row, and the
paper — describe the attestation fingerprint as "TDX module version, CPU SVN,
PCE SVN, microcode revision, QE identity, PCS chain". That was written before
any quote had been parsed. Against `dcap-qvl` 0.6 there is **no `pce_svn` and
no `microcode`** on any report type: the PCE SVN lives in the PCK certificate
extension, not the report body, and microcode revision is not exposed as a
field at all. Where the two lists overlap they overlap loosely — "TDX module
version" is `mr_seam` plus `mr_signer_seam`, and "CPU SVN" is `tee_tcb_svn` on
TDX and `cpu_svn` on SGX.

The theorised fingerprint has not been rewritten to match, because it is a
record of what the desk study claimed. Where the gateway measures something
different, this is the list that is real.

### Metrics

Three Prometheus counters, on a **separate listener** defaulting to loopback:

```console
$ curl -s localhost:9469/metrics | grep gateway_
gateway_requests_total{verdict="verified"} 1847
gateway_requests_total{verdict="unverified"} 210
gateway_quotes_total{platform="tdx_v10",tcb_status="up_to_date"} 1831
gateway_unverified_total{why_kind="collateral_absent"} 204
```

Separate rather than a route on the proxy port, because the proxy forwards
every request unconditionally: a `/metrics` route there would either be
swallowed by the forward, or carve `/metrics` out of the URL space of the API
being fronted. `GET /metrics` on the proxy port is still just a request, and
the upstream still answers it.

Every label is a fixed-size Rust enum with a hand-written encoder and no
wildcard arm, so **cardinality is bounded by construction** — a new platform
variant fails the build rather than silently minting a label. Free text never
reaches a label: an FMSPC in an `Unverified` reason would be a per-platform
identifier retained indefinitely in a time-series database, so reasons are
classified into a fixed set of buckets instead.

That classifier is keyword-matched against `verify.rs`'s wording, which is
prose and can be reworded. **A nonzero and rising `why_kind="other"` rate is
the signal that it has drifted** — the bucket exists so an unrecognised reason
is counted honestly rather than guessed into the wrong one, and a steady
stream of them means the keywords no longer match the messages, not that
something new is happening.

Failing to bind the metrics listener is logged loudly and the gateway starts
anyway. Refusing to front an API because port 9469 was taken would be the same
mistake as rejecting a request over a bad quote.

### What phase 1 is not

No `--enforce`, no RA-TLS, no credential verification, no BBS+ in the request
path. Header transport, real quote verification, the meter, findings, metrics,
and a hostile-agent fixture. `Unverified` is a gap we admit to, not a pass.

## How this maps to the standard

occultation is a research tool for the
[**Proof-of-Control Standard**](https://github.com/AAI-Society/ov-poc-standard).
C5 Identity carries an open question the standard has not answered; this tool
supplies the evidence it needs, and finds that four requirements are in
structural tension with the answer:

| | Standard | |
| :-- | :-- | :-- |
| ✅ | **C5.2** — *`[WG-INPUT NEEDED]`: whether the standard supports verifiable-but-unlinkable identity binding as an implementer-selectable option, **and how*** | measures what the option costs per action, and what breaks when it runs out |
| ⚠️ | **C5.1.1** — every execution record carries the agent **and** principal identifier | the field a profile must suspend, not satisfy |
| ⚠️ | **C5.1.4** — the credential is bound to an attested execution environment | the binding leaks: TCB collateral is itself a fingerprint, and 120 identical hosts split 71/34/11/3/1 |
| ⚠️ | **C5.2.2** — a receiver validates sender identity from published key material | under unlinkability there is no persistent sender identity to validate |
| ⚠️ | **C7.3.1** — records hash-chained so reordering invalidates the chain | a global chain links every action by construction; decoupling it surrenders *no action was deleted* |
| ⚡ | **C10.1.4** — the statement lists properties met and Tier reached | it must also name which identity profile is in force — a verifier's capabilities differ |

**[→ Full mapping, with what it costs and what is only modelled](docs/STANDARD-MAP.md)**

## The paper

[`paper/main.pdf`](paper/main.pdf) — *What Unlinkability Costs at Agent Action
Rates: A Composed-Path Measurement and the Soundness of Pre-Computation.*
Builds with `cd paper && tectonic -Z shell-escape main.tex`.

Every figure in its results section is read from `results/` at build time.
None of them is typed by hand.

Supporting tool for **P05 — Accountable but Unlinkable Agent Identity**, part
of the [Proof-of-Control](https://github.com/Task-force-for-AI-agents-in-Healthcare)
research programme. Sibling tools: **parallax** (residual trust in attestation
tiers) and **transit** (effect binding).

## Licence

Apache-2.0 throughout, code and paper alike. See [`LICENSE`](LICENSE) and
[`NOTICE`](NOTICE). Copyright Advanced AI Society and the Proof-of-Control
contributors.
