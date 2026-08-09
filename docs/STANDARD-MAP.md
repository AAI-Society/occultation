# occultation ↔ the Proof-of-Control Standard

Where this tool touches [**AAI-Society/ov-poc-standard**](https://github.com/AAI-Society/ov-poc-standard),
what it supplies, and what it contradicts.

Requirement IDs below link into `0.1/en/`. The standard has not yet decided
whether to support unlinkable identity — C5.2 carries an explicit
`[WG-INPUT NEEDED]` marker pointing at
[Appendix D, issue 2](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x93-Appendix-D_Open-Issues.md).
This tool exists to give that decision a cost basis. Four of the requirements
around it turn out to be in structural tension with the answer, which is a
finding about the standard rather than about any implementation of it.

**Two of the five layers measured here are modelled stubs with no security.**
Every claim below that touches ECDAA or threshold escrow is a claim about
*cost*, never about a security property. See
[What this does not cover](#what-this-does-not-cover).

---

## At a glance

| Standard | What it says today | What occultation does | |
| :-- | :-- | :-- | :-- |
| [**C5.2** Inter-Agent Identity](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C05-Identity.md#c52-inter-agent-identity) | *`[WG-INPUT NEEDED]` — whether the standard supports verifiable-but-unlinkable identity binding as an implementer-selectable option, **and how*** | Measures what the option costs per action, and what breaks when the pre-computation it depends on runs out | ✅ **supplies the evidence** |
| [**C5.1.1**](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C05-Identity.md#c51-agent-and-principal-binding) | Every execution record carries the **agent instance identifier and the principal identifier**, so any sampled action resolves to a named principal (Level 1) | This is the requirement a profile must **suspend**, not satisfy. Cross-RP unlinkability and "resolves to a named principal" cannot both hold for the same relying party | ⚠️ **structural conflict** |
| [**C5.1.4**](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C05-Identity.md#c51-agent-and-principal-binding) | The credential is **bound to an attested execution environment** (Level 3) | The binding leaks what the credential hides. Quote collateral is itself a fingerprint: 120 identical hosts split into 5 groups of 71/34/11/3/1 after six weeks of ordinary drift, one host alone | ⚠️ **contradicts** |
| [**C5.2.2**](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C05-Identity.md#c52-inter-agent-identity) | A receiver validates **sender identity** from published key material, without contacting the sender's operator (Level 3) | Under unlinkability there is no persistent sender identity to validate. The property degrades to *some valid member of a group*, which is a different claim | ⚠️ **needs restatement** |
| [**C7.3.1**](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C07-Evidence-Generation-and-Properties.md#c73-the-tamper-evident-property) | Records are hash-chained or Merkle-anchored so modifying, inserting or **reordering** any record invalidates the chain (Level 2) | A global chain links every action *by construction*, whatever signature scheme wraps it. Decoupling into per-session chains buys unlinkability and surrenders *no action was deleted* | ⚠️ **in tension** |
| [**C7.2.4**](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C07-Evidence-Generation-and-Properties.md#c72-the-contemporaneous-property) | Hardware attestation binds the evidence signing key: the key's digest appears in the attested report body | Whether an anonymous platform attestation can carry that digest without re-emitting a platform identifier is **open**. ECDAA is modelled here, so this tool costs the composition and does not settle it | ⚠️ **open, and modelled here** |
| [**C2.3.1**](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C02-Privacy.md#c23-privacy-preserving-verification-mechanisms) | Where Tier 3 evidence would re-leak protected inputs, substitute a ZK proof, **a selective disclosure**, or a commitment (Level 3) | Supplies a working selective disclosure and its cost: a real BBS+ presentation and proof verification, benchmarked against an Ed25519 baseline | ✅ **implements, and prices** |
| [**C10.1.4**](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C10-Conformance-and-Disclosure.md#c101-conformance-claims) | The statement lists per-claim evidence properties met and Tier reached (Level 1) | It must also name **which identity profile is in force**. A verifier's capabilities differ, and a relying party has to decide by policy whether an anonymous presentation is acceptable at all | ⚡ **proposes an addition** |

---

## The four tensions, in detail

### 1. C5.1.1 is the requirement the profile suspends

C5.1.1 is a Level 1 requirement: *every* execution record carries the agent
instance identifier and the principal identifier. It is the floor of the
domain.

Unlinkability is not a weaker version of that. It is its negation, for one
specific reader. The enterprise still needs the record to resolve to a named
principal; the vendor must not be able to resolve it at all, and two vendors
comparing notes must not be able to either.

So a C5-Unlinkability profile cannot claim C5.1.1 at Level 1 and cannot claim
a partial version of it. It has to say plainly which reader retains the
resolution, and the conformance statement has to name the profile — which is
the C10.1.4 addition above. Two profiles rather than a spectrum keeps
conformance checkable.

### 2. C5.1.4's binding leaks what the credential hides

This is the finding that would matter most to an implementer, and it is
cheap to check.

C5.1.4 binds the credential to an attested execution environment, so it
cannot be exercised from an environment that fails attestation. Good
requirement. But the attestation carries collateral — TDX module version, CPU
SVN, PCE SVN, microcode revision, QE identity, PCS chain — and that collateral
is a fingerprint. Two agents on different patch levels are distinguishable
*even under a perfect anonymous attestation scheme*, because the anonymity set
is not "every agent" but "every agent on an identical TCB".

`occultation anonymity` partitions a fleet by that collateral:

```console
$ occultation anonymity --fleet examples/fleet-drifted.toml

  fleet size            120
  distinct TCB configs  5
  smallest set          1
  singletons            1
  effective set size    52.73
  entropy               1.470 bits
```

120 identical machines, six weeks of drift no operator would describe as
unusual — a patch wave 60% done, a rack that missed two maintenance windows,
one machine rebuilt last week — and the largest anonymity set is 71. One host
is alone on its configuration before it presents anything.

The consequence for the standard is a **deployment threshold, not a yes/no**:
a C5-UP profile is worth little on a fleet whose TCB configurations have
drifted, and a conformance claim that asserts unlinkability without stating
the fleet's configuration diversity is asserting something it has not
measured. `--min-set K` exits non-zero, so the check runs in CI.

**The shipped fleets are synthetic, hand-authored fixtures.** They are not
telemetry. The mechanism is real; the specific numbers are illustrative until
someone points the tool at a live fleet.

### 3. C5.2.2 becomes a different claim

C5.2.2 asks that a receiver validate *sender identity* from published key
material without contacting the sender's operator. Under a group credential
there is no persistent sender identity to validate. What the receiver can
establish is membership: *some* holder of a valid, unrevoked credential issued
by this authority. That is a useful property and it is not the one the text
describes, so the text needs restating rather than relaxing.

Revocation is the unsolved half. Revoking a compromised agent's credential
without linking its past actions, and without an accumulator update whose cost
scales badly, is an open problem in its own right. This tool does not address
it.

### 4. C7.3.1 and unlinkability cannot both hold as written

C7.3.1 requires that reordering any record invalidates the chain. A single
globally ordered chain does exactly that — and links every action by
construction, whatever credential scheme sits above it. Two actions in the
same chain are linked *by the chain*.

The proposed answer is per-session ephemeral chains with roots posted as
re-randomizable commitments. That buys unlinkability at a price the standard
should state explicitly: a global chain proves *no action was deleted*;
independent session chains prove no action was deleted **from a session you
already know about**. An agent could suppress an entire session and the log
would show no gap.

Naming precisely what is surrendered is the contribution here, whichever way
the working group resolves it. This tool does not implement the log layer, so
it costs the credential layer and leaves the chain question open.

---

## What occultation supplies that C5.2 asks for and does not yet define

The `[WG-INPUT NEEDED]` marker asks two things: *whether* to support unlinkable
identity, and *how*. The "how" needs a cost basis, and the cost basis had an
arithmetic error in it.

A desk study assessed BBS+ presentation (~13.8 ms) and verification (~4.2 ms)
separately against a 15 ms per-action budget and found each acceptable. An
action pays for both: 18 ms, which misses. With cached pairings, 14.9 ms —
under the limit by 100 µs, which this tool reports as `MARGINAL` rather than a
pass. Only the composition with a pre-computation pool fits.

That converts the open question from a performance one into a security one.
The pool is load-bearing, so its exhaustion behaviour is part of the profile,
not an implementation detail. On exhaustion there are two behaviours available
— stall or reuse — and reuse is not a tuning choice: two presentations sharing
one blinding factor let an observer recover the signature scalar and every
undisclosed attribute by subtraction. **A C5-UP profile has to specify stall,
and has to state the timing side channel that stalling opens.**

Both figures a working group would need are in `results/`, regenerated by CI:
the composed-path budget verdicts, and the burst behaviour with its
duration-invariant side-channel measures.

---

## What this does not cover

- **ECDAA and threshold ElGamal escrow are modelled stubs with no security
  whatsoever.** They carry a representative cost profile so the composed path
  can be priced, and nothing else. Every claim above about C7.2.4 or about
  accountability is a claim about cost. They require `--allow-modelled`, and
  every number they produce prints with `MODELLED` beside it.
- **The BBS+ implementation is real but not interoperable.** It is not
  validated against `draft-irtf-cfrg-bbs-signatures`' test vectors, so its
  wire encoding will not match another implementation. The cost profile is the
  deliverable.
- **Nothing here measures a pooled presentation's online phase.** That figure
  is an estimate from two hash-to-scalar operations and is almost certainly too
  low; `occultation pool` does not measure it either, and takes it as a given.
- **The evidence-log and transport layers are not implemented.** C7.3 and the
  transport-linkability question (Oblivious HTTP, padding) are discussed above
  and untouched by code.
- **The fleet fixtures are synthetic.** The anonymity mechanism is real; the
  71/34/11/3/1 split is an illustration until run against a real fleet.
- **No claim is made about C5.1.2, C5.1.3, C5.2.1, or the C10.2 disclosure
  format.** Those are [parallax](https://github.com/Task-force-for-AI-agents-in-Healthcare/parallax)'s
  territory or nobody's yet.

---

## Suggested revisions

If the working group resolves issue 2 in favour of supporting unlinkability,
the smallest coherent set of changes is:

1. **C5 gains two named profiles** — `C5-Identified` (default: Ed25519,
   explicit `agent_id`, global linear chain) and `C5-Unlinkability` — rather
   than a spectrum, so conformance stays checkable.
2. **C5.1.1 is scoped per profile**, naming which reader retains resolution to
   a principal.
3. **C5.1.4 gains a fleet-diversity obligation**: a claim of unlinkability
   states the anonymity set the deployment actually achieves, measured rather
   than assumed.
4. **C5.2.2 is restated** as membership validation under the unlinkability
   profile.
5. **C7.3 permits decoupled session chains under C5-UP**, and says explicitly
   what tamper-evidence still means once global order is gone.
6. **C10.1.4 requires the conformance statement to name the identity profile
   in force.**
7. **A new requirement covers pre-computation pool behaviour** under
   exhaustion: stall, never reuse, and disclose the resulting timing channel.

Items 1–2 and 5–6 track P05's own recommendations. Items 3 and 7 come out of
this tool's measurements and were not in the desk study.
