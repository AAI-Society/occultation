# P05 arXiv Preprint

LaTeX source for *What Unlinkability Costs at Agent Action Rates: A Composed-Path
Measurement and the Soundness of Pre-Computation*.

**Status: working draft for co-author review — not yet submitted.**

**Prose style.** Plain declarative section titles ("The Problem", "What Others Have
Built", "What We Still Don't Know"), examples before abstractions, and explicit
statements of what is *not* known or claimed — the same register as the standard's
own preprint in `../../ov-poc-standard/paper/`.

The measured results in Section 6 come from the reference implementation in
[`../`](../README.md); regenerate them with `../scripts/regen-results.sh` from the
repository root.

## Build

```bash
cd paper
tectonic -Z shell-escape main.tex
```

Output: `main.pdf`. `-Z shell-escape` is passed for consistency with the sibling
papers in this series; this paper has no listing that currently requires it.

## Before Submission — Required Steps

1. **Co-author consent.** The author list mirrors the Advanced AI Society
   leadership, board, and advisory board as published at
   [advancedaisociety.org/about](https://advancedaisociety.org/about), with Jim
   Schwoebel as first author. Every listed individual must review the draft and
   consent to authorship; remove anyone who does not. The title-page footnote
   states this.
2. **Citation verification.** Entries in `references.bib` marked `[verify]`
   (Idemix, U-Prove, the BBS+ attribution, the BBS signature draft's author list
   and revision, and SPSEQ-UC) carry bibliographic detail that has not been
   checked against the primary source — confirm venue, page range, and author
   list before submission.
3. **Numbers refresh.** Every table and every inline figure in Section 6 is
   generated. Re-run `../scripts/regen-results.sh` and rebuild; continuous
   integration already regenerates `results/deterministic/` on every push and
   fails the build on a diff, so a stale number there cannot reach `main`. The
   files under `results/measured/` are wall-clock timing and will legitimately
   differ between machines — that is expected, and Table captions in Section 6
   describe them as such.
4. **arXiv metadata.** Suggested categories: cs.CR (primary), cs.CY (secondary).
   License: Apache-2.0, which arXiv accepts as a submission licence, matching the
   licence of the code the paper measures.
5. **Modelled-component audit.** Every claim in the paper that rests on ECDAA
   or threshold escrow must say so in the sentence that makes it, not in a
   footnote. Re-read the results section looking for any figure that would
   mislead a reader who skipped §3's table.

## Files

| File | Purpose |
| --- | --- |
| `main.tex` | The paper (compiles with tectonic, XeTeX engine) |
| `references.bib` | Bibliography: standards, RFCs, and the cryptography literature the construction draws on |
| `main.pdf` | Compiled output (gitignored build artifact; rebuild with the command above) |
