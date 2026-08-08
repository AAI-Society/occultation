use crate::baseline::{measure_baseline, Baseline};
use crate::bbs::keys::KeyPair;
use crate::bbs::proof::{prove, verify_proof, verify_proof_prepared};
use crate::bbs::sign::{message_to_scalar, sign, verify};
use crate::bbs::BbsError;
use crate::bls::{hash_to_scalar, Generators, PreparedIssuer, API_ID};
use crate::cost::Source;
use crate::harness::{measure, Sample};
use crate::modelled::{AnonymousAttestation, EscrowTag, ModelledError, ModelledPermit, Provenance};
use crate::report::{Row, Table};
use blstrs::{G1Projective, Scalar};
use ff::Field;
use group::Group;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct BenchOptions {
    pub iters: u32,
    pub seed: u64,
    /// Attributes in the credential.
    pub attributes: usize,
    /// How many of them a presentation discloses.
    pub disclose: usize,
    pub allow_modelled: bool,
    /// Whether the operator asked to include the modelled escrow tag in the
    /// composed presentation cost. `run_bench` enforces that this requires
    /// `allow_modelled` (see its first lines) — the same refusal the CLI's
    /// own guard gives, so the check holds for library callers too, not only
    /// callers that go through the binary. Folding the measured tag into a
    /// composed report is done separately, by `composed_report_with`, which
    /// takes the tag directly rather than reading this field.
    pub with_escrow: bool,
}

impl Default for BenchOptions {
    fn default() -> Self {
        // Ten attributes with two disclosed is the shape P05 describes: an
        // agent proving authorization scope while revealing almost nothing.
        // 1000, not 100. The Ed25519 round trip is the smallest thing in the
        // table and it divides every other row, so at 100 iterations — of
        // which the harness warms up ten — the denominator moved by 60%
        // between runs and the headline multiple ranged 9x to 15x for the
        // same code. A tool whose only product is ratios cannot have a
        // default that is not reproducible.
        BenchOptions {
            iters: 1000,
            seed: 7,
            attributes: 10,
            disclose: 2,
            allow_modelled: false,
            with_escrow: false,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BenchError {
    #[error(transparent)]
    Bbs(#[from] BbsError),
    #[error(transparent)]
    Harness(#[from] crate::harness::HarnessError),
    #[error(transparent)]
    Modelled(#[from] ModelledError),
    #[error("cannot disclose {disclose} of {attributes} attributes")]
    BadDisclosure { disclose: usize, attributes: usize },
}

impl BenchError {
    /// The process exit code this error should produce.
    ///
    /// The binary must not collapse everything to 2: a modelled component
    /// requested without the flag is exit 3, and a caller distinguishing
    /// "you asked for a stub" from "your input was malformed" is the point of
    /// having separate codes at all.
    pub fn exit_code(&self) -> u8 {
        match self {
            BenchError::Modelled(_) => 3,
            _ => 2,
        }
    }
}

/// Everything `bench` measures, kept as structured samples so `bench
/// --composed` can reuse them without re-timing.
#[derive(Debug)]
pub struct PrimitiveCosts {
    pub baseline: Baseline,
    pub g1_mul: Sample,
    pub hash_to_scalar: Sample,
    pub bbs_sign: Sample,
    pub bbs_verify: Sample,
    pub present: Sample,
    pub verify_proof_uncached: Sample,
    pub verify_proof_cached: Sample,
    pub modelled_ecdaa_attest: Option<Sample>,
    pub modelled_escrow_tag: Option<Sample>,
}

pub fn run_bench(opts: &BenchOptions) -> Result<PrimitiveCosts, BenchError> {
    if opts.disclose > opts.attributes {
        return Err(BenchError::BadDisclosure {
            disclose: opts.disclose,
            attributes: opts.attributes,
        });
    }
    // Wired, not merely carried: a library caller who asks for the escrow tag
    // (`with_escrow`) without accepting what it is (`allow_modelled`) gets the
    // same refusal the CLI's own guard gives, rather than having the field
    // read by nothing and the request silently ignored. This does not by
    // itself fold the tag into a composed cost — that is
    // `composed_report_with`, which takes the measured tag directly — but it
    // makes `with_escrow` mean something even to a caller that never goes
    // through the CLI.
    if opts.with_escrow {
        ModelledPermit::from_flag(opts.allow_modelled)?;
    }

    let baseline = measure_baseline(opts.seed, opts.iters)?;

    let kp = KeyPair::generate(opts.seed);
    let gens = Generators::create(opts.attributes);
    let msgs: Vec<Scalar> = (0..opts.attributes)
        .map(|i| message_to_scalar(format!("attribute-{i}").as_bytes()))
        .collect::<Result<_, _>>()?;
    let header = b"occultation bench";
    let ph = b"occultation bench nonce";
    let disclosed: Vec<usize> = (0..opts.disclose).collect();
    let disclosed_pairs: Vec<(usize, Scalar)> = disclosed.iter().map(|&i| (i, msgs[i])).collect();

    let sig = sign(&kp.sk, &kp.pk, &gens, header, &msgs)?;
    let mut rng = ChaCha20Rng::seed_from_u64(opts.seed);
    let proof = prove(&kp.pk, &gens, header, ph, &sig, &msgs, &disclosed, &mut rng)?;
    let prepared = PreparedIssuer::new(&kp.pk.0);

    let s = Scalar::random(&mut ChaCha20Rng::seed_from_u64(opts.seed));
    // `measure` black-boxes the *result* of each call, which stops the
    // compiler from discarding it, but `s` and the message below are the
    // same value on every iteration; a sufficiently aggressive optimizer
    // could still prove the computation itself is loop-invariant and hoist
    // it outside the loop, leaving only a cheap black_box materialization
    // per iteration. These two calls are small and pure enough for that to
    // be plausible, unlike the pairing-heavy BBS+ operations below, so the
    // inputs are black-boxed too.
    let g1_mul = measure("G1 scalar multiplication", opts.iters, || {
        G1Projective::generator() * std::hint::black_box(s)
    });
    let h2s = measure("hash_to_scalar", opts.iters, || {
        hash_to_scalar(std::hint::black_box(b"an agent action"), API_ID).expect("fixed-length DST")
    });

    let bbs_sign = measure("BBS+ sign (issuer)", opts.iters, || {
        sign(&kp.sk, &kp.pk, &gens, header, &msgs).expect("valid inputs")
    });
    let bbs_verify = measure("BBS+ signature verify (holder)", opts.iters, || {
        verify(&kp.pk, &gens, header, &msgs, &sig).expect("valid inputs")
    });

    let mut prove_rng = ChaCha20Rng::seed_from_u64(opts.seed);
    let present = measure("BBS+ presentation", opts.iters, || {
        prove(
            &kp.pk,
            &gens,
            header,
            ph,
            &sig,
            &msgs,
            &disclosed,
            &mut prove_rng,
        )
        .expect("valid inputs")
    });
    let verify_proof_uncached = measure("BBS+ proof verify", opts.iters, || {
        verify_proof(&kp.pk, &gens, header, ph, &disclosed_pairs, &proof).expect("valid inputs")
    });
    let verify_proof_cached = measure("BBS+ proof verify, cached pairings", opts.iters, || {
        verify_proof_prepared(
            &prepared,
            &kp.pk,
            &gens,
            header,
            ph,
            &disclosed_pairs,
            &proof,
        )
        .expect("valid inputs")
    });

    // Modelled components are only executed with a permit. Note that this is
    // the *execution* gate: `bench --composed` can still do arithmetic over
    // the desk study's published escrow figure without one, because reading a
    // number out of a paper is not running a stub.
    let (modelled_ecdaa_attest, modelled_escrow_tag) = if opts.allow_modelled {
        let permit = ModelledPermit::from_flag(true)?;
        let ecdaa = crate::ecdaa::ModelledEcdaa::new(permit);
        let escrow = crate::escrow::ModelledThresholdElGamal::new(permit, 3, 5)?;
        (
            Some(measure("ECDAA attest", opts.iters, || {
                ecdaa.attest(b"measurement").expect("stub cannot fail")
            })),
            Some(measure("escrow tag + DLEQ", opts.iters, || {
                escrow.tag(b"did:web:agent-42").expect("stub cannot fail")
            })),
        )
    } else {
        (None, None)
    };

    Ok(PrimitiveCosts {
        baseline,
        g1_mul,
        hash_to_scalar: h2s,
        bbs_sign,
        bbs_verify,
        present,
        verify_proof_uncached,
        verify_proof_cached,
        modelled_ecdaa_attest,
        modelled_escrow_tag,
    })
}

impl PrimitiveCosts {
    /// The comparison the paper reports: every primitive against an Ed25519
    /// sign-and-verify round trip, not against verification alone.
    pub fn table(&self) -> Table {
        let b = self.baseline.round_trip();
        let src = |s: &Sample| Source::MeasuredHere { iters: s.iters };
        // Every measured row carries its own p95 as well as its median, via
        // `.with_p95(s.p95)` — see the note on `Row::p95`. The baseline row
        // matters most: it is the denominator of every other ratio.
        let mut t = Table::new("Primitive costs against the Ed25519 baseline")
            .with(
                Row::real(
                    self.baseline.sign.label.clone(),
                    self.baseline.sign.median,
                    src(&self.baseline.sign),
                )
                .against(b)
                .with_p95(self.baseline.sign.p95),
            )
            .with(
                Row::real(
                    self.baseline.verify.label.clone(),
                    self.baseline.verify.median,
                    src(&self.baseline.verify),
                )
                .against(b)
                .with_p95(self.baseline.verify.p95),
            )
            .with(
                Row::real(
                    "Ed25519 sign + verify (baseline)",
                    b,
                    src(&self.baseline.sign),
                )
                .against(b),
            )
            .with(
                Row::real(
                    self.g1_mul.label.clone(),
                    self.g1_mul.median,
                    src(&self.g1_mul),
                )
                .against(b)
                .with_p95(self.g1_mul.p95),
            )
            .with(
                Row::real(
                    self.hash_to_scalar.label.clone(),
                    self.hash_to_scalar.median,
                    src(&self.hash_to_scalar),
                )
                .against(b)
                .with_p95(self.hash_to_scalar.p95),
            )
            .with(
                Row::real(
                    self.bbs_sign.label.clone(),
                    self.bbs_sign.median,
                    src(&self.bbs_sign),
                )
                .against(b)
                .with_p95(self.bbs_sign.p95),
            )
            .with(
                Row::real(
                    self.bbs_verify.label.clone(),
                    self.bbs_verify.median,
                    src(&self.bbs_verify),
                )
                .against(b)
                .with_p95(self.bbs_verify.p95),
            )
            .with(
                Row::real(
                    self.present.label.clone(),
                    self.present.median,
                    src(&self.present),
                )
                .against(b)
                .with_p95(self.present.p95),
            )
            .with(
                Row::real(
                    self.verify_proof_uncached.label.clone(),
                    self.verify_proof_uncached.median,
                    src(&self.verify_proof_uncached),
                )
                .against(b)
                .with_p95(self.verify_proof_uncached.p95),
            )
            .with(
                Row::real(
                    self.verify_proof_cached.label.clone(),
                    self.verify_proof_cached.median,
                    src(&self.verify_proof_cached),
                )
                .against(b)
                .with_p95(self.verify_proof_cached.p95),
            );

        for (sample, component) in [
            (&self.modelled_ecdaa_attest, "ECDAA"),
            (&self.modelled_escrow_tag, "threshold ElGamal escrow"),
        ] {
            if let Some(s) = sample {
                t = t.with(
                    Row::new(
                        s.label.clone(),
                        s.median,
                        Source::MeasuredHere { iters: s.iters },
                        Provenance::Modelled {
                            component,
                            reason: "stub; cost stand-in only",
                        },
                    )
                    .against(b)
                    .with_p95(s.p95),
                );
            }
        }

        if self.modelled_ecdaa_attest.is_none() && self.modelled_escrow_tag.is_none() {
            t = t.note(
                "ECDAA and escrow are not shown: they are modelled and require \
                 --allow-modelled to execute.",
            );
        }
        t
    }

    /// What `bench --composed` needs from a measured run.
    pub fn composed_halves(&self) -> (Duration, Duration, Duration) {
        (
            self.present.median,
            self.verify_proof_uncached.median,
            self.verify_proof_cached.median,
        )
    }
}

use crate::cost::{compose, fmt_ms, Composed, CostProfile};
use serde::Serialize;

/// Where a composed row's two halves came from.
///
/// Three-valued, not a boolean, and it carries the citation. A boolean would
/// force the estimated pooled row into one of the two real buckets, and
/// `published: false` on a derived number asserts in machine-readable form
/// that this host measured it. That is a smaller version of the mistake this
/// whole command exists to correct — the desk study presented other people's
/// benchmarks as characterising its own stack — so the tool must not commit
/// it.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RowOrigin {
    MeasuredHere,
    Published { citation: &'static str },
    Estimated { basis: &'static str },
}

impl RowOrigin {
    pub fn is_published(&self) -> bool {
        matches!(self, RowOrigin::Published { .. })
    }
}

/// One composition of a present-and-verify path, judged as a whole.
#[derive(Debug)]
pub struct ComposedRow {
    pub label: String,
    pub composed: Composed,
    pub origin: RowOrigin,
    pub note: Option<String>,
    /// Whether a modelled component's cost was folded into `composed`.
    /// `origin` alone cannot say this: a row with the escrow tag folded in is
    /// still `RowOrigin::MeasuredHere` for the BBS+ halves it also carries,
    /// so a JSON consumer filtering on `origin.kind` would otherwise see a
    /// clean measured row even though a third of its `present` figure came
    /// from a stub. Only the label's `+ MODELLED escrow tag` suffix said so
    /// before this field existed.
    pub includes_modelled: bool,
}

#[derive(Debug)]
pub struct ComposedReport {
    pub desk_study: Vec<ComposedRow>,
    pub measured: Vec<ComposedRow>,
    pub baseline_round_trip: Duration,
    pub measured_ratio: f64,
}

/// Compose the desk study's published figures and this host's measured ones.
///
/// Three compositions each: the naive path, the path with cached pairings
/// only, and the path with both a pre-computation pool and cached pairings.
pub fn composed_report(costs: &PrimitiveCosts) -> ComposedReport {
    let d = CostProfile::desk_study();
    let desk_study = vec![
        ComposedRow {
            label: "naive (no pool, no cached pairings)".into(),
            composed: compose(d.present_naive.cost, d.verify_naive.cost),
            origin: RowOrigin::Published {
                citation: crate::cost::DESK,
            },
            note: Some(
                "13.8 ms and 4.2 ms were each assessed separately against the \
                 15 ms budget and each looked acceptable."
                    .into(),
            ),
            includes_modelled: false,
        },
        ComposedRow {
            label: "cached pairings only".into(),
            composed: compose(d.present_naive.cost, d.verify_cached.cost),
            origin: RowOrigin::Published {
                citation: crate::cost::DESK,
            },
            note: Some(
                "Under the limit with 100 us to spare, which leaves nothing for \
                 application work, network time or evidence writing."
                    .into(),
            ),
            includes_modelled: false,
        },
        ComposedRow {
            label: "pre-computation pool + cached pairings".into(),
            composed: compose(d.present_pooled.cost, d.verify_cached.cost),
            origin: RowOrigin::Published {
                citation: crate::cost::DESK,
            },
            note: Some(
                "The only composition that fits. Pre-computation is load-bearing, \
                 not an optimization."
                    .into(),
            ),
            includes_modelled: false,
        },
    ];

    let (present, verify_uncached, verify_cached) = costs.composed_halves();
    // A pooled presentation removes the group operations from the online path,
    // leaving the challenge hash and the field-arithmetic responses. No
    // command in this tool measures that online phase directly: here it is
    // the presentation minus its group work, approximated by the hash cost,
    // and labelled as an estimate. `occultation pool` does not measure it
    // either — its `--online` cost is either supplied by the operator or
    // defaults to this identical estimate (see `main`'s `online_cost`
    // default), so it is not an independent, more-real source to contrast
    // this row against.
    let pooled_estimate = costs.hash_to_scalar.median * 2;
    let measured = vec![
        ComposedRow {
            label: "naive (no pool, no cached pairings)".into(),
            composed: compose(present, verify_uncached),
            origin: RowOrigin::MeasuredHere,
            note: None,
            includes_modelled: false,
        },
        ComposedRow {
            label: "cached pairings only".into(),
            composed: compose(present, verify_cached),
            origin: RowOrigin::MeasuredHere,
            note: None,
            includes_modelled: false,
        },
        ComposedRow {
            label: "pool (ESTIMATED) + cached pairings".into(),
            composed: compose(pooled_estimate, verify_cached),
            origin: RowOrigin::Estimated {
                basis: "two hash-to-scalar operations; nothing in this tool measures a pooled \
                        presentation's online phase directly yet, `occultation pool` included, \
                        whose default online cost is this same estimate",
            },
            note: Some(
                "The pooled presentation here is a crude estimate, not a measurement, \
                 and it is almost certainly too low: it implies a 99% reduction where \
                 the desk study's own pooled figure implies 80%."
                    .into(),
            ),
            includes_modelled: false,
        },
    ];

    let baseline_round_trip = costs.baseline.round_trip();
    let measured_ratio = if baseline_round_trip.is_zero() {
        f64::NAN
    } else {
        measured[0].composed.total.as_secs_f64() / baseline_round_trip.as_secs_f64()
    };

    ComposedReport {
        desk_study,
        measured,
        baseline_round_trip,
        measured_ratio,
    }
}

/// The measured escrow tag cost, when the operator asked for it and accepted
/// what it is. `None` means the composed measured path excludes escrow, and
/// the report says so.
pub fn composed_report_with(
    costs: &PrimitiveCosts,
    escrow_tag: Option<Duration>,
) -> ComposedReport {
    let mut report = composed_report(costs);
    match escrow_tag {
        Some(tag) => {
            for row in &mut report.measured {
                row.composed = compose(row.composed.present + tag, row.composed.verify);
                row.label = format!("{} + MODELLED escrow tag", row.label);
                // `origin` stays `MeasuredHere` (or `Estimated`) for the BBS+
                // halves the row also carries, so it alone cannot say a stub's
                // cost is folded in; a JSON consumer filtering on
                // `origin.kind` needs this to notice.
                row.includes_modelled = true;
            }
            // `measured_ratio` was computed by `composed_report` against the
            // pre-escrow total. Recompute it here so the rendered "Composed
            // BBS+ costs Nx" headline agrees with the rows above it instead
            // of quietly citing a ratio from before the escrow tag was added.
            report.measured_ratio = if report.baseline_round_trip.is_zero() {
                f64::NAN
            } else {
                report.measured[0].composed.total.as_secs_f64()
                    / report.baseline_round_trip.as_secs_f64()
            };
        }
        None => {
            for row in &mut report.measured {
                // Append, never replace. The estimated pooled row's note is the
                // only place a table reader learns its figure is a crude proxy
                // that is almost certainly too low — the renderer does not
                // print `origin.basis` — and overwriting it here silently
                // stripped that caveat from every CLI run of the command the
                // paper cites.
                let escrow = "excludes the escrow tag, which is modelled; the desk study \
                              attributes 4.6 ms (33%) of presentation to it";
                row.note = Some(match row.note.take() {
                    Some(existing) => format!("{existing} It also {escrow}."),
                    None => escrow.to_string(),
                });
            }
        }
    }
    report
}

impl ComposedReport {
    pub fn render(&self) -> String {
        let mut out =
            String::from("The composed present-and-verify path against a 15 ms budget\n\n");

        out.push_str(&format!(
            "PUBLISHED — not measured on this stack. Source: {}\n",
            crate::cost::DESK
        ));
        out.push_str(&Self::rows(&self.desk_study));
        out.push_str(&format!(
            "\nThe correction: presentation ({p}) and verification ({v}) were assessed \
             separately\nagainst the budget and each looked acceptable. Their sum is \
             {t}, which is over.\n",
            p = fmt_ms(self.desk_study[0].composed.present),
            v = fmt_ms(self.desk_study[0].composed.verify),
            t = fmt_ms(self.desk_study[0].composed.total),
        ));

        out.push_str("\nmeasured here\n");
        out.push_str(&Self::rows(&self.measured));
        // Derived, not asserted. A hardcoded "this host is faster" would print
        // identically on a host where it is false.
        let published_total = self.desk_study[0].composed.total.as_secs_f64();
        let measured_total = self.measured[0].composed.total.as_secs_f64();
        let direction = if measured_total < published_total {
            "cheaper"
        } else {
            "dearer"
        };
        let factor = (published_total / measured_total).max(measured_total / published_total);
        out.push_str(&format!(
            "\nMeasured and published figures differ: the composed path is {factor:.0}x \
             {direction}\nhere than the desk study's figures imply. The composition error \
             is unaffected —\nit is an error in arithmetic, not in hardware. Composed BBS+ \
             costs {ratio:.0}x an\nEd25519 sign-and-verify round trip of {rt} here.\n",
            ratio = self.measured_ratio,
            rt = fmt_ms(self.baseline_round_trip)
        ));

        // The divergence is in shape as well as magnitude, and only one
        // optimization appears on both sides of the table. A uniformly faster
        // host would preserve the desk study's ratio; this one does not, and
        // saying only "smaller" would let a reader assume "proportionally
        // smaller".
        let (dp, dc) = (
            self.desk_study[0].composed.verify.as_secs_f64(),
            self.desk_study[1].composed.verify.as_secs_f64(),
        );
        let (mp, mc) = (
            self.measured[0].composed.verify.as_secs_f64(),
            self.measured[1].composed.verify.as_secs_f64(),
        );
        out.push_str(&format!(
            "\nThe divergence is not uniform. Cached pairings are the one optimization \
             measured\non both sides: the desk study reports them saving {:.0}% of \
             verification, and they\nsave {:.0}% here. So the measured block does not \
             corroborate the desk study's\noptimization structure either, which is a \
             second finding rather than noise.\n",
            (1.0 - dc / dp) * 100.0,
            (1.0 - mc / mp) * 100.0
        ));
        out
    }

    fn rows(rows: &[ComposedRow]) -> String {
        let mut out = format!(
            "  {:<46} {:>10} {:>10} {:>10}  {}\n",
            "COMPOSITION", "PRESENT", "VERIFY", "TOTAL", "VERDICT"
        );
        for r in rows {
            out.push_str(&format!(
                "  {:<46} {:>10} {:>10} {:>10}  {}\n",
                r.label,
                fmt_ms(r.composed.present),
                fmt_ms(r.composed.verify),
                fmt_ms(r.composed.total),
                r.composed.verdict
            ));
            if let Some(n) = &r.note {
                out.push_str(&format!("      {n}\n"));
            }
        }
        out
    }

    pub fn to_json(&self) -> serde_json::Value {
        let rows = |rs: &[ComposedRow]| {
            rs.iter()
                .map(|r| {
                    serde_json::json!({
                        "label": r.label,
                        "origin": r.origin,
                        "composed": r.composed,
                        "note": r.note,
                        "includes_modelled": r.includes_modelled,
                    })
                })
                .collect::<Vec<_>>()
        };
        serde_json::json!({
            "budget_us": crate::cost::BUDGET.as_secs_f64() * 1e6,
            "desk_study": rows(&self.desk_study),
            "measured": rows(&self.measured),
            "baseline_round_trip_us": self.baseline_round_trip.as_secs_f64() * 1e6,
            "measured_ratio_to_baseline": self.measured_ratio,
        })
    }
}

#[cfg(test)]
mod composed_tests {
    use super::*;
    use crate::cost::{BudgetVerdict, BUDGET};

    fn costs() -> PrimitiveCosts {
        // Few iterations: these tests assert structure, not speed.
        run_bench(&BenchOptions {
            iters: 5,
            ..Default::default()
        })
        .unwrap()
    }

    #[test]
    fn the_report_carries_both_profiles() {
        let r = composed_report(&costs());
        assert!(r.desk_study.iter().all(|row| row.origin.is_published()));
        assert!(r.measured.iter().all(|row| !row.origin.is_published()));
        assert_eq!(r.desk_study.len(), 3, "naive, cached-only, pool+cached");
        assert_eq!(r.measured.len(), 3);
    }

    #[test]
    fn the_desk_study_naive_row_misses_the_budget() {
        let r = composed_report(&costs());
        let naive = &r.desk_study[0];
        assert_eq!(naive.composed.total, Duration::from_micros(18_000));
        assert_eq!(
            naive.composed.verdict,
            BudgetVerdict::Misses {
                over: Duration::from_millis(3)
            }
        );
    }

    #[test]
    fn every_row_total_is_the_sum_of_its_halves() {
        // The whole point: nothing is judged against the budget except a sum.
        let r = composed_report(&costs());
        for row in r.desk_study.iter().chain(r.measured.iter()) {
            assert_eq!(
                row.composed.total,
                row.composed.present + row.composed.verify,
                "{} was judged on something other than its sum",
                row.label
            );
            assert_eq!(row.composed.budget, BUDGET);
        }
    }

    #[test]
    fn the_rendered_report_never_shows_a_half_path_verdict() {
        // A verdict beside a presentation-only or verification-only figure is
        // exactly the mistake being corrected. There must be one verdict per
        // composed row and no more.
        let out = composed_report(&costs()).render();
        let verdicts = out.matches("MISSES").count()
            + out.matches("MARGINAL").count()
            + out.matches("fits,").count();
        assert_eq!(
            verdicts, 6,
            "one verdict per composed row, no others:\n{out}"
        );
    }

    #[test]
    fn the_report_states_the_correction_in_prose() {
        let out = composed_report(&costs()).render();
        assert!(out.contains("separately"), "must name the error: {out}");
        assert!(out.contains("18.00 ms"), "must show the sum: {out}");
        assert!(
            out.contains("Accountable Unlinkable"),
            "the citation must reach the reader: {out}"
        );
    }

    #[test]
    fn the_measured_profile_is_labelled_as_diverging_from_the_published_one() {
        let out = composed_report(&costs()).render();
        assert!(out.contains("measured here"));
        assert!(out.contains("PUBLISHED"));
        assert!(
            out.contains("differ"),
            "the report must say the two profiles disagree, not print them silently: {out}"
        );
    }

    #[test]
    fn the_measured_composed_cost_is_a_large_multiple_of_the_baseline() {
        // Host-independent form of "unlinkability is expensive". The desk
        // study says ~70x unoptimized; a large multiple reproduces the
        // qualitative claim without pinning a wall clock.
        //
        // The floor is lower under `cargo test`, which builds unoptimized:
        // ed25519-dalek is pure Rust and loses roughly an order of magnitude,
        // while blstrs' work happens in blst's C, which is compiled optimized
        // either way. The debug ratio is therefore compressed and says nothing
        // about the release one. Run `cargo test --release` for the real
        // figure.
        let floor = if cfg!(debug_assertions) { 2.0 } else { 10.0 };
        let c = costs();
        let r = composed_report(&c);
        let ratio =
            r.measured[0].composed.total.as_secs_f64() / c.baseline.round_trip().as_secs_f64();
        assert!(
            ratio > floor,
            "composed BBS+ was only {ratio:.1}x Ed25519 (floor {floor})"
        );
    }

    /// The JSON form must carry provenance as data, not just as prose in
    /// `render()`. Machine consumers do not read the table's headings, so
    /// each of the three `RowOrigin` variants must be distinguishable in
    /// `to_json` output: a published row keeps its citation, a measured row
    /// declares itself, and an estimated row cannot be mistaken for either.
    #[test]
    fn to_json_carries_the_origin_kind_for_each_of_the_three_variants() {
        let r = composed_report(&costs());
        let v = r.to_json();

        let published = &v["desk_study"][0]["origin"];
        assert_eq!(published["kind"], "published");
        assert_eq!(published["citation"], crate::cost::DESK);

        let measured = &v["measured"][0]["origin"];
        assert_eq!(measured["kind"], "measured_here");

        let estimated = &v["measured"][2]["origin"];
        assert_eq!(estimated["kind"], "estimated");
        assert!(
            estimated["basis"]
                .as_str()
                .unwrap()
                .contains("hash-to-scalar"),
            "an estimate must say what it is derived from: {estimated}"
        );
    }
}
