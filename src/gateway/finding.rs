//! The `Finding` an operator reads and the Prometheus metrics an operator
//! graphs. The output layer, and the last place any of the guarantees built
//! by Tasks 1–5 either survive or quietly stop mattering.
//!
//! # The PPID cannot reach here
//!
//! [`Finding`] is built only from [`QuoteVerdict`], [`SessionBinding`] and
//! [`Observation`] — the three types Task 4's verifier boundary and Task 5's
//! meter already hand back with the hardware serial destroyed. Nothing in
//! this module ever touches a `dcap_qvl` report, so there is no field here
//! that *could* carry it: `the_json_form_never_contains_the_ppid_or_a_config_hash`
//! and `the_rendered_finding_also_contains_no_ppid_text` prove the two output
//! paths (`to_json`, `render`) agree with that, rather than assuming it.
//! `Finding` deliberately derives neither `Debug` nor `Serialize` — both
//! `to_json` and `render` are written by hand against the three permitted
//! fields, so the escape hatch a blanket derive would open (a future field
//! added to this struct silently reaching a formatter) does not exist.
//!
//! # `Unverified` is not a soft yes
//!
//! `QuoteVerdict::Unverified` means "we could not check" — a cold cache, a
//! stale one, an unreadable clock. [`Finding::render`] gives it the same
//! all-caps, first-line prominence `VERIFIED` gets, with the reason inline,
//! the same discipline `report::Table::render` uses for `MODELLED` rows (see
//! `a_modelled_row_renders_the_word_modelled_on_its_own_line`'s reasoning: a
//! footnote at the bottom of a long finding is not the same guarantee as a
//! marker on the line itself, which is also why
//! `unverified_is_as_prominent_as_verified_and_says_why` checks the *first
//! line* alone rather than the whole rendering — a whole-output `contains`
//! would pass even if the verdict word moved to a footnote).
//!
//! The banner ahead of `quote: ...` is itself conditional, not fixed text:
//! `VERIFIED` alone earns "agent authorized ✓" — every other verdict gets
//! "agent forwarded (fail-open)". Fail-open means the *request* always goes
//! through regardless of the verdict, but a fixed "authorized ✓" prefix on
//! every line would put an affirmative checkmark next to `UNVERIFIED`, and a
//! checkmark is a pass signal no reworded parenthetical can cancel out.
//! `an_unverified_line_carries_no_checkmark` pins this.
//!
//! The anonymity block — the one place this module prints a number — is
//! gated on **both** `observation.is_some()` *and* the verdict being
//! `Verified`, not on either alone: an `Unverified` or `Invalid` finding has
//! no trustworthy configuration to partition on, so it must never carry a
//! set size, even if a caller (Task 7, say) constructs one with an
//! `Observation` attached anyway — both `Finding` fields are `pub`, so
//! nothing stops that at the type level.
//! `a_verified_finding_with_no_observation_omits_the_anonymity_block_too`
//! and `an_unverified_finding_with_an_observation_still_carries_no_anonymity_number`
//! pin both halves of the conjunction independently.
//!
//! # Attribute names
//!
//! The `varying` line prints whatever [`Observation::varying_attributes`]
//! contains, which — because `LinkabilityMeter::observe` only ever sees a
//! [`crate::gateway::verify::TcbConfig`] built by Task 4's verifier — can
//! only ever be drawn from:
//!
//! - **TDX 1.0** — `fmspc`, `tee_tcb_svn`, `mr_seam`, `mr_signer_seam`,
//!   `seam_attributes`, `td_attributes`, `xfam`
//! - **TDX 1.5** — the above plus `tee_tcb_svn2`
//! - **SGX** — `fmspc`, `cpu_svn`, `attributes`, `misc_select`,
//!   `isv_prod_id`, `isv_svn`
//!
//! There is no `pce_svn` and no `microcode` on any report type (see
//! `verify.rs`'s module docs and Task 4's review against the `dcap-qvl`
//! source). This module's own tests use `tee_tcb_svn` and `xfam` as
//! fixture values rather than either invented name, for the same reason the
//! task brief gives: a rendered finding is operator-facing, and a test whose
//! assertion an operator could mistake for real output must not name an
//! attribute the gateway can never produce.
//!
//! # Metric cardinality is bounded by construction, not convention
//!
//! Every label this module emits — `verdict`, `platform`, `tcb_status`,
//! `why_kind` — is a fixed-size Rust enum with a hand-written
//! [`EncodeLabelValue`] impl whose `match` has **no wildcard arm**: adding a
//! new [`Platform`] variant, for instance, fails this module's build rather
//! than silently falling through to a default label. `platform` reuses
//! [`Platform`] itself (now `Hash`, at coordinator ruling) rather than a
//! local mirror enum — one three-variant enum with one rendering to a
//! Prometheus label, rather than a second copy that agrees with the first
//! only because someone hand-kept them in sync. `platform_display` stays a
//! separate function deliberately: it renders *operator prose* ("TDX 1.0"),
//! a different job from a machine-readable label, and the two are pinned
//! independently (`each_platform_variant_renders_its_own_distinct_label` for
//! the label, `a_verified_finding_states_the_exact_first_line_per_platform`
//! for the prose). `tcb_status` and
//! `why_kind` both start from free text (`QuoteVerdict::Verified.tcb_status`
//! is a `String`; `QuoteVerdict::Unverified.why` likewise) that must never
//! itself reach a label — see [`TcbStatusLabel::classify`] and
//! [`WhyKind::classify`], and `a_free_text_why_containing_an_fmspc_never_reaches_a_metric_label`
//! for the property this whole module exists to hold: a Prometheus label is
//! a database, and a free-text `why` can carry an FMSPC into it.
//!
//! One honest gap: the task brief names exactly four `why_kind` values
//! (`collateral_absent`, `collateral_stale`, `pcs_unreachable`,
//! `unsupported_platform`).
//! [`QuoteVerifier::verify_at`](crate::gateway::verify::QuoteVerifier) in
//! `verify.rs` also produces a fifth `Unverified` reason today — an
//! unreadable system clock —
//! that does not describe any of the four. Silently folding it into one of
//! them (most plausibly `unsupported_platform`) would misreport *why*
//! verification failed, which is exactly the failure mode this module is
//! built to avoid. [`WhyKind`] therefore adds a fifth variant, `Other`, so a
//! `why` this module cannot classify is bucketed honestly rather than
//! mislabeled — still a small, enum-derived string, never the free text
//! itself. `an_unreadable_clock_reason_does_not_pretend_to_be_one_of_the_four_named_causes`
//! pins that this specific, real gap lands in `Other` rather than being
//! guessed at.

use crate::gateway::meter::Observation;
use crate::gateway::source::SessionBinding;
use crate::gateway::verify::{Platform, QuoteVerdict};
use prometheus_client::encoding::{EncodeLabelSet, EncodeLabelValue, LabelValueEncoder};
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::registry::Registry;
use std::fmt::Write as _;

/// What a relying party learns about one request: the quote verdict, whether
/// the transport bound it to this session, and — when the verdict is
/// [`QuoteVerdict::Verified`] and the meter has observed it — the anonymity
/// set it landed in.
///
/// No field here may derive `Debug` or `Serialize` blanket-style; see the
/// module docs for why `to_json` and `render` are written by hand instead.
pub struct Finding {
    pub verdict: QuoteVerdict,
    pub binding: SessionBinding,
    pub observation: Option<Observation>,
}

/// The platform names `verify::tcb_config_from_td10`'s callers actually
/// produce, in the words an operator reads.
fn platform_display(p: &Platform) -> &'static str {
    match p {
        Platform::TdxV10 => "TDX 1.0",
        Platform::TdxV15 => "TDX 1.5",
        Platform::SgxEnclave => "SGX",
    }
}

impl Finding {
    /// Render the finding the way an operator reads it.
    ///
    /// Fail-open binds this too: nothing here may panic. Every branch is a
    /// fixed format string over data this module already owns — there is no
    /// indexing, no parsing, and no I/O for a hostile or malformed input to
    /// reach.
    pub fn render(&self) -> String {
        // Only a genuinely `Verified` quote earns the checkmark. Fail-open
        // means the request is forwarded either way — that is what "agent
        // forwarded (fail-open)" states plainly for the other two arms —
        // but a fixed "authorized ✓" prefix on every line would put an
        // affirmative pass signal directly ahead of `UNVERIFIED` or
        // `INVALID`, which constraint 2 forbids regardless of how the
        // parenthetical reads. See `an_unverified_line_carries_no_checkmark`.
        let (prefix, verdict_word, parenthetical) = match &self.verdict {
            QuoteVerdict::Verified {
                platform,
                tcb_status,
                ..
            } => (
                "agent authorized \u{2713}",
                "VERIFIED",
                format!("{}, TCB {tcb_status}", platform_display(platform)),
            ),
            QuoteVerdict::Unverified { why } => {
                ("agent forwarded (fail-open)", "UNVERIFIED", why.clone())
            }
            QuoteVerdict::Invalid { reason } => {
                ("agent forwarded (fail-open)", "INVALID", reason.clone())
            }
        };

        let mut out = format!("{prefix}   quote: {verdict_word} ({parenthetical})\n");

        // Gated on **both** the `Option` and the verdict, not either alone:
        // an `Unverified` or `Invalid` finding has no trustworthy
        // configuration to partition on, so it must never carry a set size
        // — even if a caller attaches an `Observation` to one anyway, which
        // nothing at the type level prevents (`Finding`'s fields are both
        // `pub`). See `an_unverified_finding_with_an_observation_still_carries_no_anonymity_number`.
        if let (QuoteVerdict::Verified { .. }, Some(obs)) = (&self.verdict, &self.observation) {
            let _ = writeln!(
                out,
                "  anonymity set     {} of {} sessions",
                obs.set_size, obs.total_sessions
            );
            let varying = if obs.varying_attributes.is_empty() {
                "none".to_string()
            } else {
                obs.varying_attributes.join(", ")
            };
            let _ = writeln!(out, "  varying           {varying}");
        }

        match &self.binding {
            SessionBinding::Bound => out.push_str("  session binding   BOUND\n"),
            SessionBinding::Unbound { why } => {
                let _ = writeln!(out, "  session binding   NONE \u{2014} {why}");
            }
        }

        out
    }

    /// The machine-readable form. Built field by field from the same three
    /// inputs `render` uses, never by deriving `Serialize` on `self` — see
    /// the module docs.
    ///
    /// `serde_json::to_value` cannot fail on any of these three types (no
    /// floats, no non-string map keys, no custom `Serialize` that can
    /// error), but `to_json` falls back to `Value::Null` rather than
    /// `.expect(...)` regardless: fail-open means this function may not
    /// panic even if that were ever no longer true.
    pub fn to_json(&self) -> serde_json::Value {
        let verdict = serde_json::to_value(&self.verdict).unwrap_or(serde_json::Value::Null);
        let binding = serde_json::to_value(self.binding).unwrap_or(serde_json::Value::Null);
        let observation = self
            .observation
            .as_ref()
            .map(|o| serde_json::to_value(o).unwrap_or(serde_json::Value::Null));
        serde_json::json!({
            "verdict": verdict,
            "binding": binding,
            "observation": observation,
        })
    }
}

// ---------------------------------------------------------------------
// Metric labels. Every enum below has a hand-written `EncodeLabelValue`
// whose `match` has no wildcard arm, so a new variant anywhere upstream
// fails this module's build instead of silently producing a new label.
// ---------------------------------------------------------------------

/// The `verdict` label on `gateway_requests_total`.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
enum VerdictKind {
    Verified,
    Invalid,
    Unverified,
}

impl VerdictKind {
    fn of(v: &QuoteVerdict) -> VerdictKind {
        match v {
            QuoteVerdict::Verified { .. } => VerdictKind::Verified,
            QuoteVerdict::Invalid { .. } => VerdictKind::Invalid,
            QuoteVerdict::Unverified { .. } => VerdictKind::Unverified,
        }
    }
}

impl EncodeLabelValue for VerdictKind {
    fn encode(&self, encoder: &mut LabelValueEncoder) -> Result<(), std::fmt::Error> {
        let s: &str = match self {
            VerdictKind::Verified => "verified",
            VerdictKind::Invalid => "invalid",
            VerdictKind::Unverified => "unverified",
        };
        encoder.write_str(s)
    }
}

/// The `platform` label on `gateway_quotes_total`.
///
/// [`Platform`] itself, not a local mirror: it now derives `Hash` (see
/// `verify.rs`), so reusing it directly here means there is exactly one
/// three-variant enum and one place its Prometheus rendering is written,
/// instead of two independent copies (this one, plus `verify.rs`'s serde
/// rename) that agree only because someone hand-kept them in sync. This
/// `match` is exhaustive for the same reason every other mapping here is —
/// a fourth `Platform` variant fails this `impl`'s build.
impl EncodeLabelValue for Platform {
    fn encode(&self, encoder: &mut LabelValueEncoder) -> Result<(), std::fmt::Error> {
        let s: &str = match self {
            Platform::TdxV10 => "tdx_v10",
            Platform::TdxV15 => "tdx_v15",
            Platform::SgxEnclave => "sgx_enclave",
        };
        encoder.write_str(s)
    }
}

/// The `tcb_status` label on `gateway_quotes_total`.
///
/// `QuoteVerdict::Verified::tcb_status` is a `String` — `verify::verified_verdict`
/// takes it by value straight from the field `dcap_qvl` names `status` on its
/// full verification result, which is itself `TcbStatus::to_string()`.
/// `dcap_qvl::TcbStatus` has exactly seven
/// variants (`UpToDate`, `OutOfDate`, `OutOfDateConfigurationNeeded`,
/// `ConfigurationNeeded`, `ConfigurationAndSWHardeningNeeded`,
/// `SWHardeningNeeded`, `Revoked`); [`classify`](Self::classify) recognizes
/// their exact `Display` spellings and buckets anything else — a future
/// dcap-qvl status this module has not been taught, or a string that is not
/// a status at all — into `Other`. That default is the only thing standing
/// between an unrecognized string and a label with unbounded cardinality:
/// were `classify` ever removed and the raw `String` passed straight
/// through, any value `tcb_status` carries — in principle, anything the
/// caller of `verified_verdict` puts there — becomes a distinct Prometheus
/// series forever.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
enum TcbStatusLabel {
    UpToDate,
    OutOfDate,
    OutOfDateConfigurationNeeded,
    ConfigurationNeeded,
    ConfigurationAndSWHardeningNeeded,
    SWHardeningNeeded,
    Revoked,
    /// Anything this module does not recognize as one of the seven known
    /// statuses. Never the original string.
    Other,
}

impl TcbStatusLabel {
    fn classify(status: &str) -> TcbStatusLabel {
        match status {
            "UpToDate" => TcbStatusLabel::UpToDate,
            "OutOfDate" => TcbStatusLabel::OutOfDate,
            "OutOfDateConfigurationNeeded" => TcbStatusLabel::OutOfDateConfigurationNeeded,
            "ConfigurationNeeded" => TcbStatusLabel::ConfigurationNeeded,
            "ConfigurationAndSWHardeningNeeded" => {
                TcbStatusLabel::ConfigurationAndSWHardeningNeeded
            }
            "SWHardeningNeeded" => TcbStatusLabel::SWHardeningNeeded,
            "Revoked" => TcbStatusLabel::Revoked,
            _ => TcbStatusLabel::Other,
        }
    }
}

impl EncodeLabelValue for TcbStatusLabel {
    fn encode(&self, encoder: &mut LabelValueEncoder) -> Result<(), std::fmt::Error> {
        let s: &str = match self {
            TcbStatusLabel::UpToDate => "up_to_date",
            TcbStatusLabel::OutOfDate => "out_of_date",
            TcbStatusLabel::OutOfDateConfigurationNeeded => "out_of_date_configuration_needed",
            TcbStatusLabel::ConfigurationNeeded => "configuration_needed",
            TcbStatusLabel::ConfigurationAndSWHardeningNeeded => {
                "configuration_and_sw_hardening_needed"
            }
            TcbStatusLabel::SWHardeningNeeded => "sw_hardening_needed",
            TcbStatusLabel::Revoked => "revoked",
            TcbStatusLabel::Other => "other",
        };
        encoder.write_str(s)
    }
}

/// The `why_kind` label on `gateway_unverified_total`.
///
/// See the module docs for why this has five variants rather than the task
/// brief's four: [`QuoteVerifier::verify_at`](crate::gateway::verify::QuoteVerifier)
/// produces an `Unverified` reason today (an unreadable system clock) that
/// is none of the other four, and `Other` is where it lands rather than
/// being guessed into the wrong bucket.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
enum WhyKind {
    CollateralAbsent,
    CollateralStale,
    PcsUnreachable,
    UnsupportedPlatform,
    Other,
}

impl WhyKind {
    /// Classify a free-text `why` by keyword, never returning the text
    /// itself. Matched against the exact phrases `verify.rs`'s
    /// `collateral_or_unverified` uses today ("no collateral cached", "past
    /// its TTL") plus the vocabulary `Task7`'s wiring is expected to use for
    /// a provisioning-service failure or an unsupported report type. Case
    /// folded once up front so "PCS unreachable" and "pcs unreachable"
    /// classify identically.
    fn classify(why: &str) -> WhyKind {
        let lower = why.to_ascii_lowercase();
        if lower.contains("no collateral cached") {
            WhyKind::CollateralAbsent
        } else if lower.contains("past its ttl") {
            WhyKind::CollateralStale
        } else if lower.contains("pcs")
            || lower.contains("pccs")
            || lower.contains("provisioning service")
        {
            WhyKind::PcsUnreachable
        } else if lower.contains("platform")
            && (lower.contains("unsupported") || lower.contains("not supported"))
        {
            WhyKind::UnsupportedPlatform
        } else {
            WhyKind::Other
        }
    }
}

impl EncodeLabelValue for WhyKind {
    fn encode(&self, encoder: &mut LabelValueEncoder) -> Result<(), std::fmt::Error> {
        let s: &str = match self {
            WhyKind::CollateralAbsent => "collateral_absent",
            WhyKind::CollateralStale => "collateral_stale",
            WhyKind::PcsUnreachable => "pcs_unreachable",
            WhyKind::UnsupportedPlatform => "unsupported_platform",
            WhyKind::Other => "other",
        };
        encoder.write_str(s)
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct RequestLabels {
    verdict: VerdictKind,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct QuoteLabels {
    platform: Platform,
    tcb_status: TcbStatusLabel,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct UnverifiedLabels {
    why_kind: WhyKind,
}

/// The gateway's three Prometheus counters, registered once at startup.
///
/// Every label on every counter here is one of the bounded enums above.
/// Nothing per-counterparty, nothing free-text, and never the `TcbConfig`
/// itself — a Prometheus label is a database, and this one must not rebuild
/// the dossier the meter refuses to keep.
pub struct Metrics {
    requests: Family<RequestLabels, Counter>,
    quotes: Family<QuoteLabels, Counter>,
    unverified: Family<UnverifiedLabels, Counter>,
}

impl Metrics {
    pub fn new(registry: &mut Registry) -> Metrics {
        let requests = Family::<RequestLabels, Counter>::default();
        registry.register(
            "gateway_requests",
            "Requests the gateway has measured, by quote verdict",
            requests.clone(),
        );

        let quotes = Family::<QuoteLabels, Counter>::default();
        registry.register(
            "gateway_quotes",
            "Quotes the gateway has verified, by platform and TCB status",
            quotes.clone(),
        );

        let unverified = Family::<UnverifiedLabels, Counter>::default();
        registry.register(
            "gateway_unverified",
            "Quotes the gateway could not verify, by reason class",
            unverified.clone(),
        );

        Metrics {
            requests,
            quotes,
            unverified,
        }
    }

    /// Record one finding. Fail-open binds this too: every branch below is
    /// an infallible label lookup and an atomic increment, so this function
    /// cannot panic regardless of what `finding` contains.
    pub fn record(&self, finding: &Finding) {
        self.requests
            .get_or_create(&RequestLabels {
                verdict: VerdictKind::of(&finding.verdict),
            })
            .inc();

        match &finding.verdict {
            QuoteVerdict::Verified {
                platform,
                tcb_status,
                ..
            } => {
                self.quotes
                    .get_or_create(&QuoteLabels {
                        platform: *platform,
                        tcb_status: TcbStatusLabel::classify(tcb_status),
                    })
                    .inc();
            }
            QuoteVerdict::Unverified { why } => {
                self.unverified
                    .get_or_create(&UnverifiedLabels {
                        why_kind: WhyKind::classify(why),
                    })
                    .inc();
            }
            QuoteVerdict::Invalid { .. } => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::verify::TcbConfig;

    fn verified() -> QuoteVerdict {
        QuoteVerdict::Verified {
            platform: Platform::TdxV10,
            tcb_status: "UpToDate".into(),
            advisories: vec![],
            config: TcbConfig::for_test(&[("tdx_module", "1.5.05")]),
        }
    }

    /// `tee_tcb_svn` and `xfam` are two of the seven attributes
    /// `verify::tcb_config_from_td10` actually produces for a TDX 1.0
    /// platform (see `verify.rs`'s module docs and its
    /// `a_real_verification_yields_the_configuration_attributes_and_no_more`
    /// test). The task brief's original fixture used `microcode` and
    /// `pce_svn`, both of which Task 4 established do not exist on any
    /// report type; substituted here so this test's own assertions do not
    /// read as evidence for an attribute the gateway can never report.
    fn obs(set: u64, total: u64) -> Observation {
        Observation {
            set_size: set,
            total_sessions: total,
            distinct_configs: 4,
            varying_attributes: vec!["tee_tcb_svn".into(), "xfam".into()],
        }
    }

    #[test]
    fn a_verified_finding_states_the_set_and_the_attributes() {
        let f = Finding {
            verdict: verified(),
            binding: SessionBinding::Unbound {
                why: "header transport is replayable",
            },
            observation: Some(obs(3, 1847)),
        };
        let out = f.render();
        assert!(out.contains("VERIFIED"), "{out}");
        assert!(!out.contains("UNVERIFIED"), "{out}");
        assert!(
            out.contains("3 of 1847"),
            "the set and the corpus, together: {out}"
        );
        assert!(out.contains("tee_tcb_svn"), "{out}");
        // The positive half of the anonymity-block gate: `an_unverified_finding_carries_no_anonymity_number`
        // and `a_verified_finding_with_no_observation_omits_the_anonymity_block_too`
        // only ever assert these labels are *absent*, which a mutation that
        // always omitted the block would also satisfy vacuously. This is the
        // case where they must appear.
        assert!(out.contains("anonymity set"), "{out}");
        assert!(out.contains("varying"), "{out}");
    }

    /// The gap between header transport and RA-TLS is a finding, not a
    /// footnote. If this line disappears an operator reads a verified quote
    /// as a bound one.
    #[test]
    fn unbound_transport_is_reported_on_the_finding() {
        let f = Finding {
            verdict: verified(),
            binding: SessionBinding::Unbound {
                why: "a captured quote is reusable",
            },
            observation: Some(obs(3, 1847)),
        };
        assert!(f.render().contains("captured quote is reusable"));
    }

    #[test]
    fn a_bound_transport_makes_no_replay_claim() {
        let f = Finding {
            verdict: verified(),
            binding: SessionBinding::Bound,
            observation: Some(obs(3, 9)),
        };
        let out = f.render();
        assert!(!out.to_lowercase().contains("replay"), "{out}");
        // The positive half: `BOUND` must actually appear on the session
        // binding line, not merely "no replay claim was made because the
        // line vanished".
        assert!(
            out.contains("session binding") && out.contains("BOUND"),
            "{out}"
        );
    }

    #[test]
    fn unverified_is_as_prominent_as_verified_and_says_why() {
        let f = Finding {
            verdict: QuoteVerdict::Unverified {
                why: "no collateral cached for FMSPC 00806f".into(),
            },
            binding: SessionBinding::Unbound { why: "x" },
            observation: None,
        };
        let out = f.render();
        // The *first line*, not the whole rendering: `report.rs`'s own
        // `a_modelled_row_renders_the_word_modelled_on_its_own_line` exists
        // precisely because a whole-output `contains` still passes if the
        // marker moves to a footnote — this module cites that test by name
        // as the discipline it follows, so its own test has to hold the
        // same line, not just the same output.
        let first = out
            .lines()
            .next()
            .expect("render always emits a first line");
        assert!(first.contains("UNVERIFIED"), "{first}");
        assert!(
            first.contains("no collateral cached"),
            "the reason must reach the reader on the same line: {first}"
        );
    }

    /// Ruling 1: fail-open always forwards the request, but an affirmative
    /// checkmark next to `UNVERIFIED` is still a pass signal, and constraint
    /// 2 forbids `Unverified` ever reading as one. The prefix must change,
    /// not just the parenthetical.
    #[test]
    fn an_unverified_line_carries_no_checkmark() {
        let f = Finding {
            verdict: QuoteVerdict::Unverified {
                why: "PCS unreachable".into(),
            },
            binding: SessionBinding::Bound,
            observation: None,
        };
        let out = f.render();
        assert!(
            !out.contains('\u{2713}'),
            "a checkmark reached an unverified line: {out}"
        );
        assert!(out.contains("agent forwarded (fail-open)"), "{out}");
    }

    /// The same property for `Invalid` — an agent's malformed or revoked
    /// quote must not earn the checkmark either.
    #[test]
    fn an_invalid_line_carries_no_checkmark() {
        let f = Finding {
            verdict: QuoteVerdict::Invalid {
                reason: "signature check failed".into(),
            },
            binding: SessionBinding::Bound,
            observation: None,
        };
        let out = f.render();
        assert!(
            !out.contains('\u{2713}'),
            "a checkmark reached an invalid line: {out}"
        );
    }

    /// The positive half of Ruling 1: a genuinely `Verified` finding must
    /// still get the checkmark. Without this, a mutation that removed the
    /// checkmark from *every* verdict would still pass the two tests above.
    #[test]
    fn a_verified_line_still_carries_the_checkmark() {
        let f = Finding {
            verdict: verified(),
            binding: SessionBinding::Bound,
            observation: None,
        };
        assert!(f.render().contains('\u{2713}'));
    }

    #[test]
    fn an_unverified_finding_carries_no_anonymity_number() {
        // We did not verify the quote, so we have no trustworthy
        // configuration to partition on. Printing a set size here would be a
        // number with no provenance.
        let f = Finding {
            verdict: QuoteVerdict::Unverified {
                why: "PCS unreachable".into(),
            },
            binding: SessionBinding::Bound,
            observation: None,
        };
        let out = f.render();
        assert!(!out.contains("anonymity set"), "{out}");
    }

    /// The same gate as above, proved against the *other* arm: a verified
    /// finding with no observation must omit the block too. Without this,
    /// `render` could gate the anonymity block on `matches!(verdict,
    /// Verified)` instead of `observation.is_some()` and still pass the test
    /// above — that mutation only differs from the real gate when a verified
    /// finding happens to carry no observation, which is exactly this case.
    #[test]
    fn a_verified_finding_with_no_observation_omits_the_anonymity_block_too() {
        let f = Finding {
            verdict: verified(),
            binding: SessionBinding::Bound,
            observation: None,
        };
        let out = f.render();
        assert!(!out.contains("anonymity set"), "{out}");
        assert!(!out.contains("varying"), "{out}");
    }

    /// The gap a `pub`-fielded `Finding` leaves open at the type level: Task
    /// 7 (or any future caller) can construct an `Unverified` finding that
    /// still carries `Some(observation)` — nothing stops it. The render gate
    /// has to be a conjunction (`Some` *and* `Verified`), not `Some` alone,
    /// or this exact combination would render a full anonymity block for a
    /// quote that was never checked.
    #[test]
    fn an_unverified_finding_with_an_observation_still_carries_no_anonymity_number() {
        let f = Finding {
            verdict: QuoteVerdict::Unverified {
                why: "PCS unreachable".into(),
            },
            binding: SessionBinding::Bound,
            observation: Some(obs(3, 1847)),
        };
        let out = f.render();
        assert!(!out.contains("anonymity set"), "{out}");
        assert!(!out.contains("varying"), "{out}");
    }

    #[test]
    fn an_invalid_finding_states_invalid_and_the_reason() {
        let f = Finding {
            verdict: QuoteVerdict::Invalid {
                reason: "signature check failed".into(),
            },
            binding: SessionBinding::Bound,
            observation: None,
        };
        let out = f.render();
        assert!(out.contains("INVALID"), "{out}");
        assert!(out.contains("signature check failed"), "{out}");
        assert!(!out.contains("VERIFIED"), "{out}");
        assert!(!out.contains("UNVERIFIED"), "{out}");
    }

    /// `platform_display` pinned exactly, for all three platforms, against
    /// the *first line* of a real rendering. Without this, all three arms
    /// could return `""`, or the same string, or drop `TCB {tcb_status}`
    /// from the parenthetical entirely, and every other test in this file —
    /// none of which renders a TDX 1.5 or SGX finding, and none of which
    /// asserts the exact first line rather than a substring — would stay
    /// green.
    #[test]
    fn a_verified_finding_states_the_exact_first_line_per_platform() {
        let cases = [
            (Platform::TdxV10, "TDX 1.0"),
            (Platform::TdxV15, "TDX 1.5"),
            (Platform::SgxEnclave, "SGX"),
        ];
        for (platform, expected_name) in cases {
            let f = Finding {
                verdict: QuoteVerdict::Verified {
                    platform,
                    tcb_status: "UpToDate".into(),
                    advisories: vec![],
                    config: TcbConfig::for_test(&[]),
                },
                binding: SessionBinding::Bound,
                observation: None,
            };
            let out = f.render();
            let first = out
                .lines()
                .next()
                .expect("render always emits a first line");
            let expected = format!(
                "agent authorized \u{2713}   quote: VERIFIED ({expected_name}, TCB UpToDate)"
            );
            assert_eq!(first, expected, "platform {platform:?}");
        }
    }

    #[test]
    fn the_json_form_never_contains_the_ppid_or_a_config_hash() {
        let f = Finding {
            verdict: verified(),
            binding: SessionBinding::Bound,
            observation: Some(obs(3, 1847)),
        };
        let j = serde_json::to_string(&f.to_json()).unwrap().to_lowercase();
        assert!(!j.contains("ppid"));
        assert!(
            !j.contains("fingerprint"),
            "a per-counterparty key must not reach the wire"
        );
    }

    /// The positive counterpart the negative test above cannot provide:
    /// neither `"ppid"` nor `"fingerprint"` is a field name, value, or
    /// possible rendering of anything `to_json` touches, so that test passes
    /// for `json!({})`, for a `verdict`/`binding` swap, or for `observation`
    /// silently dropped — none of those contain the two forbidden words
    /// either. This pins the actual shape, following `report.rs`'s
    /// `json_carries_the_source_and_provenance_as_data_not_prose`.
    #[test]
    fn to_json_carries_the_verdict_binding_and_observation_as_data_not_prose() {
        let f = Finding {
            verdict: verified(),
            binding: SessionBinding::Bound,
            observation: Some(obs(3, 1847)),
        };
        let j = f.to_json();
        assert_eq!(j["verdict"]["verdict"], "verified");
        assert_eq!(j["verdict"]["platform"], "tdx_v10");
        assert_eq!(j["verdict"]["tcb_status"], "UpToDate");
        assert_eq!(j["binding"]["kind"], "bound");
        assert_eq!(j["observation"]["set_size"], 3);
        assert_eq!(j["observation"]["total_sessions"], 1847);
        assert!(j["observation"]["varying_attributes"]
            .as_array()
            .expect("varying_attributes is a JSON array")
            .contains(&serde_json::json!("tee_tcb_svn")));
    }

    /// `binding`'s other arm and the reason it carries, so a swap of the two
    /// `SessionBinding` variants — or a dropped `why` — doesn't hide behind
    /// the `Bound` case above always being exercised.
    #[test]
    fn to_json_carries_an_unbound_reason() {
        let f = Finding {
            verdict: verified(),
            binding: SessionBinding::Unbound {
                why: "a captured quote is reusable",
            },
            observation: None,
        };
        let j = f.to_json();
        assert_eq!(j["binding"]["kind"], "unbound");
        assert_eq!(j["binding"]["why"], "a captured quote is reusable");
        assert!(
            j["observation"].is_null(),
            "no observation must serialize as null, not be silently omitted or defaulted"
        );
    }

    /// The same property, against the human-readable form. `render` never
    /// touches anything but the three permitted fields, so this is defense
    /// in depth rather than a distinct risk — but `to_json` alone being
    /// clean would leave a hand-written `render` free to regress unnoticed.
    #[test]
    fn the_rendered_finding_also_contains_no_ppid_text() {
        let f = Finding {
            verdict: verified(),
            binding: SessionBinding::Bound,
            observation: Some(obs(3, 1847)),
        };
        let out = f.render().to_lowercase();
        assert!(!out.contains("ppid"));
    }

    #[test]
    fn metric_labels_are_low_cardinality() {
        // A Prometheus label is a database. Anything per-counterparty here
        // rebuilds the dossier the meter refuses to keep.
        let mut reg = Registry::default();
        let m = Metrics::new(&mut reg);
        m.record(&Finding {
            verdict: verified(),
            binding: SessionBinding::Bound,
            observation: Some(obs(3, 1847)),
        });
        let mut buf = String::new();
        prometheus_client::encoding::text::encode(&mut buf, &reg).unwrap();
        assert!(buf.contains("tdx_v10"));
        assert!(
            !buf.contains("1.5.05"),
            "a TCB value reached a label: {buf}"
        );
    }

    /// The property the whole metric-cardinality rule exists to hold. An
    /// FMSPC in a free-text `why` must classify into a bounded bucket, never
    /// ride along into a label — a Prometheus label is a database, and an
    /// FMSPC there is a per-platform identifier retained indefinitely.
    #[test]
    fn a_free_text_why_containing_an_fmspc_never_reaches_a_metric_label() {
        let mut reg = Registry::default();
        let m = Metrics::new(&mut reg);
        m.record(&Finding {
            verdict: QuoteVerdict::Unverified {
                why: "no collateral cached for FMSPC deadbeef1234 yet".into(),
            },
            binding: SessionBinding::Bound,
            observation: None,
        });
        let mut buf = String::new();
        prometheus_client::encoding::text::encode(&mut buf, &reg).unwrap();
        assert!(
            !buf.contains("deadbeef1234"),
            "the FMSPC reached a metric label: {buf}"
        );
        assert!(
            buf.contains("collateral_absent"),
            "the classified reason must still appear: {buf}"
        );
    }

    #[test]
    fn every_verdict_kind_increments_the_requests_counter_under_its_own_label() {
        let mut reg = Registry::default();
        let m = Metrics::new(&mut reg);
        m.record(&Finding {
            verdict: verified(),
            binding: SessionBinding::Bound,
            observation: None,
        });
        m.record(&Finding {
            verdict: QuoteVerdict::Invalid {
                reason: "bad signature".into(),
            },
            binding: SessionBinding::Bound,
            observation: None,
        });
        m.record(&Finding {
            verdict: QuoteVerdict::Unverified {
                why: "no collateral cached for FMSPC aaaaaaaaaaaa yet".into(),
            },
            binding: SessionBinding::Bound,
            observation: None,
        });

        let mut buf = String::new();
        prometheus_client::encoding::text::encode(&mut buf, &reg).unwrap();
        assert!(
            buf.contains("gateway_requests_total{verdict=\"verified\"} 1"),
            "{buf}"
        );
        assert!(
            buf.contains("gateway_requests_total{verdict=\"invalid\"} 1"),
            "{buf}"
        );
        assert!(
            buf.contains("gateway_requests_total{verdict=\"unverified\"} 1"),
            "{buf}"
        );
    }

    /// Neither an invalid nor an unverified quote may touch
    /// `gateway_quotes_total` — that counter's whole meaning is "a quote we
    /// verified", and a mutation that routed every verdict into it would
    /// silently report failed verifications as successful ones.
    #[test]
    fn only_a_verified_quote_increments_the_quotes_counter() {
        let mut reg = Registry::default();
        let m = Metrics::new(&mut reg);
        m.record(&Finding {
            verdict: QuoteVerdict::Invalid {
                reason: "bad signature".into(),
            },
            binding: SessionBinding::Bound,
            observation: None,
        });
        m.record(&Finding {
            verdict: QuoteVerdict::Unverified {
                why: "no collateral cached for FMSPC aaaaaaaaaaaa yet".into(),
            },
            binding: SessionBinding::Bound,
            observation: None,
        });
        let mut buf = String::new();
        prometheus_client::encoding::text::encode(&mut buf, &reg).unwrap();
        assert!(
            !buf.contains("gateway_quotes_total{"),
            "an unverified or invalid quote must not touch gateway_quotes_total: {buf}"
        );

        m.record(&Finding {
            verdict: verified(),
            binding: SessionBinding::Bound,
            observation: None,
        });
        let mut buf = String::new();
        prometheus_client::encoding::text::encode(&mut buf, &reg).unwrap();
        assert!(
            buf.contains("gateway_quotes_total{platform=\"tdx_v10\",tcb_status=\"up_to_date\"} 1"),
            "{buf}"
        );
    }

    /// The mirror check: neither a verified nor an invalid quote may touch
    /// `gateway_unverified_total`. That counter exists so an operator can
    /// alert on "we could not check" specifically; a verified quote landing
    /// in it would drown the signal in noise, and an invalid one would
    /// misreport an agent's bad quote as the gateway's own operational gap.
    #[test]
    fn only_an_unverified_quote_increments_the_unverified_counter() {
        let mut reg = Registry::default();
        let m = Metrics::new(&mut reg);
        m.record(&Finding {
            verdict: verified(),
            binding: SessionBinding::Bound,
            observation: None,
        });
        m.record(&Finding {
            verdict: QuoteVerdict::Invalid {
                reason: "bad signature".into(),
            },
            binding: SessionBinding::Bound,
            observation: None,
        });
        let mut buf = String::new();
        prometheus_client::encoding::text::encode(&mut buf, &reg).unwrap();
        assert!(
            !buf.contains("gateway_unverified_total{"),
            "a verified or invalid quote must not touch gateway_unverified_total: {buf}"
        );

        m.record(&Finding {
            verdict: QuoteVerdict::Unverified {
                why: "no collateral cached for FMSPC aaaaaaaaaaaa yet".into(),
            },
            binding: SessionBinding::Bound,
            observation: None,
        });
        let mut buf = String::new();
        prometheus_client::encoding::text::encode(&mut buf, &reg).unwrap();
        assert!(
            buf.contains("gateway_unverified_total{why_kind=\"collateral_absent\"} 1"),
            "{buf}"
        );
    }

    /// Each platform recorded **in isolation**, one `Registry` per platform,
    /// and the full series line pinned exactly. Recording all three
    /// platforms into one shared registry and then checking that all three
    /// label strings appear *somewhere* is not enough: a `TdxV15` ↔
    /// `SgxEnclave` encoder swap is symmetric across that fixed set of
    /// three, so the same three label strings would all still appear, just
    /// each attached to the wrong platform — a shared-registry version of
    /// this test stays green under exactly the mutation it exists to catch.
    /// Isolating each platform's recording closes that: when `TdxV15` alone
    /// is recorded under a swapped encoder, the buffer contains
    /// `platform="sgx_enclave"` and never `platform="tdx_v15"`, which this
    /// loop's own needle catches on that iteration.
    #[test]
    fn each_platform_variant_renders_its_own_distinct_label() {
        for (platform, label) in [
            (Platform::TdxV10, "tdx_v10"),
            (Platform::TdxV15, "tdx_v15"),
            (Platform::SgxEnclave, "sgx_enclave"),
        ] {
            let mut reg = Registry::default();
            let m = Metrics::new(&mut reg);
            m.record(&Finding {
                verdict: QuoteVerdict::Verified {
                    platform,
                    tcb_status: "UpToDate".into(),
                    advisories: vec![],
                    config: TcbConfig::for_test(&[]),
                },
                binding: SessionBinding::Bound,
                observation: None,
            });
            let mut buf = String::new();
            prometheus_client::encoding::text::encode(&mut buf, &reg).unwrap();
            let needle =
                format!("gateway_quotes_total{{platform=\"{label}\",tcb_status=\"up_to_date\"}} 1");
            assert!(
                buf.contains(&needle),
                "platform {platform:?} did not encode to its own label {needle}: {buf}"
            );
        }
    }

    /// Every `TcbStatusLabel` encoder arm, pinned to its exact rendered
    /// string. The `classify` tests below only compare *enum values*
    /// (`String -> variant`), so they say nothing about `variant -> label`
    /// — a one-token edit, `TcbStatusLabel::Revoked => "up_to_date"`, graphs
    /// a revoked platform as up to date and passes every other test in this
    /// file. Recording all eight classifications under the *same* platform
    /// and then requiring all eight distinct series lines to exist is what
    /// catches that: the mutation collapses `Revoked` onto the `UpToDate`
    /// series, so the `"revoked"` line simply never appears.
    #[test]
    fn every_tcb_status_encodes_to_its_own_exact_label() {
        let mut reg = Registry::default();
        let m = Metrics::new(&mut reg);
        let statuses = [
            ("UpToDate", "up_to_date"),
            ("OutOfDate", "out_of_date"),
            (
                "OutOfDateConfigurationNeeded",
                "out_of_date_configuration_needed",
            ),
            ("ConfigurationNeeded", "configuration_needed"),
            (
                "ConfigurationAndSWHardeningNeeded",
                "configuration_and_sw_hardening_needed",
            ),
            ("SWHardeningNeeded", "sw_hardening_needed"),
            ("Revoked", "revoked"),
            ("SomeFutureDcapStatus", "other"),
        ];
        for (status, _) in statuses {
            m.record(&Finding {
                verdict: QuoteVerdict::Verified {
                    platform: Platform::TdxV10,
                    tcb_status: status.into(),
                    advisories: vec![],
                    config: TcbConfig::for_test(&[]),
                },
                binding: SessionBinding::Bound,
                observation: None,
            });
        }
        let mut buf = String::new();
        prometheus_client::encoding::text::encode(&mut buf, &reg).unwrap();
        for (status, label) in statuses {
            let needle = format!("tcb_status=\"{label}\"");
            assert!(
                buf.contains(&needle),
                "status {status} did not encode to its own label {needle}: {buf}"
            );
        }
    }

    /// The `WhyKind` equivalent of the test above: every encoder arm, pinned
    /// exactly, including the `Other` bucket.
    #[test]
    fn every_why_kind_encodes_to_its_own_exact_label() {
        let mut reg = Registry::default();
        let m = Metrics::new(&mut reg);
        let whys = [
            (
                "no collateral cached for FMSPC aaaaaaaaaaaa yet",
                "collateral_absent",
            ),
            (
                "collateral for FMSPC aaaaaaaaaaaa is 900s old and past its TTL",
                "collateral_stale",
            ),
            (
                "could not reach the provisioning service at https://pccs.example: timed out",
                "pcs_unreachable",
            ),
            (
                "this platform is not supported by this gateway",
                "unsupported_platform",
            ),
            (
                "the system clock reads before the Unix epoch, so collateral \
                 validity cannot be checked",
                "other",
            ),
        ];
        for (why, _) in whys {
            m.record(&Finding {
                verdict: QuoteVerdict::Unverified { why: why.into() },
                binding: SessionBinding::Bound,
                observation: None,
            });
        }
        let mut buf = String::new();
        prometheus_client::encoding::text::encode(&mut buf, &reg).unwrap();
        for (why, label) in whys {
            let needle = format!("why_kind=\"{label}\"");
            assert!(
                buf.contains(&needle),
                "why {why:?} did not encode to its own label {needle}: {buf}"
            );
        }
    }

    #[test]
    fn tcb_status_classification_covers_every_known_dcap_status_exactly() {
        let cases = [
            ("UpToDate", TcbStatusLabel::UpToDate),
            (
                "OutOfDateConfigurationNeeded",
                TcbStatusLabel::OutOfDateConfigurationNeeded,
            ),
            ("OutOfDate", TcbStatusLabel::OutOfDate),
            (
                "ConfigurationAndSWHardeningNeeded",
                TcbStatusLabel::ConfigurationAndSWHardeningNeeded,
            ),
            ("ConfigurationNeeded", TcbStatusLabel::ConfigurationNeeded),
            ("SWHardeningNeeded", TcbStatusLabel::SWHardeningNeeded),
            ("Revoked", TcbStatusLabel::Revoked),
        ];
        for (s, expected) in cases {
            assert_eq!(TcbStatusLabel::classify(s), expected, "status {s}");
        }
    }

    /// The default arm, made concrete. Without it, an unrecognized status —
    /// or, worse, a string that is not a status at all — would need to be
    /// passed straight through to be encoded, and every string is a distinct
    /// label.
    #[test]
    fn an_unrecognized_tcb_status_string_is_bucketed_as_other_not_passed_through() {
        assert_eq!(
            TcbStatusLabel::classify("SomeFutureDcapStatus"),
            TcbStatusLabel::Other
        );
        assert_eq!(
            TcbStatusLabel::classify("00806f000000"),
            TcbStatusLabel::Other,
            "an FMSPC-shaped string must not be mistaken for a status"
        );
    }

    #[test]
    fn why_classification_covers_the_four_named_causes() {
        assert_eq!(
            WhyKind::classify("no collateral cached for FMSPC 00806f000000 yet"),
            WhyKind::CollateralAbsent
        );
        assert_eq!(
            WhyKind::classify(
                "collateral for FMSPC 00806f000000 is 900s old and past its TTL; \
                 verifying against expired TCB data could report a revoked \
                 platform as up to date"
            ),
            WhyKind::CollateralStale
        );
        assert_eq!(
            WhyKind::classify("PCS unreachable"),
            WhyKind::PcsUnreachable
        );
        assert_eq!(
            WhyKind::classify(
                "could not reach the provisioning service at https://pccs.example: timed out"
            ),
            WhyKind::PcsUnreachable
        );
        assert_eq!(
            WhyKind::classify("this platform is not supported by this gateway"),
            WhyKind::UnsupportedPlatform
        );
    }

    /// The other producer of `Unverified` reasons, held to the same standard.
    ///
    /// Task 7's pipeline writes four fixed strings of its own for the cases
    /// `verify.rs` never sees: a source or verifier that panicked, a request
    /// with no attestation at all, and the session-binding fallback that goes
    /// with a panicked source. Every one of them describes a **gateway bug**
    /// or a **missing header** — not a collateral problem and not a
    /// provisioning-service problem. Each must therefore land in `Other`.
    ///
    /// The risk is a rewording, not a bug: these are English sentences, and
    /// slipping the word "pcs", "provisioning service" or "platform" plus
    /// "unsupported" into one of them silently relabels a crash in our own
    /// code as an infrastructure failure and sends an operator to fix the
    /// wrong thing. Nothing but this table catches that.
    ///
    /// `BINDING_UNKNOWN` never reaches `classify` today — it is a
    /// `SessionBinding` reason, not a `QuoteVerdict` one — and is included
    /// anyway so that a future wiring which does classify it cannot start out
    /// mislabelled.
    #[test]
    fn the_pipelines_own_unverified_reasons_all_bucket_as_other() {
        use crate::gateway::pipeline::{
            BINDING_UNKNOWN, NO_ATTESTATION, SOURCE_PANICKED, VERIFIER_PANICKED,
        };
        for (name, why) in [
            ("SOURCE_PANICKED", SOURCE_PANICKED),
            ("BINDING_UNKNOWN", BINDING_UNKNOWN),
            ("NO_ATTESTATION", NO_ATTESTATION),
            ("VERIFIER_PANICKED", VERIFIER_PANICKED),
        ] {
            assert_eq!(
                WhyKind::classify(why),
                WhyKind::Other,
                "{name} classifies as something it is not: {why:?}"
            );
        }
    }

    /// The real, current gap: `verify.rs`'s unreadable-clock message is
    /// none of the four named causes. Copied verbatim from `verify_at` here,
    /// and pinned against the *live source* by
    /// `the_three_keywords_verify_rs_produces_still_appear_there` below — so
    /// a rewording there is now actually caught here, not just documented as
    /// if it were.
    #[test]
    fn an_unreadable_clock_reason_does_not_pretend_to_be_one_of_the_four_named_causes() {
        let why = "the system clock reads before the Unix epoch, so collateral \
                    validity cannot be checked";
        assert_eq!(WhyKind::classify(why), WhyKind::Other);
    }

    /// `verify.rs`'s own idiom (see its formatter-ban guard,
    /// `the_verifier_hands_nothing_to_a_formatter_it_did_not_choose`)
    /// applied to a different risk: `WhyKind::classify`'s keywords for the
    /// three reasons `verify.rs` actually produces today
    /// (`collateral_absent`, `collateral_stale`, and the unreadable-clock
    /// `Other` case) are hand-copied prose, not derived from `verify.rs` in
    /// any way the compiler checks. A rewording of any of the three phrases
    /// below would silently degrade that bucket to `Other` with nothing
    /// failing — except this test.
    ///
    /// Scanned against the **non-test** region only, split on the same
    /// `#[cfg(test)]\nmod tests {` marker `verify.rs`'s own guard splits on.
    /// A naive `include_str!("verify.rs").contains(phrase)` over the whole
    /// file is close to vacuous here: `verify.rs`'s own tests assert
    /// `why.contains("no collateral cached")` and a doc comment quotes
    /// "past its TTL" verbatim, so the phrase keeps appearing in the file
    /// even if the *production* `format!` string that generates it is
    /// reworded — which is exactly what happened when this test was first
    /// written this way, and it passed anyway. Restricting the search to
    /// the region before the test module closes that gap.
    /// `pcs_unreachable` and `unsupported_platform` are not covered here
    /// because `verify.rs` does not produce either reason today; see
    /// `every_why_kind_encodes_to_its_own_exact_label` and
    /// `why_classification_covers_the_four_named_causes` for those, against
    /// synthetic text.
    #[test]
    fn the_three_keywords_verify_rs_produces_still_appear_there() {
        let src = include_str!("verify.rs");
        const MARKER: &str = "#[cfg(test)]\nmod tests {";
        assert_eq!(
            src.matches(MARKER).count(),
            1,
            "ambiguous test module boundary in verify.rs"
        );
        let non_test = src.split(MARKER).next().expect("split yields a head");
        // The split itself has to actually reach the two functions that
        // produce these phrases, or this guard would pass against a
        // truncated string without ever having scanned anything real.
        assert!(
            non_test.contains("fn collateral_or_unverified") && non_test.contains("fn verify_at"),
            "the scanned region does not reach verify.rs's implementation, \
             so this guard would pass against a truncated string"
        );
        for phrase in [
            "no collateral cached",
            "past its TTL",
            "the system clock reads before the Unix epoch",
        ] {
            assert!(
                non_test.contains(phrase),
                "the phrase {phrase:?} no longer appears in verify.rs's \
                 production code; WhyKind::classify's keyword for it is now \
                 unreachable and would silently misclassify a real \
                 Unverified reason"
            );
        }
    }

    /// End-to-end proof for the two reasons `verify.rs` produces today,
    /// through a real `QuoteVerifier` rather than a hand-copied string. This
    /// is what `why_classification_covers_the_four_named_causes` cannot be:
    /// that test's strings are typed by hand and could drift from
    /// `verify.rs`'s actual wording without either test noticing. These two
    /// call the real verifier and classify whatever `why` it actually
    /// produces.
    mod against_a_real_verifier {
        use super::*;
        use crate::gateway::collateral::CollateralCache;
        use crate::gateway::source::RawAttestation;
        use crate::gateway::verify::QuoteVerifier;
        use std::sync::Arc;
        use std::time::{Duration, Instant};

        /// Vendored real TDX quote, same fixture `verify.rs`'s own tests use
        /// (Phala Network, MIT — see `tests/fixtures/PROVENANCE.txt`). Needed
        /// only so `dcap_qvl::intel::quote_fmspc` succeeds and the verifier
        /// reaches the cache lookup at all; its collateral is irrelevant to
        /// the absent-cache case and is only decoded for the stale case.
        fn real_tdx_quote() -> Vec<u8> {
            include_bytes!("../../tests/fixtures/tdx-quote.bin").to_vec()
        }

        fn real_collateral() -> dcap_qvl::QuoteCollateralV3 {
            serde_json::from_slice(include_bytes!(
                "../../tests/fixtures/tdx-quote-collateral.json"
            ))
            .expect("the vendored collateral fixture decodes")
        }

        /// The fixture's FMSPC, exactly as `verify.rs` pins it under
        /// `REAL_FMSPC_HEX` (private to that module, so re-stated here
        /// rather than imported).
        const REAL_FMSPC_HEX: &str = "b0c06f000000";

        #[test]
        fn an_empty_cache_classifies_as_collateral_absent() {
            let verifier = QuoteVerifier::new(Arc::new(CollateralCache::new(
                "https://pccs.invalid".into(),
                Duration::from_secs(3600),
            )));
            let verdict = verifier.verify(&RawAttestation {
                bytes: real_tdx_quote(),
            });
            let QuoteVerdict::Unverified { why } = verdict else {
                panic!("expected Unverified against an empty cache, got {verdict:?}");
            };
            assert_eq!(WhyKind::classify(&why), WhyKind::CollateralAbsent);
        }

        #[test]
        fn a_stale_cache_entry_classifies_as_collateral_stale() {
            // Same technique as verify.rs's own `stale_collateral_is_unverified_never_verified`:
            // a zero TTL plus a spin-wait past the insertion instant, so
            // `age > ttl` is guaranteed without assuming any host uptime.
            let cache = CollateralCache::new("https://pccs.invalid".into(), Duration::ZERO);
            let fetched = Instant::now();
            cache.insert_for_test(REAL_FMSPC_HEX, real_collateral(), fetched);
            while Instant::now() <= fetched {
                std::hint::spin_loop();
            }
            let verifier = QuoteVerifier::new(Arc::new(cache));
            let verdict = verifier.verify(&RawAttestation {
                bytes: real_tdx_quote(),
            });
            let QuoteVerdict::Unverified { why } = verdict else {
                panic!("expected Unverified against a stale cache, got {verdict:?}");
            };
            assert_eq!(WhyKind::classify(&why), WhyKind::CollateralStale);
        }
    }
}
