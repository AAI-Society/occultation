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
//! marker on the line itself). The anonymity block — the one place this
//! module prints a number — is gated on `observation.is_some()` alone, not
//! on which verdict produced it: an `Unverified` finding has no trustworthy
//! configuration to partition on, so it must never carry a set size, and
//! `a_verified_finding_with_no_observation_omits_the_anonymity_block_too`
//! pins that the gate is the `Option`, not a `matches!` on the verdict, so a
//! future edit cannot special-case one arm at a time and shrink the other's
//! guarantee.
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
//! than silently falling through to a default label. `tcb_status` and
//! `why_kind` both start from free text (`QuoteVerdict::Verified.tcb_status`
//! is a `String`; `QuoteVerdict::Unverified.why` likewise) that must never
//! itself reach a label — see [`TcbStatusLabel::classify`] and
//! [`WhyKind::classify`], and `a_free_text_why_containing_an_fmspc_never_reaches_a_metric_label`
//! for the property this whole module exists to hold: a Prometheus label is
//! a database, and a free-text `why` can carry an FMSPC into it.
//!
//! One honest gap: the task brief names exactly four `why_kind` values
//! (`collateral_absent`, `collateral_stale`, `pcs_unreachable`,
//! `unsupported_platform`). [`QuoteVerifier::verify_at`] in `verify.rs` also
//! produces a fifth `Unverified` reason today — an unreadable system clock —
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
        let (verdict_word, parenthetical) = match &self.verdict {
            QuoteVerdict::Verified {
                platform,
                tcb_status,
                ..
            } => (
                "VERIFIED",
                format!("{}, TCB {tcb_status}", platform_display(platform)),
            ),
            QuoteVerdict::Unverified { why } => ("UNVERIFIED", why.clone()),
            QuoteVerdict::Invalid { reason } => ("INVALID", reason.clone()),
        };

        let mut out =
            format!("agent authorized \u{2713}   quote: {verdict_word} ({parenthetical})\n");

        // Gated on the `Option` alone, not on the verdict: an `Unverified`
        // or `Invalid` finding has no trustworthy configuration to
        // partition on, so it must never carry a set size, no matter which
        // verdict arm produced it.
        if let Some(obs) = &self.observation {
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
/// A local mirror of [`Platform`] rather than that type reused directly:
/// `Platform` does not derive `Hash` (nothing before this module needed a
/// `Platform` as a map key), and this module's file scope is `Finding` and
/// `Metrics` only — adding a derive to `verify.rs` is Task 4's file to
/// touch, not this one's. The `From` impl is exhaustive for the same reason
/// every other mapping here is.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
enum PlatformLabel {
    TdxV10,
    TdxV15,
    SgxEnclave,
}

impl From<Platform> for PlatformLabel {
    fn from(p: Platform) -> Self {
        match p {
            Platform::TdxV10 => PlatformLabel::TdxV10,
            Platform::TdxV15 => PlatformLabel::TdxV15,
            Platform::SgxEnclave => PlatformLabel::SgxEnclave,
        }
    }
}

impl EncodeLabelValue for PlatformLabel {
    fn encode(&self, encoder: &mut LabelValueEncoder) -> Result<(), std::fmt::Error> {
        let s: &str = match self {
            PlatformLabel::TdxV10 => "tdx_v10",
            PlatformLabel::TdxV15 => "tdx_v15",
            PlatformLabel::SgxEnclave => "sgx_enclave",
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
    platform: PlatformLabel,
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
                        platform: PlatformLabel::from(*platform),
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
        assert!(
            out.contains("3 of 1847"),
            "the set and the corpus, together: {out}"
        );
        assert!(out.contains("tee_tcb_svn"), "{out}");
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
        assert!(!f.render().to_lowercase().contains("replay"));
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
        assert!(out.contains("UNVERIFIED"), "{out}");
        assert!(
            out.contains("no collateral cached"),
            "the reason must reach the reader: {out}"
        );
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

    #[test]
    fn each_platform_variant_renders_its_own_distinct_label() {
        let mut reg = Registry::default();
        let m = Metrics::new(&mut reg);
        for platform in [Platform::TdxV10, Platform::TdxV15, Platform::SgxEnclave] {
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
        }
        let mut buf = String::new();
        prometheus_client::encoding::text::encode(&mut buf, &reg).unwrap();
        for label in ["tdx_v10", "tdx_v15", "sgx_enclave"] {
            assert!(buf.contains(label), "missing platform label {label}: {buf}");
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

    /// The real, current gap: `verify.rs`'s unreadable-clock message is
    /// none of the four named causes. Copied verbatim from `verify_at` so a
    /// rewording there is caught here rather than silently reclassified.
    #[test]
    fn an_unreadable_clock_reason_does_not_pretend_to_be_one_of_the_four_named_causes() {
        let why = "the system clock reads before the Unix epoch, so collateral \
                    validity cannot be checked";
        assert_eq!(WhyKind::classify(why), WhyKind::Other);
    }
}
