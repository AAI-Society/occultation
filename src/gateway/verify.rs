//! Full-chain DCAP quote verification, and the boundary where a hardware
//! serial number is destroyed rather than propagated.
//!
//! `dcap-qvl`'s verified-report struct carries a `ppid` field: a unique
//! per-platform hardware identifier, present on every *successful*
//! verification. This gateway exists to stop a relying party accumulating a
//! dossier on its counterparties, so it must not be the thing that writes
//! one down. The report is destructured inside [`QuoteVerifier::verify_at`],
//! three fields are copied out of it, and the binding is dropped in that
//! scope. Nothing downstream — [`QuoteVerdict`], [`TcbConfig`], the meter —
//! can carry it, because nothing downstream has anywhere to put it.
//!
//! The rule is structural rather than a matter of discipline, because the
//! field is *deliberately wired for serialization* upstream: the struct
//! derives both `Debug` and `Serialize` and the `ppid` field carries an
//! explicit `serde_bytes` attribute. A single `{:?}`, a `serde_json::to_*`,
//! or a `#[derive(Serialize)]` on anything holding one emits the hardware
//! serial with no warning at all. Confirmed against the fixture: `serde_bytes`
//! renders it as a *plain hex string*, so one `serde_json::to_string` on a
//! report prints the serial in the most directly readable form there is.
//!
//! Three greps at the bottom of this file enforce the absence of the
//! spellings that would let that happen — the field access, the name of the
//! struct that carries it (which is what a stored field, a return type or a
//! destructuring pattern would all have to write), and the TCB-override
//! entry point. They are duplicated as a CI guard in Task 8, and they are
//! the only checks that survive someone marking a behavioural test
//! `#[ignore]`. The one thing a grep cannot see — handing the whole binding
//! to a formatter — is covered behaviourally by
//! `a_real_verified_report_leaks_none_of_its_hardware_identifier`, which
//! runs a genuine verification and asserts the real serial appears nowhere
//! in the resulting verdict's `Debug` or JSON rendering.

use crate::gateway::collateral::{fmspc_to_hex, hex_lower, CacheLookup, CollateralCache};
use crate::gateway::source::RawAttestation;
use dcap_qvl::quote::{EnclaveReport, Report, TDReport10, TDReport15};
use dcap_qvl::{Fmspc, QuoteCollateralV3};
use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Which trusted-execution platform produced a quote.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    TdxV10,
    TdxV15,
    SgxEnclave,
}

/// The TCB attributes the meter partitions on. A `BTreeMap` so the ordering
/// is canonical and the fingerprint downstream cannot depend on insertion
/// order — the same reasoning as `anonymity::Fleet`'s TCB map.
///
/// Only *configuration* lands here: things that take the same value across
/// every workload on a platform of a given TCB level. Per-instance
/// measurements (`mr_td`, the runtime measurement registers, `mr_enclave`,
/// `mr_signer`, `report_data`) are deliberately excluded — they identify a
/// particular workload rather than a platform configuration, so including
/// them would shrink every anonymity set this tool exists to measure to one.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct TcbConfig {
    pub attributes: BTreeMap<String, String>,
}

impl TcbConfig {
    fn from_pairs(pairs: &[(&str, String)]) -> Self {
        TcbConfig {
            attributes: pairs
                .iter()
                .map(|(k, v)| ((*k).to_string(), v.clone()))
                .collect(),
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test(pairs: &[(&str, &str)]) -> Self {
        TcbConfig {
            attributes: pairs
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum QuoteVerdict {
    Verified {
        platform: Platform,
        tcb_status: String,
        advisories: Vec<String>,
        config: TcbConfig,
    },
    /// The agent's fault: the bytes are not a valid quote, or the chain fails.
    Invalid { reason: String },
    /// Our fault: we could not check. Never a pass.
    Unverified { why: String },
}

pub struct QuoteVerifier {
    cache: Arc<CollateralCache>,
}

/// Read the wall clock as whole seconds since the Unix epoch.
///
/// `None` for a clock set before the epoch. That is not an error the
/// counterparty caused, and it is not something we can verify around: the
/// collateral validity window is expressed in Unix seconds, so without a
/// readable clock there is no way to tell fresh collateral from expired.
/// [`QuoteVerifier::verify`] turns `None` into `Unverified`. Substituting a
/// `0` fallback would push a 1970 timestamp into the verifier, which happens
/// to fail closed today but only by accident of the collateral's `issueDate`.
fn now_secs_from(t: SystemTime) -> Option<u64> {
    t.duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs())
}

/// Turn a cache lookup into either collateral to verify against, or the
/// verdict explaining why we could not.
///
/// This is the single place the cache's three states become a decision, so a
/// reviewer can check the invariant by reading one function: **`Ok` is
/// returned for `Fresh` and nothing else.** Both other arms are `Unverified`
/// and never `Invalid`, because a cold or aged cache is our failure and not
/// the counterparty's — reporting it as `Invalid` would blame an agent for
/// our own operational gap. `Verified` is not reachable from here at all:
/// `CacheLookup::Stale` carries no collateral by construction (Task 3), so
/// there is nothing an arm could verify against even if it wanted to.
fn collateral_or_unverified(
    lookup: CacheLookup,
    fmspc_hex: &str,
) -> Result<Arc<QuoteCollateralV3>, QuoteVerdict> {
    match lookup {
        CacheLookup::Fresh(c) => Ok(c),
        CacheLookup::Stale { age } => Err(QuoteVerdict::Unverified {
            why: format!(
                "collateral for FMSPC {fmspc_hex} is {}s old and past its TTL; \
                 verifying against expired TCB data could report a revoked \
                 platform as up to date",
                age.as_secs()
            ),
        }),
        CacheLookup::Absent => Err(QuoteVerdict::Unverified {
            why: format!("no collateral cached for FMSPC {fmspc_hex} yet"),
        }),
    }
}

/// TDX 1.0 configuration attributes.
///
/// `tee_tcb_svn` is the TDX TCB version vector and `mr_seam` / `mr_signer_seam`
/// identify the Intel-signed TDX module itself, so together they are the
/// "which TDX module, at which patch level" fingerprint the meter partitions
/// on. `td_attributes` and `xfam` are the TD's configuration flags (debug
/// enabled, which extended features are activated) — configuration by
/// definition, and the debug bit in particular changes what a quote is worth.
///
/// Everything per-instance is left out on purpose: `mr_td`, `mr_config_id`,
/// `mr_owner`, `mr_owner_config`, `rt_mr0`–`rt_mr3` and `report_data` all
/// describe the specific workload rather than the platform it runs on.
fn tcb_config_from_td10(td: &TDReport10, fmspc: &Fmspc) -> TcbConfig {
    TcbConfig::from_pairs(&[
        ("fmspc", fmspc_to_hex(fmspc)),
        ("tee_tcb_svn", hex_lower(&td.tee_tcb_svn)),
        ("mr_seam", hex_lower(&td.mr_seam)),
        ("mr_signer_seam", hex_lower(&td.mr_signer_seam)),
        ("seam_attributes", hex_lower(&td.seam_attributes)),
        ("td_attributes", hex_lower(&td.td_attributes)),
        ("xfam", hex_lower(&td.xfam)),
    ])
}

/// TDX 1.5 configuration attributes: everything TDX 1.0 exposes, from the
/// embedded `base` report, plus the second TCB SVN vector 1.5 adds.
///
/// `mr_service_td` is *not* included. It measures the service TD a workload
/// is bound to, which is a property of that workload rather than of the
/// platform's configuration.
fn tcb_config_from_td15(td: &TDReport15, fmspc: &Fmspc) -> TcbConfig {
    let mut config = tcb_config_from_td10(&td.base, fmspc);
    config
        .attributes
        .insert("tee_tcb_svn2".to_string(), hex_lower(&td.tee_tcb_svn2));
    config
}

/// SGX enclave configuration attributes.
///
/// `cpu_svn` is the platform TCB level; `attributes` and `misc_select` are
/// the enclave's configuration flags; `isv_prod_id` and `isv_svn` name the
/// enclave product and its security version. `mr_enclave`, `mr_signer` and
/// `report_data` are excluded — the first two identify a specific enclave
/// binary and its signing key, and the third is caller-controlled.
fn tcb_config_from_sgx(e: &EnclaveReport, fmspc: &Fmspc) -> TcbConfig {
    TcbConfig::from_pairs(&[
        ("fmspc", fmspc_to_hex(fmspc)),
        ("cpu_svn", hex_lower(&e.cpu_svn)),
        ("attributes", hex_lower(&e.attributes)),
        ("misc_select", format!("{:08x}", e.misc_select)),
        ("isv_prod_id", e.isv_prod_id.to_string()),
        ("isv_svn", e.isv_svn.to_string()),
    ])
}

/// Build the `Verified` verdict from the three fields that are allowed to
/// leave a verified report, and nothing else.
///
/// Taking `status` and `advisory_ids` *by value* is the point: the caller
/// moves exactly those two fields out of the report and borrows the third,
/// so the set of things that cross this boundary is the parameter list of
/// this function and a reader does not have to trust a comment about it.
fn verified_verdict(
    status: String,
    advisory_ids: Vec<String>,
    report: &Report,
    fmspc: &Fmspc,
) -> QuoteVerdict {
    let (platform, config) = match report {
        Report::TD10(td) => (Platform::TdxV10, tcb_config_from_td10(td, fmspc)),
        Report::TD15(td) => (Platform::TdxV15, tcb_config_from_td15(td, fmspc)),
        Report::SgxEnclave(e) => (Platform::SgxEnclave, tcb_config_from_sgx(e, fmspc)),
    };
    QuoteVerdict::Verified {
        platform,
        tcb_status: status,
        advisories: advisory_ids,
        config,
    }
}

impl QuoteVerifier {
    pub fn new(cache: Arc<CollateralCache>) -> Self {
        QuoteVerifier { cache }
    }

    /// Verify a quote against cached collateral.
    ///
    /// Fail-open is absolute here: every input, malformed or hostile,
    /// produces a [`QuoteVerdict`]. There is no error path out of this
    /// function and nothing in it may panic.
    ///
    /// `dcap-qvl` also exposes a TCB-override entry point, whose name begins
    /// `dangerous_verify_with_` and which is well named: it lets a caller
    /// rewrite the TCB info after signature checking, which would make this
    /// gateway report `Verified` for a platform Intel has revoked. It is
    /// never called here, and
    /// `the_dangerous_override_is_never_called_anywhere_in_this_crate`
    /// asserts the full spelling appears nowhere under `src/`. (That is also
    /// why this comment does not write the name out in full — the test would
    /// find its own documentation.)
    pub fn verify(&self, raw: &RawAttestation) -> QuoteVerdict {
        self.verify_at(raw, now_secs_from(SystemTime::now()))
    }

    /// [`Self::verify`] with the wall clock injected.
    ///
    /// Parameterized on `now_secs` for the same reason `CollateralCache`'s
    /// `lookup_at` is: collateral is only valid inside a window of Unix
    /// seconds, so a test that cannot pin the clock cannot reach a genuine
    /// `Verified` at all, and every attribute key below would go unpinned.
    /// `None` models an unreadable clock. Production always passes
    /// `now_secs_from(SystemTime::now())`.
    fn verify_at(&self, raw: &RawAttestation, now_secs: Option<u64>) -> QuoteVerdict {
        let parsed = match dcap_qvl::quote::Quote::parse(&raw.bytes) {
            Ok(q) => q,
            Err(e) => {
                return QuoteVerdict::Invalid {
                    reason: format!("not a DCAP quote: {e}"),
                }
            }
        };
        let fmspc = match dcap_qvl::intel::quote_fmspc(&parsed) {
            Ok(f) => f,
            Err(e) => {
                return QuoteVerdict::Invalid {
                    reason: format!("not a DCAP quote: {e}"),
                }
            }
        };
        let fmspc_hex = fmspc_to_hex(&fmspc);

        let collateral = match collateral_or_unverified(self.cache.get(&fmspc), &fmspc_hex) {
            Ok(c) => c,
            Err(verdict) => return verdict,
        };

        let Some(now_secs) = now_secs else {
            return QuoteVerdict::Unverified {
                why: "the system clock reads before the Unix epoch, so collateral \
                      validity cannot be checked"
                    .to_string(),
            };
        };

        match dcap_qvl::verify::verify(&raw.bytes, &collateral, now_secs) {
            Err(e) => QuoteVerdict::Invalid {
                reason: e.to_string(),
            },
            // `verified` also carries a unique per-platform hardware
            // identifier. It is never bound to a name, never formatted,
            // never serialized, and drops at the end of this arm. Exactly
            // three fields leave: the two moved out below and the borrowed
            // report body, from which only configuration is copied.
            Ok(verified) => verified_verdict(
                verified.status,
                verified.advisory_ids,
                &verified.report,
                &fmspc,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    /// A real TDX quote, vendored from `dcap-qvl` 0.6.1's `sample/tdx_quote`
    /// (Phala Network, MIT — see `tests/fixtures/PROVENANCE.txt`), together
    /// with the collateral bundle Intel issued for it.
    ///
    /// It is a genuine quote off real hardware rather than a fabrication: a
    /// hand-built quote could not carry a PCK certificate chain, so
    /// `quote_fmspc` would fail on it and every test below would stop at
    /// `Invalid` without ever reaching the cache arms or the verifier. Using
    /// the real thing is also what makes
    /// `a_real_verification_yields_the_configuration_attributes_and_no_more`
    /// possible, which is the only test that pins the attribute key strings.
    fn real_tdx_quote() -> Vec<u8> {
        include_bytes!("../../tests/fixtures/tdx-quote.bin").to_vec()
    }

    fn real_collateral() -> QuoteCollateralV3 {
        serde_json::from_slice(include_bytes!(
            "../../tests/fixtures/tdx-quote-collateral.json"
        ))
        .expect("the vendored collateral fixture decodes")
    }

    /// The FMSPC of [`real_tdx_quote`], as `fmspc_to_hex` renders it. Written
    /// out rather than computed so a mutation to the FMSPC extraction path
    /// shows up as a failure here instead of quietly agreeing with itself.
    const REAL_FMSPC_HEX: &str = "b0c06f000000";

    /// A timestamp inside the vendored collateral's validity window. Both the
    /// TCB info and the QE identity in the bundle were issued 2025-06-19 and
    /// expire 2025-07-19, so a real clock is far outside it now; verification
    /// against this bundle only succeeds with the clock pinned.
    const NOW_INSIDE_COLLATERAL_WINDOW: u64 = 1_750_809_600; // 2025-06-25T00:00:00Z

    fn fmspc_of_real_quote() -> Fmspc {
        let parsed =
            dcap_qvl::quote::Quote::parse(&real_tdx_quote()).expect("the fixture is a real quote");
        dcap_qvl::intel::quote_fmspc(&parsed).expect("the fixture carries a PCK chain")
    }

    fn verifier_with_empty_cache() -> QuoteVerifier {
        QuoteVerifier::new(Arc::new(CollateralCache::new(
            "https://pccs.invalid".into(),
            Duration::from_secs(3600),
        )))
    }

    fn verifier_with_fresh_collateral() -> QuoteVerifier {
        let cache = CollateralCache::new("https://pccs.invalid".into(), Duration::from_secs(3600));
        cache.insert_for_test(
            &fmspc_to_hex(&fmspc_of_real_quote()),
            real_collateral(),
            Instant::now(),
        );
        QuoteVerifier::new(Arc::new(cache))
    }

    /// The fixture must be the platform every other test assumes it is. If
    /// this drifts, the `why`-string assertions below would still pass while
    /// asserting nothing about the real extraction path.
    #[test]
    fn the_fixture_is_a_real_tdx_quote_with_a_known_fmspc() {
        assert_eq!(fmspc_to_hex(&fmspc_of_real_quote()), REAL_FMSPC_HEX);
    }

    #[test]
    fn a_quote_with_no_collateral_is_unverified_not_invalid() {
        // Absent collateral is our failure, not the agent's. Reporting it as
        // Invalid would blame a counterparty for our own cold cache.
        let v = verifier_with_empty_cache();
        match v.verify(&RawAttestation {
            bytes: real_tdx_quote(),
        }) {
            QuoteVerdict::Unverified { why } => {
                assert!(why.contains("collateral"), "unhelpful why: {why}");
                // An operator has to act on this, so it must name the
                // platform whose collateral is missing.
                assert!(why.contains(REAL_FMSPC_HEX), "why omits the FMSPC: {why}");
            }
            other => panic!("expected Unverified, got {other:?}"),
        }
    }

    #[test]
    fn stale_collateral_is_unverified_never_verified() {
        // A zero TTL plus a guaranteed clock tick, rather than
        // `Instant::now() - Duration::from_secs(61)`: `Instant` is monotonic
        // from boot, so subtracting a minute panics on a host that has been
        // up for less than one. Spinning until the clock has advanced past
        // `fetched` makes `age > 0` certain without assuming any uptime, and
        // without the test being able to pass for the wrong reason (a
        // still-fresh entry would return `Fresh` and fail the assertion).
        let cache = CollateralCache::new("https://pccs.invalid".into(), Duration::ZERO);
        let fetched = Instant::now();
        cache.insert_for_test(
            &fmspc_to_hex(&fmspc_of_real_quote()),
            real_collateral(),
            fetched,
        );
        while Instant::now() <= fetched {
            std::hint::spin_loop();
        }

        let v = QuoteVerifier::new(Arc::new(cache));
        match v.verify(&RawAttestation {
            bytes: real_tdx_quote(),
        }) {
            QuoteVerdict::Unverified { why } => {
                // Content, not just the variant: an operator reads this, and
                // a `why` that said "no collateral cached" would describe the
                // wrong failure and send them to fix the wrong thing.
                assert!(why.contains("past its TTL"), "wrong why for stale: {why}");
                assert!(why.contains(REAL_FMSPC_HEX), "why omits the FMSPC: {why}");
            }
            other => panic!("stale collateral must be Unverified, got {other:?}"),
        }
    }

    #[test]
    fn bytes_that_are_not_a_quote_are_invalid_not_a_panic() {
        let v = verifier_with_empty_cache();
        for junk in [
            vec![],
            vec![0u8; 3],
            vec![0xff; 5000],
            b"not a quote at all".to_vec(),
        ] {
            match v.verify(&RawAttestation { bytes: junk }) {
                QuoteVerdict::Invalid { reason } => {
                    assert!(reason.contains("not a DCAP quote"), "bare reason: {reason}");
                }
                QuoteVerdict::Unverified { .. } => {}
                QuoteVerdict::Verified { .. } => panic!("junk must never verify"),
            }
        }
    }

    /// A truncation sweep over the real quote: every prefix of a genuine
    /// quote is a plausible hostile input, and none of them may panic or
    /// verify. Fixed junk buffers all fail in the same first few bytes of
    /// the header and never exercise the deeper decode paths.
    #[test]
    fn every_truncation_of_a_real_quote_is_refused_without_panicking() {
        let v = verifier_with_fresh_collateral();
        let full = real_tdx_quote();
        for len in (0..full.len()).step_by(7) {
            let verdict = v.verify(&RawAttestation {
                bytes: full[..len].to_vec(),
            });
            assert!(
                !matches!(verdict, QuoteVerdict::Verified { .. }),
                "a {len}-byte truncation verified"
            );
        }
    }

    /// The constraint the design turns on. A verified report carries a
    /// unique per-platform hardware identifier, and it must not survive this
    /// boundary in any form.
    #[test]
    fn the_ppid_never_crosses_the_verifier_boundary() {
        let verdict = QuoteVerdict::Verified {
            platform: Platform::TdxV10,
            tcb_status: "UpToDate".into(),
            advisories: vec![],
            config: TcbConfig::for_test(&[("tdx_module", "1.5.05")]),
        };
        let json = serde_json::to_string(&verdict).unwrap();
        assert!(
            !json.to_lowercase().contains("ppid"),
            "the PPID reached the verdict: {json}"
        );
    }

    /// The same constraint, proved against the real thing rather than a
    /// hand-built verdict.
    ///
    /// Runs a genuine full-chain verification, pulls the hardware identifier
    /// out of the resulting report *in the test only* (via serde, so this
    /// file still contains no field access the grep guard would catch), and
    /// asserts none of its bytes appear anywhere in the serialized verdict —
    /// in hex, in either case, or as the JSON number array `serde_bytes`
    /// would produce. The hand-built test above cannot catch a verifier that
    /// copies the identifier into a TCB attribute value; this one does.
    ///
    /// It also fails loudly if upstream ever renames or drops the field,
    /// which is the right time to re-read this module rather than to assume
    /// the problem went away.
    #[test]
    fn a_real_verified_report_leaks_none_of_its_hardware_identifier() {
        let report = dcap_qvl::verify::verify(
            &real_tdx_quote(),
            &real_collateral(),
            NOW_INSIDE_COLLATERAL_WINDOW,
        )
        .expect("the vendored fixture verifies inside its collateral window");

        let as_json = serde_json::to_value(&report).expect("a verified report serializes");
        let field = as_json
            .get("ppid")
            .expect("dcap-qvl still exposes a per-platform hardware identifier");
        // Worth recording what this turned out to be: `serde_bytes` renders
        // the field as a *plain hex string*, not a JSON byte array, so a
        // single `serde_json::to_string` on a report emits the hardware
        // serial in the most directly readable form there is.
        let bytes: Vec<u8> = match field {
            serde_json::Value::String(s) => (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..(i + 2).min(s.len())], 16))
                .collect::<Result<_, _>>()
                .expect("the identifier renders as hex"),
            serde_json::Value::Array(_) => {
                serde_json::from_value(field.clone()).expect("the identifier is a byte array")
            }
            other => panic!("unexpected hardware identifier encoding: {other}"),
        };
        assert!(
            !bytes.is_empty(),
            "the fixture produced an empty hardware identifier, so this test proves nothing"
        );

        let verdict = verifier_with_fresh_collateral().verify_at(
            &RawAttestation {
                bytes: real_tdx_quote(),
            },
            Some(NOW_INSIDE_COLLATERAL_WINDOW),
        );
        assert!(
            matches!(verdict, QuoteVerdict::Verified { .. }),
            "expected a real Verified verdict to test against, got {verdict:?}"
        );

        let lower = hex_lower(&bytes);
        let upper = lower.to_uppercase();
        let numbers = bytes
            .iter()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let rendered = format!(
            "{}|{:?}",
            serde_json::to_string(&verdict).expect("the verdict serializes"),
            verdict
        );
        // Deliberately does not print the needle or the verdict on failure:
        // a test that leaks the hardware serial into CI logs to complain
        // about the hardware serial leaking has not helped anyone.
        for (shape, needle) in [
            ("lowercase hex", &lower),
            ("uppercase hex", &upper),
            ("a byte array", &numbers),
        ] {
            assert!(
                !rendered.contains(needle.as_str()),
                "the hardware identifier reached the verdict as {shape}"
            );
        }
    }

    /// The only test that pins the attribute key strings against a real
    /// report. An attribute the meter later partitions on is worthless if a
    /// typo'd key silently produces a different fingerprint, and every other
    /// test here uses `for_test`, which would happily accept any key at all.
    #[test]
    fn a_real_verification_yields_the_configuration_attributes_and_no_more() {
        let verdict = verifier_with_fresh_collateral().verify_at(
            &RawAttestation {
                bytes: real_tdx_quote(),
            },
            Some(NOW_INSIDE_COLLATERAL_WINDOW),
        );
        let QuoteVerdict::Verified {
            platform,
            tcb_status,
            config,
            ..
        } = verdict
        else {
            panic!("the fixture must verify inside its collateral window, got {verdict:?}");
        };

        assert_eq!(platform, Platform::TdxV10);
        assert!(!tcb_status.is_empty(), "a verified report has a TCB status");

        let keys: Vec<&str> = config.attributes.keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            [
                "fmspc",
                "mr_seam",
                "mr_signer_seam",
                "seam_attributes",
                "td_attributes",
                "tee_tcb_svn",
                "xfam",
            ],
            "the meter partitions on these exact keys"
        );
        assert_eq!(
            config.attributes.get("fmspc").map(String::as_str),
            Some(REAL_FMSPC_HEX),
            "the FMSPC attribute must be the quote's own, rendered by fmspc_to_hex"
        );
        // Values are real, not placeholders: every one is non-empty hex.
        for (k, v) in &config.attributes {
            assert!(!v.is_empty(), "attribute {k} is empty");
            assert!(
                v.chars().all(|c| c.is_ascii_hexdigit()),
                "attribute {k} is not hex: {v}"
            );
        }

        // Per-instance measurements must not have crept in. Each of these is
        // a field of the same TDReport10 the configuration came out of, so a
        // careless addition would land here.
        for forbidden in [
            "mr_td",
            "mr_config_id",
            "mr_owner",
            "mr_owner_config",
            "rt_mr0",
            "rt_mr1",
            "rt_mr2",
            "rt_mr3",
            "report_data",
            "mr_enclave",
            "mr_signer",
            "ppid",
        ] {
            assert!(
                !config.attributes.contains_key(forbidden),
                "{forbidden} is per-instance and must not partition the meter"
            );
        }
    }

    /// Fresh collateral must actually reach `dcap_qvl::verify::verify`. With
    /// a clock outside the bundle's validity window the chain check fails,
    /// and that failure has to surface as `Invalid` — a verifier that
    /// returned `Unverified` here would be indistinguishable from one that
    /// never called the verifier at all.
    #[test]
    fn fresh_collateral_reaches_the_verifier_and_a_failed_chain_is_invalid() {
        let verdict = verifier_with_fresh_collateral().verify_at(
            &RawAttestation {
                bytes: real_tdx_quote(),
            },
            Some(NOW_INSIDE_COLLATERAL_WINDOW + 400 * 24 * 3600),
        );
        match verdict {
            QuoteVerdict::Invalid { reason } => assert!(!reason.is_empty()),
            other => panic!("an expired chain must be Invalid, got {other:?}"),
        }
    }

    /// The three cache states, at the one function that turns them into a
    /// decision. Asserted on content because an operator reads these, and
    /// because `matches!(v, Unverified { .. })` passes for a message that
    /// describes the wrong failure.
    #[test]
    fn absent_and_stale_collateral_both_refuse_to_produce_a_pass() {
        let absent = collateral_or_unverified(CacheLookup::Absent, REAL_FMSPC_HEX)
            .expect_err("an absent entry cannot yield collateral");
        match &absent {
            QuoteVerdict::Unverified { why } => {
                assert!(why.contains("no collateral cached"), "{why}");
                assert!(why.contains(REAL_FMSPC_HEX), "{why}");
            }
            other => panic!("Absent must be Unverified, not {other:?}"),
        }

        let stale = collateral_or_unverified(
            CacheLookup::Stale {
                age: Duration::from_secs(900),
            },
            REAL_FMSPC_HEX,
        )
        .expect_err("a stale entry cannot yield collateral");
        match &stale {
            QuoteVerdict::Unverified { why } => {
                assert!(why.contains("900s old"), "the age must be reported: {why}");
                assert!(why.contains("past its TTL"), "{why}");
                assert!(why.contains(REAL_FMSPC_HEX), "{why}");
            }
            other => panic!("Stale must be Unverified, not {other:?}"),
        }

        // And Fresh is the only arm that hands back collateral at all.
        assert!(
            collateral_or_unverified(
                CacheLookup::Fresh(Arc::new(real_collateral())),
                REAL_FMSPC_HEX
            )
            .is_ok(),
            "Fresh collateral must reach the verifier"
        );
    }

    /// An unreadable clock is our failure, like a cold cache — not the
    /// counterparty's, and never a pass.
    #[test]
    fn an_unreadable_clock_is_unverified_rather_than_a_pass() {
        let verdict = verifier_with_fresh_collateral().verify_at(
            &RawAttestation {
                bytes: real_tdx_quote(),
            },
            None,
        );
        match verdict {
            QuoteVerdict::Unverified { why } => assert!(why.contains("clock"), "{why}"),
            other => panic!("an unreadable clock must be Unverified, got {other:?}"),
        }
        assert_eq!(now_secs_from(UNIX_EPOCH - Duration::from_secs(1)), None);
        assert_eq!(now_secs_from(UNIX_EPOCH + Duration::from_secs(7)), Some(7));
    }

    /// The verifier renders TCB attribute values through the *same* function
    /// the cache keys its entries with, so a cache key and an attribute can
    /// never describe one platform two ways. `fmspc_to_hex` is now a wrapper
    /// over `hex_lower`, which makes that identity structural rather than a
    /// property two independent renderers happen to share.
    ///
    /// The widths here are the ones the FMSPC renderer cannot take: a report
    /// field is 8, 16 or 48 bytes wide, and dropped zero-padding on any of
    /// them would silently merge two distinct TCB configurations into one
    /// fingerprint downstream.
    #[test]
    fn tcb_attribute_hex_is_the_same_rendering_the_cache_keys_on() {
        let fmspc: Fmspc = [0x00, 0x80, 0x6f, 0x05, 0x00, 0xff];
        assert_eq!(hex_lower(&fmspc), fmspc_to_hex(&fmspc));
        assert_eq!(hex_lower(&fmspc), "00806f0500ff");
        // Zero-padding, at a report field's width rather than an FMSPC's.
        assert_eq!(
            hex_lower(&[0x00u8, 0x01, 0x0f, 0xa0, 0xff, 0x00, 0x00, 0x09]),
            "00010fa0ff000009"
        );
    }

    #[test]
    fn tcb_config_carries_the_attributes_the_meter_partitions_on() {
        let c = TcbConfig::for_test(&[("tdx_module", "1.5.05"), ("pce_svn", "13")]);
        assert_eq!(c.attributes.len(), 2);
        assert_eq!(c.attributes.get("pce_svn").map(String::as_str), Some("13"));
        // Ordered, so the fingerprint downstream is order-independent.
        assert_eq!(
            c.attributes.keys().next().map(String::as_str),
            Some("pce_svn")
        );
    }

    /// Assemble a needle at runtime so a grep for it cannot match the test
    /// that performs the grep. Spelling either name out in a string literal
    /// — or in a doc comment — would make these tests fail on their own
    /// source and force someone to weaken them.
    fn needle(head: &str, tail: &str) -> String {
        format!("{head}{tail}")
    }

    fn grep_src(pattern: &str) -> String {
        let out = std::process::Command::new("grep")
            .args(["-rn", "--include=*.rs", pattern, "src/"])
            .output()
            .expect("grep runs");
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// A structural guard, not a stylistic one. This call would make the
    /// gateway report `Verified` for a platform whose TCB is out of date or
    /// revoked, and it is the only check that survives someone marking the
    /// behavioural tests `#[ignore]`.
    #[test]
    fn the_dangerous_override_is_never_called_anywhere_in_this_crate() {
        let found = grep_src(&needle("dangerous_verify_with", "_tcb_override"));
        assert!(
            found.is_empty(),
            "the TCB-override entry point appears in src/: {found}"
        );
    }

    /// Same shape, for the hardware identifier.
    ///
    /// Two patterns, because one alone is escapable. The field-access
    /// spelling catches `report.<id>`; the type-name spelling catches
    /// everything that has to name the struct to get at it — a struct field
    /// holding one, a function returning one, a `let Struct { id, .. }`
    /// destructure, a turbofish. Together they leave only "pass the whole
    /// binding to a formatter", which is why `verified_verdict` takes the
    /// three permitted fields as parameters instead.
    #[test]
    fn the_hardware_identifier_is_referenced_nowhere_in_this_crate() {
        let by_field = grep_src(&needle("\\.", "ppid"));
        assert!(
            by_field.is_empty(),
            "something reads the hardware identifier field: {by_field}"
        );

        let by_type = grep_src(&needle("Verified", "Report"));
        assert!(
            by_type.is_empty(),
            "something names the report type that carries the hardware \
             identifier, which is how it would become a field, a return \
             type, or a destructuring pattern: {by_type}"
        );
    }
}
