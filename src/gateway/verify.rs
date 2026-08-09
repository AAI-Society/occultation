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
//! serial with no warning at all.
//!
//! The two renderings differ, and assuming otherwise is how this module's
//! first version shipped a hole. `serde_bytes` in `dcap-qvl` is a **rename**
//! (its manifest maps the name to `serde-human-bytes`), which on a
//! human-readable format calls `serialize_str` on lowercase hex — so JSON
//! gives `"deadbeef…"`, not the number array vanilla `serde_bytes` would
//! produce. Derived `Debug`, meanwhile, gives comma-*space* decimal:
//! `[222, 173, 190, …]`. Pretty `Debug` (`{:#?}`) gives one byte per line
//! *with a trailing comma*, and hex `Debug` (`{:x?}`) gives unpadded hex
//! (`[de, ad, be, ef, …, 9, …]`). A leak check has to cover all of them.
//! (Those bytes are invented. The fixture's real identifier is not written
//! anywhere in this crate, including in comments — it is recoverable from
//! the committed sample quote by anyone who needs it, but writing it down
//! is the exact habit this module exists to refuse.)
//!
//! Four guards, because no one of them is sufficient:
//!
//! 1. Three greps over `src/`, `tests/`, `benches/` and `examples/` — the
//!    field access, the name of the struct that carries it (which a stored
//!    field, a return type or a destructuring pattern all have to write),
//!    and the TCB-override entry point. Task 8 duplicates these, and they
//!    are the only checks that survive someone marking a behavioural test
//!    `#[ignore]`.
//! 2. A lexical ban on `:?`, `log::`, `println!`, `eprintln!` and `dbg!` in
//!    this module's non-test code. A grep for the identifier cannot see
//!    `log::info!("{verified:?}")`, which names nothing forbidden and never
//!    touches the verdict, but still writes the serial to disk.
//! 3. `a_real_verified_report_leaks_none_of_its_hardware_identifier`, which
//!    runs a genuine verification and asserts the real serial appears in
//!    neither the JSON nor the `Debug` rendering of the verdict, in any of
//!    four byte shapes and independent of whitespace.
//! 4. The escape set being a parameter list: `verified_verdict` takes the
//!    three permitted fields, so the report itself is never in scope where
//!    a verdict is built.

use crate::gateway::collateral::{fmspc_to_hex, hex_lower, CacheLookup, CollateralCache};
use crate::gateway::source::RawAttestation;
use dcap_qvl::quote::{EnclaveReport, Report, TDReport10, TDReport15};
use dcap_qvl::{Fmspc, QuoteCollateralV3};
use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Which trusted-execution platform produced a quote.
///
/// Derives `Hash` so `finding.rs` can use it directly as a Prometheus label
/// value's key (`Family`'s label set must be `Hash`) without a parallel
/// mirror enum — one three-variant enum, not two kept in sync by hand.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, Serialize)]
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
/// our own operational gap.
///
/// The strong guarantee is Task 3's, not the type system's: `CacheLookup::Stale`
/// carries no collateral by construction, so nothing can ever be *verified
/// against* a stale entry. Note what is **not** claimed — the error side of
/// this `Result` is a whole `QuoteVerdict`, so `Err(QuoteVerdict::Verified
/// { .. })` compiles fine. Returning a pass from here is prevented by the
/// tests below, not by the compiler.
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
    /// asserts the full spelling appears nowhere in `src/`, `tests/`,
    /// `benches/` or `examples/`. (That is also
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

        // Every shape the identifier can take on its way out. The two that
        // matter in practice are the ends of this list: `serde-human-bytes`
        // (which dcap-qvl renames to `serde_bytes` in its manifest) emits
        // *hex* from `serde_json`, while Rust's derived `Debug` for a
        // `Vec<u8>` emits *comma-space decimal*. An earlier version of this
        // test carried only a `join(",")` needle, which covers neither: it
        // matched serde's compact number array, the one form that never
        // occurs. `format!("{verified:?}")` into `tcb_status` passed all
        // fifteen tests as a result.
        let lower = hex_lower(&bytes);
        let upper = lower.to_uppercase();
        let debug_form = format!("{bytes:?}");
        let pretty_form = format!("{bytes:#?}");
        let hex_debug = format!("{bytes:x?}");
        let upper_hex_debug = format!("{bytes:X?}");
        // Redundant against `debug_form` at first glance — squeezed, that is
        // this string wrapped in brackets — but deliberately kept unbracketed:
        // pretty `Debug` emits a *trailing comma* before its closing bracket,
        // so `[129,…,253]` does not occur in a `{:#?}` dump while `129,…,253`
        // still does.
        let joined = bytes
            .iter()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let rendered = format!(
            "{}|{:?}",
            serde_json::to_string(&verdict).expect("the verdict serializes"),
            verdict
        );

        // Normalized before comparison, so a match cannot depend on how a
        // formatter chose to lay out its separators. Stripping whitespace is
        // not enough on its own: once a pretty `Debug` dump is *inside* a
        // string field, both `serde_json` and `Debug for str` escape its
        // newlines into the two literal characters `\` and `n`, which are not
        // whitespace and so survive the strip — leaving `[\n129,\n29,…` and
        // matching none of the needles. The escape pairs are removed first.
        fn squeeze(s: &str) -> String {
            s.replace("\\n", "")
                .replace("\\r", "")
                .replace("\\t", "")
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect()
        }
        let rendered = squeeze(&rendered);

        // Deliberately does not print the needle or the verdict on failure:
        // a test that leaks the hardware serial into CI logs to complain
        // about the hardware serial leaking has not helped anyone.
        for (shape, needle) in [
            ("lowercase hex", &lower),
            ("uppercase hex", &upper),
            ("a Debug byte array", &debug_form),
            ("a pretty Debug byte array", &pretty_form),
            ("a hex Debug byte array", &hex_debug),
            ("an upper-hex Debug byte array", &upper_hex_debug),
            ("a comma-joined byte array", &joined),
        ] {
            assert!(
                !rendered.contains(&squeeze(needle)),
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
        // Documents the wrapper relation rather than testing it: since the
        // extraction, `fmspc_to_hex` *is* a call to `hex_lower`, so this
        // line cannot fail. It is kept because the equality is the property
        // the rest of the module depends on, and a future edit that split
        // them again should have to delete an assertion that says so.
        assert_eq!(hex_lower(&fmspc), fmspc_to_hex(&fmspc));
        assert_eq!(hex_lower(&fmspc), "00806f0500ff");
        // Zero-padding, at a report field's width rather than an FMSPC's.
        assert_eq!(
            hex_lower(&[0x00u8, 0x01, 0x0f, 0xa0, 0xff, 0x00, 0x00, 0x09]),
            "00010fa0ff000009"
        );
    }

    /// `TcbConfig` ordering only. The keys here are illustrative and are
    /// deliberately *not* ones the implementation produces — the real key
    /// lists are pinned against real and synthetic reports elsewhere in this
    /// module.
    #[test]
    fn tcb_config_orders_its_attributes_regardless_of_insertion_order() {
        let c = TcbConfig::for_test(&[("tdx_module", "1.5.05"), ("pce_svn", "13")]);
        assert_eq!(c.attributes.len(), 2);
        assert_eq!(c.attributes.get("pce_svn").map(String::as_str), Some("13"));
        // Ordered, so the fingerprint downstream is order-independent.
        assert_eq!(
            c.attributes.keys().next().map(String::as_str),
            Some("pce_svn")
        );
    }

    /// A `TDReport10` with a distinct fill byte per field, so a helper that
    /// reads the *wrong* field produces the wrong value rather than a
    /// coincidentally-equal one. Every field is `pub` and the struct is
    /// `Copy` plain data, so this needs no fixture, no network and no clock
    /// — which is why the TDX 1.5 and SGX key lists have no excuse for going
    /// unpinned just because no sample quote for them exists.
    fn td10_with_distinct_fields() -> TDReport10 {
        TDReport10 {
            tee_tcb_svn: [0x11; 16],
            mr_seam: [0x22; 48],
            mr_signer_seam: [0x33; 48],
            seam_attributes: [0x44; 8],
            td_attributes: [0x55; 8],
            xfam: [0x66; 8],
            mr_td: [0x77; 48],
            mr_config_id: [0x88; 48],
            mr_owner: [0x99; 48],
            mr_owner_config: [0xaa; 48],
            rt_mr0: [0xbb; 48],
            rt_mr1: [0xcc; 48],
            rt_mr2: [0xdd; 48],
            rt_mr3: [0xee; 48],
            report_data: [0xff; 64],
        }
    }

    const TEST_FMSPC: Fmspc = [0x00, 0x80, 0x6f, 0x05, 0x00, 0x01];

    /// TDX 1.5 has no sample quote anywhere upstream, so this is the only
    /// thing standing between `tcb_config_from_td15` and a silent wrong
    /// answer. It pins the full key list *and* every value, so mapping a key
    /// to the wrong field — or reading `td.base` where `td` was meant —
    /// fails here rather than in the meter six weeks from now.
    #[test]
    fn the_tdx_15_config_adds_the_second_svn_and_keeps_the_base_attributes() {
        let td15 = TDReport15 {
            base: td10_with_distinct_fields(),
            tee_tcb_svn2: [0x12; 16],
            mr_service_td: [0x34; 48],
        };
        let c = tcb_config_from_td15(&td15, &TEST_FMSPC);

        let keys: Vec<&str> = c.attributes.keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            [
                "fmspc",
                "mr_seam",
                "mr_signer_seam",
                "seam_attributes",
                "td_attributes",
                "tee_tcb_svn",
                "tee_tcb_svn2",
                "xfam",
            ]
        );
        let get = |k: &str| c.attributes.get(k).map(String::as_str).unwrap_or("");
        assert_eq!(get("fmspc"), "00806f050001");
        assert_eq!(get("tee_tcb_svn"), "11".repeat(16));
        assert_eq!(get("mr_seam"), "22".repeat(48));
        assert_eq!(get("mr_signer_seam"), "33".repeat(48));
        assert_eq!(get("seam_attributes"), "44".repeat(8));
        assert_eq!(get("td_attributes"), "55".repeat(8));
        assert_eq!(get("xfam"), "66".repeat(8));
        // The field TDX 1.5 adds, and the reason this helper exists at all.
        assert_eq!(get("tee_tcb_svn2"), "12".repeat(16));

        // `mr_service_td` measures the workload's service TD, not the
        // platform, so it must not partition the meter.
        assert!(!c.attributes.contains_key("mr_service_td"));
        assert!(!get("tee_tcb_svn2").contains("34"));
    }

    /// The SGX equivalent. Upstream does ship an SGX sample quote, but this
    /// pins the key list without needing it — and pins the two integer
    /// renderings (`misc_select` as zero-padded hex, the ISV fields as
    /// decimal) that no byte-array test would catch.
    #[test]
    fn the_sgx_config_carries_platform_configuration_and_no_measurements() {
        let e = EnclaveReport {
            cpu_svn: [0x11; 16],
            misc_select: 0x0000_00a5,
            reserved1: [0; 28],
            attributes: [0x22; 16],
            mr_enclave: [0x33; 32],
            reserved2: [0; 32],
            mr_signer: [0x44; 32],
            reserved3: [0; 96],
            isv_prod_id: 7,
            isv_svn: 11,
            reserved4: [0; 60],
            report_data: [0x55; 64],
        };
        let c = tcb_config_from_sgx(&e, &TEST_FMSPC);

        let keys: Vec<&str> = c.attributes.keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            [
                "attributes",
                "cpu_svn",
                "fmspc",
                "isv_prod_id",
                "isv_svn",
                "misc_select",
            ]
        );
        let get = |k: &str| c.attributes.get(k).map(String::as_str).unwrap_or("");
        assert_eq!(get("fmspc"), "00806f050001");
        assert_eq!(get("cpu_svn"), "11".repeat(16));
        assert_eq!(get("attributes"), "22".repeat(16));
        // Zero-padded hex, so 0xa5 does not collide with 0xa50 downstream.
        assert_eq!(get("misc_select"), "000000a5");
        assert_eq!(get("isv_prod_id"), "7");
        assert_eq!(get("isv_svn"), "11");

        // The enclave's identity and its caller-controlled data must not be
        // here: mr_enclave and mr_signer name a specific binary and signing
        // key, which would collapse the anonymity set to that one enclave.
        for forbidden in ["mr_enclave", "mr_signer", "report_data", "ppid"] {
            assert!(!c.attributes.contains_key(forbidden), "{forbidden} leaked");
        }
        for (k, v) in &c.attributes {
            assert!(!v.contains(&"33".repeat(32)), "mr_enclave reached {k}");
            assert!(!v.contains(&"44".repeat(32)), "mr_signer reached {k}");
            assert!(!v.contains(&"55".repeat(64)), "report_data reached {k}");
        }
    }

    /// The `Report` dispatch, for all three variants.
    ///
    /// Testing the three `tcb_config_from_*` helpers directly is not enough:
    /// it leaves the `match` in `verified_verdict` unexercised for every
    /// variant the fixture is not. Routing `TD15` to `tcb_config_from_td10`
    /// — which compiles, since `TDReport15` derefs nothing but exposes
    /// `base` — silently drops `tee_tcb_svn2` from the fingerprint, and it
    /// survived the helper tests alone. Only the TDX 1.0 row here is also
    /// covered by the real fixture; the other two exist only here.
    #[test]
    fn each_report_variant_routes_to_its_own_platform_and_attributes() {
        let base = td10_with_distinct_fields();
        let verdict = |r: Report| verified_verdict("UpToDate".into(), vec![], &r, &TEST_FMSPC);

        let unwrap = |v: QuoteVerdict| match v {
            QuoteVerdict::Verified {
                platform, config, ..
            } => (platform, config),
            other => panic!("expected Verified, got {other:?}"),
        };

        let (p, c) = unwrap(verdict(Report::TD10(base)));
        assert_eq!(p, Platform::TdxV10);
        assert!(!c.attributes.contains_key("tee_tcb_svn2"));

        let (p, c) = unwrap(verdict(Report::TD15(TDReport15 {
            base,
            tee_tcb_svn2: [0x12; 16],
            mr_service_td: [0x34; 48],
        })));
        assert_eq!(p, Platform::TdxV15);
        assert_eq!(
            c.attributes.get("tee_tcb_svn2").map(String::as_str),
            Some("12".repeat(16).as_str()),
            "the TDX 1.5 arm must use the TDX 1.5 helper"
        );

        let (p, c) = unwrap(verdict(Report::SgxEnclave(EnclaveReport {
            cpu_svn: [0x11; 16],
            misc_select: 0xa5,
            reserved1: [0; 28],
            attributes: [0x22; 16],
            mr_enclave: [0x33; 32],
            reserved2: [0; 32],
            mr_signer: [0x44; 32],
            reserved3: [0; 96],
            isv_prod_id: 7,
            isv_svn: 11,
            reserved4: [0; 60],
            report_data: [0x55; 64],
        })));
        assert_eq!(p, Platform::SgxEnclave);
        assert_eq!(c.attributes.get("isv_svn").map(String::as_str), Some("11"));
        assert!(!c.attributes.contains_key("tee_tcb_svn"));
    }

    /// Assemble a needle at runtime so a grep for it cannot match the test
    /// that performs the grep. Spelling either name out in a string literal
    /// — or in a doc comment — would make these tests fail on their own
    /// source and force someone to weaken them.
    fn needle(head: &str, tail: &str) -> String {
        format!("{head}{tail}")
    }

    /// The crate roots the structural guards search.
    ///
    /// `src/` alone is not enough: Tasks 5–7 wire this verifier into
    /// integration tests, and a `{:?}` on a report in `tests/` dumps the
    /// hardware serial into CI logs — the exact harm, with none of the
    /// guards firing. Enumerated rather than `.` on purpose, because `.`
    /// descends into `target/`, where the vendored `dcap-qvl` source would
    /// match every pattern here and make all three tests fail permanently.
    const CRATE_ROOTS: [&str; 4] = ["src/", "tests/", "benches/", "examples/"];

    /// Grep the crate for `pattern`, returning the matching lines.
    ///
    /// The guards below pass when this returns empty — and an empty result
    /// is also what a wrong cwd, a missing root, or an unreadable directory
    /// produce, since grep exits 2 with empty stdout. Checking the exit
    /// status is what stops all three structural guards passing vacuously in
    /// exactly the situation where they can no longer see anything. grep
    /// exits 0 for "found", 1 for "not found", and anything else is a
    /// failure to search that must be loud.
    fn grep_crate(pattern: &str) -> String {
        let roots: Vec<&str> = CRATE_ROOTS
            .iter()
            .copied()
            .filter(|r| std::path::Path::new(r).is_dir())
            .collect();
        assert!(
            roots.contains(&"src/") && roots.contains(&"tests/"),
            "grep is not running from the package root; it can see {roots:?} \
             of {CRATE_ROOTS:?} and would report every pattern as absent"
        );

        let mut args = vec!["-rn", "--include=*.rs", pattern];
        args.extend_from_slice(&roots);
        let out = std::process::Command::new("grep")
            .args(&args)
            .output()
            .expect("grep runs");
        assert!(
            matches!(out.status.code(), Some(0) | Some(1)),
            "grep could not search {roots:?} (exit {:?}): {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// A positive control for [`grep_crate`]. Every guard below asserts that
    /// a pattern is *absent*, so all of them would pass against a search
    /// that silently matched nothing. This one asserts a pattern that must
    /// exist really is found, which is the only thing distinguishing "the
    /// crate is clean" from "the search did not happen".
    ///
    /// The needle is assembled at runtime for the same reason the guards'
    /// are: spelled as a literal it would match *itself* on this very line
    /// as well as the definition, so renaming the implementation function
    /// would leave the control green and it would no longer be a sentinel.
    #[test]
    fn the_structural_guards_are_actually_searching_something() {
        let found = grep_crate(&needle("fn tcb_config_", "from_td10"));
        assert!(
            found.contains("src/gateway/verify.rs"),
            "grep found no definition it must find; the other guards in this \
             module are passing vacuously: {found}"
        );
    }

    /// Nothing in the verifier's non-test code may hand a value to a
    /// formatter or a logger.
    ///
    /// This closes the path no other guard can see. `log::info!("{v:?}")`
    /// writes the hardware serial to disk, names no forbidden token, never
    /// touches the verdict, and would pass every other test in this file —
    /// and `log`/`env_logger` are already crate dependencies, so it is one
    /// line away at all times. The non-test half of this module contains
    /// zero `:?` and zero logging today, so the guard is free and cannot
    /// false-positive. If a debug rendering is ever genuinely needed near
    /// this boundary, write it by hand and prove by test that it omits the
    /// identifier — do not relax this.
    #[test]
    fn the_verifier_hands_nothing_to_a_formatter_it_did_not_choose() {
        let src = include_str!("verify.rs");
        const MARKER: &str = "#[cfg(test)]\nmod tests {";

        // Split on the test module's own header, not on a bare `#[cfg(test)]`
        // — `TcbConfig::for_test` carries one of those far above here, so the
        // naive split silently truncated the searched region to the first
        // hundred lines, and the assertion below is what caught that.
        //
        // What actually makes this region safe is a property worth writing
        // down, because it is invisible and a future "simplification" would
        // delete it: if MARKER is ever not found, `.next()` yields the
        // *whole file*, which trips both the `/*` assertion below (this
        // guard's own doc comment holds the file's only `/*`) and the token
        // ban (this guard's own banned-list array holds every token). The
        // failure mode of a broken split is therefore loud and
        // self-referential, not silent. The two-name assertion is weaker
        // than it looks — it proves only that the region reaches
        // `verify_at`'s signature, not where the region *ends*; that half is
        // covered by the tail check.
        let non_test = src.split(MARKER).next().expect("split yields a head");
        assert!(
            non_test.contains("fn verified_verdict") && non_test.contains("fn verify_at"),
            "the scanned region does not reach the implementation, so this \
             guard would pass against a truncated string"
        );

        // ...and nothing may live *after* the test module, which
        // `split(..).next()` would discard just as silently as it discarded
        // the implementation before. The test module's own items are all
        // indented, so the only column-zero line in the tail is the brace
        // that closes it at end of file.
        assert_eq!(src.matches(MARKER).count(), 1, "ambiguous test module");
        let tail = src.split(MARKER).nth(1).expect("split yields a tail");
        let after_test_module: Vec<&str> = tail
            .lines()
            .filter(|l| !l.is_empty() && !l.starts_with(char::is_whitespace))
            .collect();
        assert_eq!(
            after_test_module,
            ["}"],
            "code appears after the test module, where this guard cannot see it"
        );

        // Comments are not code, and this module's documentation has to be
        // able to discuss the very constructs the guard bans. Block comments
        // would defeat a line-wise strip, so they are banned outright rather
        // than parsed.
        assert!(
            !non_test.contains("/*"),
            "block comments would let banned code hide from this guard"
        );
        let code: String = non_test
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(code.contains("fn verified_verdict"));

        // `?}` rather than `:?`, because `:?` is incomplete: `{v:#?}` and
        // `{v:x?}` contain no `:?` at all, and both were verified to slip
        // past the earlier ban and every needle. Every Rust debug format
        // spec terminates with `?` immediately before `}` — `{:?}`, `{v:?}`,
        // `{:#?}`, `{:x?}`, `{:X?}`, `{:#x?}`, `{:>10?}` — so `?}` is
        // complete where `:?` was not, and it additionally catches a string
        // continuation splitting the token across lines, where the source
        // holds no `:?` but the continued line opens with `?}`. `:?` is kept
        // alongside it only so the failure message names the common case.
        for banned in ["?}", ":?", "log::", "println!", "eprintln!", "dbg!"] {
            assert!(
                !code.contains(banned),
                "{banned} appears in the verifier's non-test code, which is \
                 how a verified report reaches a log or a panic message \
                 without naming anything the greps look for"
            );
        }
    }

    /// A structural guard, not a stylistic one. This call would make the
    /// gateway report `Verified` for a platform whose TCB is out of date or
    /// revoked, and it is the only check that survives someone marking the
    /// behavioural tests `#[ignore]`.
    #[test]
    fn the_dangerous_override_is_never_called_anywhere_in_this_crate() {
        let found = grep_crate(&needle("dangerous_verify_with", "_tcb_override"));
        assert!(
            found.is_empty(),
            "the TCB-override entry point appears in the crate: {found}"
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
        let by_field = grep_crate(&needle("\\.", "ppid"));
        assert!(
            by_field.is_empty(),
            "something reads the hardware identifier field: {by_field}"
        );

        let by_type = grep_crate(&needle("Verified", "Report"));
        assert!(
            by_type.is_empty(),
            "something names the report type that carries the hardware \
             identifier, which is how it would become a field, a return \
             type, or a destructuring pattern: {by_type}"
        );
    }
}
