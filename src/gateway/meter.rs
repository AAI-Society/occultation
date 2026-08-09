//! The linkability meter, and the correlation it refuses to perform.
//!
//! A tool that warns a relying party it is silently accumulating a profile
//! of its counterparties must not accumulate that profile itself. A store of
//! per-session TCB fingerprints would be exactly that profile, and a
//! high-value target whose breach hands over exactly the correlation this
//! gateway exists to warn about.
//!
//! So this module keeps exactly two structures, and no third:
//!
//! ```text
//! counts:    HashMap<[u8; 32], u64>                    // H(salt ‖ fingerprint) → sessions
//! marginals: BTreeMap<String, HashMap<[u8; 32], u64>>  // attribute → H(salt ‖ value) → count
//! ```
//!
//! `set_size`, `distinct_configs` and which attributes are doing the
//! deanonymizing all come out of that size distribution and those marginals.
//! Neither structure records *who* produced an observation, or *when* two
//! observations shared a session — there is no session identifier anywhere
//! in this module, and [`TcbConfig`] carries nothing but platform
//! configuration in the first place. The one question an operator will ask
//! for — "has this agent been here before" — this store cannot answer. That
//! refusal is structural, not documented: see
//! `two_sessions_on_one_configuration_are_indistinguishable_in_what_is_retained`
//! below, which is this module's analogue of the pool's no-reuse invariant.
//!
//! The salt (`Store::salt`) rotates on `rotation`, driven by
//! [`LinkabilityMeter::rotate_if_due`]. Rotation clears both structures, so
//! correlation ages out by construction rather than by an operator
//! remembering to purge anything. The salt only ever defends a *partial*
//! disclosure, though — it is worth being honest about the limit rather
//! than overselling it. It lives in the same `Store` as `counts` and
//! `marginals`, so anyone who can read one can read the other and the
//! config space is small enough to enumerate offline regardless; it is
//! also a pure function of the `seed` passed to [`LinkabilityMeter::new`],
//! so a seed sourced from a config file rather than real randomness makes
//! the salt derivable from that config alone. What the salt actually buys:
//! `counts`/`marginals` leaking *without* `salt` (a log line, a partial
//! backup, one file copied but not the other) cannot be joined against an
//! offline guess of which configurations were seen, and two rotation
//! epochs — or two independently seeded meters — never collide on the same
//! key for the same configuration. How `new`'s seed is sourced matters
//! precisely because of that second property.
//!
//! Between rotations, `counts` and `marginals` grow without bound: nothing
//! here caps how many distinct configurations or attribute values get
//! tracked. Verified quotes bound the *shape* of what reaches
//! [`LinkabilityMeter::observe`], but not every field is platform-fixed —
//! `td_attributes` and `xfam` are set at TD creation — so a source able to
//! mint many distinct quotes before the next rotation can grow both maps
//! arbitrarily in the meantime. The rotation interval is the only bound
//! this module provides; choosing it is choosing a memory ceiling as well
//! as a correlation window.
//!
//! An example configuration, using real DCAP attribute keys rather than
//! invented ones (a TDX 1.0 platform's `fmspc` and `tee_tcb_svn` are two of
//! the seven `TcbConfig` attributes `verify::tcb_config_from_td10` produces):
//! observing the same `{fmspc, tee_tcb_svn, ...}` map twice grows one set by
//! one; observing a map that differs in `tee_tcb_svn` starts a second,
//! independent set.
//!
//! Fail-open binds this module too: [`LinkabilityMeter::observe`] and
//! [`LinkabilityMeter::rotate_if_due`] never panic on any input, and a
//! poisoned lock is recovered rather than propagated. Unlike the
//! collateral cache's lock, these critical sections are multi-step — see
//! `recover`'s doc comment for what that means for a torn write, and why
//! `rotate_if_due` clears its maps before it installs a new salt rather
//! than after.

use crate::bls::octets;
use crate::gateway::verify::TcbConfig;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Mutex, PoisonError, RwLock};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, serde::Serialize)]
pub struct Observation {
    /// How many sessions have landed on this configuration since the last
    /// salt rotation.
    pub set_size: u64,
    pub total_sessions: u64,
    pub distinct_configs: usize,
    /// Attributes taking more than one value. Note the wording: varying is not
    /// the same as partitioning — some of these may split nothing another
    /// attribute does not already split.
    pub varying_attributes: Vec<String>,
}

struct Store {
    salt: [u8; 32],
    rotated: Instant,
    counts: HashMap<[u8; 32], u64>,
    marginals: BTreeMap<String, HashMap<[u8; 32], u64>>,
    total: u64,
}

/// Counts what a relying party is accumulating, without accumulating it.
///
/// Holds salted frequency counts and per-attribute marginals. There is **no**
/// session-to-fingerprint map and **no** joint distribution across
/// attributes, so the store cannot answer "has this agent been here before"
/// — which is the one question an operator will ask for, and the answer is
/// no. See `two_sessions_on_one_configuration_are_indistinguishable_in_what_is_retained`.
pub struct LinkabilityMeter {
    rotation: Duration,
    store: RwLock<Store>,
    seed: Mutex<u64>,
}

/// Recover a lock guard even if a prior holder panicked while holding it.
///
/// Fail-open binds this module absolutely: no lock state may panic it. But
/// unlike the collateral cache's `recover` — whose critical sections really
/// are one `HashMap` operation each — this module's are not. `observe` is
/// entry-then-increment, a second counter increment, an N-iteration
/// marginals loop, then a length read and a marginals scan; `rotate_if_due`
/// is several sequential writes. Both have observable intermediate states,
/// so a panic partway through can leave a torn `Store` for whoever recovers
/// the poisoned lock next. That sentence is not the collateral cache's — it
/// would be false there and it is true here, which is exactly why it is
/// written out rather than assumed to transfer.
///
/// Recovery is still the right call. The retained state is a measurement,
/// not a security decision: a torn count under- or over-reports a set size
/// rather than granting or denying anything, and a fail-open gateway
/// forwards the request regardless of what this module measured. The one
/// place a tear could matter more than that is `rotate_if_due`, where a
/// half-finished rotation could otherwise leave pre-rotation `counts` or
/// `marginals` alive under a *post*-rotation salt — stale correlation
/// surviving the very operation whose job is aging it out. Its body clears
/// before it installs the new salt for exactly this reason, so any tear
/// there only ever leaves the store *more* cleared than intended, which is
/// the safe direction for a module whose failure mode must always be
/// "measures less", never "correlates more".
fn recover<T>(result: Result<T, PoisonError<T>>) -> T {
    result.unwrap_or_else(|poisoned| {
        log::warn!(
            "linkability meter lock was poisoned by a prior panic; recovering the guard rather than propagating"
        );
        poisoned.into_inner()
    })
}

impl LinkabilityMeter {
    pub fn new(rotation: Duration, seed: u64) -> Self {
        LinkabilityMeter {
            rotation,
            store: RwLock::new(Store {
                salt: derive_salt(seed, 0),
                rotated: Instant::now(),
                counts: HashMap::new(),
                marginals: BTreeMap::new(),
                total: 0,
            }),
            seed: Mutex::new(seed),
        }
    }

    pub fn observe(&self, config: &TcbConfig) -> Observation {
        let mut s = recover(self.store.write());

        // Length-prefixed via `bls::octets`, so `{"ab": "c"}` cannot collide
        // with `{"a": "bc"}`: every element of `parts` — key and value alike
        // — gets its own big-endian length prefix before its bytes, so the
        // byte string `octets` produces decodes back into exactly one
        // sequence of (length, bytes) elements. Grouping that sequence into
        // adjacent (key, value) pairs is then unambiguous too, because
        // `TcbConfig::attributes` is a `BTreeMap`: its keys are unique and
        // iterated in ascending order, so the only map that yields a given
        // sorted (key, value) sequence is that map itself. Plain
        // concatenation of `k` and `v` without this framing is exactly the
        // collision `octets`'s own doc comment and
        // `bls::octets_is_unambiguous_across_different_splits` exist to
        // rule out.
        let mut parts: Vec<Vec<u8>> = Vec::with_capacity(config.attributes.len() * 2);
        for (k, v) in &config.attributes {
            parts.push(k.as_bytes().to_vec());
            parts.push(v.as_bytes().to_vec());
        }
        let refs: Vec<&[u8]> = parts.iter().map(|p| p.as_slice()).collect();
        let key = salted(&s.salt, &octets(&refs));

        let n = s.counts.entry(key).or_insert(0);
        *n = n.saturating_add(1);
        let set_size = *n;
        s.total = s.total.saturating_add(1);

        for (k, v) in &config.attributes {
            let vk = salted(&s.salt, v.as_bytes());
            let count = s
                .marginals
                .entry(k.clone())
                .or_default()
                .entry(vk)
                .or_insert(0);
            *count = count.saturating_add(1);
        }

        Observation {
            set_size,
            total_sessions: s.total,
            distinct_configs: s.counts.len(),
            varying_attributes: s
                .marginals
                .iter()
                .filter(|(_, vals)| vals.len() > 1)
                .map(|(k, _)| k.clone())
                .collect(),
        }
    }

    pub fn rotate_if_due(&self) {
        let mut s = recover(self.store.write());
        if s.rotated.elapsed() < self.rotation {
            return;
        }
        // Clear before installing the new salt, not after. `epoch` is
        // captured first because clearing zeroes `total`, and `derive_salt`
        // still needs the *pre*-rotation session count to keep successive
        // epochs from a fixed seed apart. See `recover`'s doc comment for
        // why this ordering — not the reverse — is the direction that keeps
        // a torn write safe.
        let epoch = s.total;
        s.counts.clear();
        s.marginals.clear();
        s.total = 0;
        let mut seed = recover(self.seed.lock());
        *seed = seed.wrapping_add(1);
        s.salt = derive_salt(*seed, epoch);
        s.rotated = Instant::now();
    }

    /// A clone of the salted-fingerprint counts, and nothing else this
    /// module holds. `#[cfg(test)]` because production has no legitimate
    /// caller for it: anything that can read this map can watch how many
    /// sessions have landed on a given salted key, which is exactly the
    /// observable this module's public API is designed not to expose beyond
    /// aggregate counts. Tests use it to prove what is retained is a count
    /// and nothing more — see
    /// `two_sessions_on_one_configuration_are_indistinguishable_in_what_is_retained`.
    #[cfg(test)]
    pub(crate) fn snapshot_for_test(&self) -> HashMap<[u8; 32], u64> {
        recover(self.store.read()).counts.clone()
    }
}

fn derive_salt(seed: u64, epoch: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"occultation-gateway/meter-salt/v1");
    h.update(seed.to_be_bytes());
    h.update(epoch.to_be_bytes());
    h.finalize().into()
}

fn salted(salt: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(salt);
    h.update(data);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(pairs: &[(&str, &str)]) -> TcbConfig {
        TcbConfig {
            attributes: pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    fn meter() -> LinkabilityMeter {
        LinkabilityMeter::new(Duration::from_secs(3600), 7)
    }

    #[test]
    fn the_first_session_on_a_configuration_is_a_set_of_one() {
        let m = meter();
        let o = m.observe(&cfg(&[("tdx_module", "1.5.05")]));
        assert_eq!(o.set_size, 1);
        assert_eq!(o.total_sessions, 1);
        assert_eq!(o.distinct_configs, 1);
    }

    #[test]
    fn identical_configurations_grow_the_same_set() {
        let m = meter();
        let c = cfg(&[("tdx_module", "1.5.05"), ("pce_svn", "13")]);
        for expected in 1..=5 {
            assert_eq!(m.observe(&c).set_size, expected);
        }
        assert_eq!(m.observe(&c).distinct_configs, 1);
    }

    #[test]
    fn a_differing_attribute_starts_a_new_set() {
        let m = meter();
        m.observe(&cfg(&[("pce_svn", "13")]));
        let o = m.observe(&cfg(&[("pce_svn", "12")]));
        assert_eq!(
            o.set_size, 1,
            "a different configuration is a different set"
        );
        assert_eq!(o.distinct_configs, 2);
        assert_eq!(o.total_sessions, 2);
    }

    #[test]
    fn attribute_order_does_not_create_a_new_set() {
        // TcbConfig is a BTreeMap so this holds by construction; pinned
        // because a switch to an insertion-ordered map would silently
        // fragment every set and overstate the leak.
        let m = meter();
        m.observe(&cfg(&[("a", "1"), ("b", "2")]));
        assert_eq!(
            m.observe(&cfg(&[("b", "2"), ("a", "1")])).distinct_configs,
            1
        );
    }

    #[test]
    fn varying_attributes_are_named_and_constant_ones_are_not() {
        let m = meter();
        m.observe(&cfg(&[("tdx_module", "1.5.05"), ("pce_svn", "13")]));
        let o = m.observe(&cfg(&[("tdx_module", "1.5.05"), ("pce_svn", "12")]));
        assert_eq!(o.varying_attributes, vec!["pce_svn".to_string()]);
    }

    /// The refusal, asserted rather than documented.
    ///
    /// This is the analogue of the pool's no-reuse invariant: the guarantee is
    /// that the store *cannot* answer "has this agent been here before", and a
    /// guarantee nothing tests is a comment.
    #[test]
    fn two_sessions_on_one_configuration_are_indistinguishable_in_what_is_retained() {
        let m = meter();
        let c = cfg(&[("tdx_module", "1.5.05")]);
        m.observe(&c);
        let after_one = m.snapshot_for_test();
        m.observe(&c);
        let after_two = m.snapshot_for_test();

        // The only difference is a count. Nothing distinguishes the sessions.
        assert_eq!(
            after_one.len(),
            after_two.len(),
            "no per-session entry was added"
        );
        let (k1, v1) = after_one.iter().next().unwrap();
        assert_eq!(after_two.get(k1), Some(&(v1 + 1)));
    }

    #[test]
    fn the_stored_hash_does_not_reveal_the_configuration() {
        // Not a defense against someone holding the whole store: `salt` is
        // a field of the same `Store` as `counts`, and the config space is
        // small enough to enumerate offline in a few thousand hashes
        // regardless of salting. What this pins is narrower and still
        // real: two different seeds (two meters, or two rotation epochs of
        // one meter) must key the same configuration differently, so a
        // *partial* disclosure — `counts` without `salt`, one epoch's
        // snapshot without another's — cannot be joined across seeds.
        let a = LinkabilityMeter::new(Duration::from_secs(3600), 1);
        let b = LinkabilityMeter::new(Duration::from_secs(3600), 2);
        let c = cfg(&[("tdx_module", "1.5.05")]);
        a.observe(&c);
        b.observe(&c);
        let (ka, _) = a.snapshot_for_test().into_iter().next().unwrap();
        let (kb, _) = b.snapshot_for_test().into_iter().next().unwrap();
        assert_ne!(ka, kb, "different salts must give different keys");
    }

    #[test]
    fn rotating_the_salt_ages_out_correlation() {
        let m = LinkabilityMeter::new(Duration::from_nanos(1), 7);
        let c = cfg(&[("tdx_module", "1.5.05")]);
        m.observe(&c);
        let (key_before, _) = m.snapshot_for_test().into_iter().next().unwrap();
        std::thread::sleep(Duration::from_millis(2));
        m.rotate_if_due();
        // History is gone: the same configuration is a fresh set of one.
        assert_eq!(m.observe(&c).set_size, 1);
        // That alone does not prove the *salt* rotated — `counts.clear()`
        // on its own delivers the same `set_size == 1`, salt untouched.
        // This test is named for the salt, so it has to look at the salt:
        // the same configuration must now key to a genuinely different
        // hash than it did before rotation.
        let (key_after, _) = m.snapshot_for_test().into_iter().next().unwrap();
        assert_ne!(
            key_before, key_after,
            "the salt must actually change across a rotation, not just the counts"
        );
    }

    #[test]
    fn an_empty_configuration_is_an_observation_not_a_panic() {
        assert_eq!(meter().observe(&cfg(&[])).set_size, 1);
    }

    /// `rotate_if_due` must reset its own clock, not just clear the maps.
    /// Without resetting `rotated`, the *next* call still compares against
    /// the same stale timestamp and rotates again — and again, forever.
    /// If Tasks 6/7 call this once per request (the obvious wiring), every
    /// request after the first-ever rotation would wipe the store before
    /// its own observation lands, permanently reporting `set_size: 1,
    /// distinct_configs: 1` — the tool whose job is flagging low diversity
    /// silently claiming maximum anonymity forever. That is the dangerous
    /// direction, not a merely-annoying one.
    #[test]
    fn rotate_if_due_resets_the_clock_so_the_next_call_is_not_immediately_due() {
        let m = LinkabilityMeter::new(Duration::from_millis(50), 7);
        let c = cfg(&[("tdx_module", "1.5.05")]);
        m.observe(&c);
        std::thread::sleep(Duration::from_millis(60));
        m.rotate_if_due();
        assert_eq!(
            m.observe(&c).set_size,
            1,
            "the first, genuinely-due rotation must have cleared history"
        );
        // Called again immediately: the interval has not elapsed a second
        // time, so this must be a no-op. If `rotated` was never reset above,
        // this call sees the same stale timestamp and rotates again.
        m.rotate_if_due();
        assert_eq!(
            m.observe(&c).set_size,
            2,
            "a second rotate_if_due right after the first must not clear \
             again — otherwise every call clears, forever"
        );
    }

    /// `marginals` (and the epoch counter `total` that feeds `derive_salt`)
    /// must be cleared on rotation too, not just `counts`. If the old,
    /// pre-rotation marginal entry for a value survives, it sits alongside
    /// a *new* entry — salted under the new salt — for what is literally
    /// the same string, and the attribute is misreported as varying when
    /// nothing varied at all. `total` not resetting would similarly let a
    /// session count creep across epochs that are supposed to be
    /// independent.
    #[test]
    fn rotation_clears_marginals_so_a_repeated_value_does_not_look_like_variation() {
        let m = LinkabilityMeter::new(Duration::from_nanos(1), 7);
        let c = cfg(&[("tdx_module", "1.5.05")]);
        m.observe(&c);
        std::thread::sleep(Duration::from_millis(2));
        m.rotate_if_due();
        let o = m.observe(&c);
        assert_eq!(
            o.varying_attributes,
            Vec::<String>::new(),
            "a single value, repeated across a rotation, must not look like variation"
        );
        assert_eq!(
            o.total_sessions, 1,
            "a rotation starts a fresh epoch; sessions do not carry over"
        );
    }

    /// The module's whole thesis — "exactly two structures, and no third"
    /// — is otherwise only a comment. Exhaustive destructuring (no `..`)
    /// means a field added to `Store` fails to compile right here instead
    /// of silently becoming a fourth structure `snapshot_for_test` was
    /// never asked to check. This is the same idiom `verify.rs` calls
    /// structural rather than a matter of discipline.
    #[test]
    fn the_store_holds_exactly_these_fields_and_no_others() {
        let s = Store {
            salt: [0u8; 32],
            rotated: Instant::now(),
            counts: HashMap::new(),
            marginals: BTreeMap::new(),
            total: 0,
        };
        let Store {
            salt: _,
            rotated: _,
            counts: _,
            marginals: _,
            total: _,
        } = s;
    }

    /// The length-framing guard, made concrete rather than argued in a
    /// comment. Without `octets`'s length prefixes, the flat key/value byte
    /// stream for `{"ab": "c"}` (`b"ab" ++ b"c"` = `"abc"`) is identical to
    /// the one for `{"a": "bc"}` (`b"a" ++ b"bc"` = `"abc"`), so two
    /// unrelated platform configurations would land in the same set and the
    /// meter would understate the leak. This pins that `observe` does not
    /// have that property: two configurations whose naive concatenation
    /// collides must still land in different sets.
    #[test]
    fn key_value_framing_does_not_let_different_configs_collide() {
        let m = meter();
        let o1 = m.observe(&cfg(&[("ab", "c")]));
        let o2 = m.observe(&cfg(&[("a", "bc")]));
        assert_eq!(o1.set_size, 1, "first configuration is its own fresh set");
        assert_eq!(
            o2.set_size, 1,
            "a naively-concatenated collision must still be a fresh set"
        );
        assert_eq!(
            o2.distinct_configs, 2,
            "{{ab: c}} and {{a: bc}} must be counted as two configurations, not one"
        );

        // The attribute *name* has to enter the fingerprint too, not just
        // its value — dropping the key from the preimage would merge
        // `{"a": "x"}` and `{"b": "x"}`, which share every value but not
        // which attribute carries it, into a single set.
        let o3 = m.observe(&cfg(&[("a", "x")]));
        let o4 = m.observe(&cfg(&[("b", "x")]));
        assert_eq!(
            o3.set_size, 1,
            "a fresh key/value pair is its own fresh set"
        );
        assert_eq!(
            o4.set_size, 1,
            "the same value under a different key must still be a fresh set"
        );
        assert_eq!(
            o4.distinct_configs, 4,
            "four distinct key/value maps observed so far must count as four configurations"
        );
    }

    /// The salt's participation, made concrete. If `salted` ever stopped
    /// mixing in `salt` (or a rotation ever derived the same salt twice),
    /// the fingerprint for a configuration would be identical to its
    /// pre-image hash and identical across meters — which is exactly what
    /// `the_stored_hash_does_not_reveal_the_configuration` checks for two
    /// *different* seeds. This checks the other half: two *different*
    /// `LinkabilityMeter`s constructed with the *same* seed must still key
    /// the same configuration identically, because the salt is a pure
    /// function of `(seed, epoch)` and both start at epoch zero — proving
    /// the salt is derived rather than random, and so genuinely reproducible
    /// rather than merely "probably different".
    #[test]
    fn the_same_seed_derives_the_same_initial_salt() {
        let a = LinkabilityMeter::new(Duration::from_secs(3600), 42);
        let b = LinkabilityMeter::new(Duration::from_secs(3600), 42);
        let c = cfg(&[("tdx_module", "1.5.05")]);
        a.observe(&c);
        b.observe(&c);
        let (ka, _) = a.snapshot_for_test().into_iter().next().unwrap();
        let (kb, _) = b.snapshot_for_test().into_iter().next().unwrap();
        assert_eq!(
            ka, kb,
            "the same seed at the same epoch must derive the same salt"
        );
    }

    /// `rotate_if_due` must be a no-op before the rotation interval has
    /// elapsed — otherwise the "rotates on a configured interval" guarantee
    /// is decorative and an operator's chosen interval is not honoured.
    #[test]
    fn rotate_if_due_does_nothing_before_the_interval_elapses() {
        let m = LinkabilityMeter::new(Duration::from_secs(3600), 7);
        let c = cfg(&[("tdx_module", "1.5.05")]);
        m.observe(&c);
        m.rotate_if_due();
        // The interval has not elapsed, so the set must still be growing,
        // not restarting at one.
        assert_eq!(m.observe(&c).set_size, 2);
    }

    /// A minimal analogue of `verify.rs`'s formatter ban, scoped to this
    /// module's one real risk: a `Debug` (or pretty-`Debug`) rendering of
    /// anything holding `Store::salt` or a salted key reaching a log line
    /// would write out exactly the secret this module's unlinkability
    /// guarantee depends on. The non-test half of this module has exactly
    /// one formatting call today — `log::warn!` in `recover`, with no
    /// format argument at all — so this guard is free and cannot
    /// false-positive. Every Rust debug format spec ends in a question
    /// mark immediately before its closing brace, so a search for that
    /// two-character tail catches `{:?}`, `{v:?}`, `{:#?}` and `{:x?}`
    /// alike without needing to enumerate them. If a debug rendering is
    /// ever genuinely needed here, prove by test that it excludes `salt`
    /// and every stored key rather than relaxing this.
    #[test]
    fn nothing_in_the_non_test_module_reaches_a_debug_formatter() {
        let src = include_str!("meter.rs");
        const MARKER: &str = "#[cfg(test)]\nmod tests {";
        assert_eq!(
            src.matches(MARKER).count(),
            1,
            "ambiguous test module boundary"
        );
        let non_test = src.split(MARKER).next().expect("split yields a head");
        assert!(
            non_test.contains("fn rotate_if_due") && non_test.contains("fn observe"),
            "the scanned region does not reach the implementation, so this \
             guard would pass against a truncated string"
        );
        let tail_marker = "?}";
        assert!(
            !non_test.contains(tail_marker),
            "a Debug-style format spec appears in this module's non-test code"
        );
    }
}
