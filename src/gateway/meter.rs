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
//! remembering to purge anything.
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
//! poisoned lock is recovered rather than propagated, the same choice
//! `collateral::recover` makes and for the same reason — both critical
//! sections here are simple map mutations with no observable intermediate
//! state, so there is no torn state to recover into.

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
/// Fail-open binds this module absolutely, the same as the collateral
/// cache's `recover`: no lock state may panic it. Every critical section
/// below is a single map mutation or a single clear-and-reset — there is no
/// multi-step update with an observable intermediate state, so there is no
/// torn state a recovered guard could expose. The worst a poisoned-then-
/// recovered store can do is under- or over-count by whatever the panicking
/// caller had already applied, which is a measurement gap, not a security
/// hole — this module's whole output is a measurement, and a fail-open
/// gateway forwards the request either way.
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
        let mut seed = recover(self.seed.lock());
        *seed = seed.wrapping_add(1);
        s.salt = derive_salt(*seed, s.total);
        s.counts.clear();
        s.marginals.clear();
        s.total = 0;
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
        // Salted, so an operator holding the store cannot enumerate plausible
        // TCB configurations offline and recover which ones were seen.
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
        std::thread::sleep(Duration::from_millis(2));
        m.rotate_if_due();
        // History is gone: the same configuration is a fresh set of one.
        assert_eq!(m.observe(&c).set_size, 1);
    }

    #[test]
    fn an_empty_configuration_is_an_observation_not_a_panic() {
        assert_eq!(meter().observe(&cfg(&[])).set_size, 1);
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
}
