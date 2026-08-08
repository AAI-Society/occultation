use crate::harness::{try_measure, HarnessError, Sample};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde::Serialize;
use std::time::Duration;

/// The message every baseline measurement signs. Ed25519 hashes internally,
/// so the length barely matters; it is fixed so runs are comparable.
pub const BASELINE_MESSAGE: &[u8] = b"occultation baseline: one agent action";

/// A deterministic keypair. Seeded so a benchmark can be rerun to the same
/// numbers, which `thread_rng` would make impossible.
pub fn baseline_keypair(seed: u64) -> (SigningKey, VerifyingKey) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let sk = SigningKey::generate(&mut rng);
    let vk = sk.verifying_key();
    (sk, vk)
}

/// What the standard assumes today: Ed25519 sign and verify.
#[derive(Clone, Debug, Serialize)]
pub struct Baseline {
    pub sign: Sample,
    pub verify: Sample,
}

impl Baseline {
    /// Sign plus verify — the like-for-like comparison against a composed
    /// present-and-verify path. Comparing a BBS+ round trip against Ed25519
    /// verification alone would flatter the anonymous scheme by a factor of
    /// two.
    pub fn round_trip(&self) -> Duration {
        self.sign.median + self.verify.median
    }
}

/// `iters` reaches here from `--iters` on the command line, so this returns a
/// `Result` rather than using the panicking `measure`. The plan's global
/// constraint is no panics on malformed input, and zero is malformed input.
pub fn measure_baseline(seed: u64, iters: u32) -> Result<Baseline, HarnessError> {
    let (sk, vk) = baseline_keypair(seed);
    let sig = sk.sign(BASELINE_MESSAGE);
    Ok(Baseline {
        sign: try_measure("Ed25519 sign", iters, || sk.sign(BASELINE_MESSAGE))?,
        verify: try_measure("Ed25519 verify", iters, || {
            vk.verify_strict(BASELINE_MESSAGE, &sig)
                .expect("baseline signature verifies")
        })?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_baseline_signs_and_verifies_for_real() {
        let b = measure_baseline(7, 100).unwrap();
        assert_eq!(b.sign.iters, 100);
        assert!(b.round_trip() > Duration::ZERO);
    }

    #[test]
    fn zero_iterations_is_an_error_rather_than_a_panic() {
        // `--iters 0` reaches this function from the command line in Task 7.
        assert!(measure_baseline(7, 0).is_err());
    }

    #[test]
    fn the_baseline_rejects_a_tampered_message() {
        // If this passed, the "baseline" would be timing a no-op and every
        // ratio in the tool would be nonsense.
        let (sk, vk) = baseline_keypair(7);
        let sig = sk.sign(b"agent action");
        assert!(vk.verify_strict(b"agent action", &sig).is_ok());
        assert!(vk.verify_strict(b"agent actiom", &sig).is_err());
    }

    #[test]
    fn the_same_seed_gives_the_same_key() {
        let (a, _) = baseline_keypair(7);
        let (b, _) = baseline_keypair(7);
        assert_eq!(
            a.to_bytes(),
            b.to_bytes(),
            "measurements must be rerunnable"
        );
        let (c, _) = baseline_keypair(8);
        assert_ne!(a.to_bytes(), c.to_bytes());
    }

    #[test]
    fn verification_costs_more_than_signing() {
        // True of Ed25519 everywhere. If it inverts, the harness is measuring
        // the wrong closure.
        let b = measure_baseline(7, 500).unwrap();
        assert!(
            b.verify.median > b.sign.median,
            "sign {:?} verify {:?}",
            b.sign.median,
            b.verify.median
        );
    }
}
