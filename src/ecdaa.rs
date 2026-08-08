use crate::modelled::{
    AnonymousAttestation, Attestation, AttestationVerdict, ModelledError, ModelledPermit,
    Provenance, MODELLED_WARNING,
};
use blstrs::{G1Projective, Scalar};
use ff::Field;
use group::Group;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sha2::{Digest, Sha256};

const WHY: &str = "ECDAA is not implemented; this is a cost stand-in";

/// A stand-in for ECDAA. **Provides no security whatsoever.**
///
/// It performs three G1 scalar multiplications and a hash, which is the shape
/// and roughly the cost of an ECDAA join-and-sign, so the composed cost
/// estimate is not a guess. It does not prove group membership, does not hide
/// a platform identifier, and its `verify` accepts nothing — it cannot return
/// `Valid`.
///
/// Constructing one requires a `ModelledPermit`. Once the CLI is wired
/// (Task 7), `--allow-modelled` is the only thing that produces one.
pub struct ModelledEcdaa {
    _permit: ModelledPermit,
}

impl ModelledEcdaa {
    pub fn new(permit: ModelledPermit) -> Self {
        ModelledEcdaa { _permit: permit }
    }
}

impl AnonymousAttestation for ModelledEcdaa {
    const MODELLED: bool = true;

    fn provenance(&self) -> Provenance {
        Provenance::Modelled {
            component: "ECDAA",
            reason: WHY,
        }
    }

    fn attest(&self, measurement: &[u8]) -> Result<Attestation, ModelledError> {
        log::warn!("{MODELLED_WARNING}");
        // Representative work: the group operations an ECDAA signature would
        // perform. The output is not a proof of anything.
        let mut rng = ChaCha20Rng::seed_from_u64(u64::from_le_bytes(
            Sha256::digest(measurement)[..8]
                .try_into()
                .expect("8 bytes"),
        ));
        let mut acc = G1Projective::identity();
        for _ in 0..3 {
            acc += G1Projective::generator() * Scalar::random(&mut rng);
        }
        let mut bytes = acc.to_compressed().to_vec();
        bytes.extend_from_slice(&Sha256::digest(measurement));
        Ok(Attestation::new(bytes, self.provenance()))
    }

    fn verify(&self, _measurement: &[u8], _attestation: &Attestation) -> AttestationVerdict {
        log::warn!("{MODELLED_WARNING}");
        // There is no check to perform. Returning `Valid` here — for any
        // input, including well-formed output of `attest` — would make a stub
        // indistinguishable from a working ECDAA verifier at the call site.
        AttestationVerdict::ModelledNoSecurity
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modelled::{AnonymousAttestation, AttestationVerdict, ModelledPermit, Provenance};

    fn stub() -> ModelledEcdaa {
        ModelledEcdaa::new(ModelledPermit::from_flag(true).unwrap())
    }

    /// `const _: () = assert!(..)` rather than a runtime `assert!`: a bare
    /// `assert!` on a constant is both a clippy lint and a weaker check.
    /// This form fails to *compile* if `MODELLED` is ever flipped to false,
    /// which is the guarantee worth having for a security barrier.
    #[test]
    fn it_declares_itself_modelled() {
        const _: () = assert!(ModelledEcdaa::MODELLED);
        assert!(matches!(stub().provenance(), Provenance::Modelled { .. }));
    }

    /// The load-bearing test. A modelled attestation must never produce the
    /// verdict a real one produces, whatever it is handed — including its own
    /// honestly-produced output.
    #[test]
    fn it_can_never_return_valid() {
        let s = stub();
        let a = s.attest(b"measurement").unwrap();
        assert_eq!(
            s.verify(b"measurement", &a),
            AttestationVerdict::ModelledNoSecurity
        );
        assert_eq!(
            s.verify(b"different", &a),
            AttestationVerdict::ModelledNoSecurity
        );
        let mut tampered = a.clone();
        tampered.bytes[0] ^= 0xff;
        assert_eq!(
            s.verify(b"measurement", &tampered),
            AttestationVerdict::ModelledNoSecurity
        );
    }

    #[test]
    fn the_attestation_it_produces_is_labelled_modelled() {
        let a = stub().attest(b"m").unwrap();
        assert!(matches!(a.provenance(), Provenance::Modelled { .. }));
    }

    /// The cost profile has to be representative or the composed bench is
    /// fiction. The stub does group work of the same order ECDAA would, so
    /// its cost is a stand-in rather than a guess — but it is still a
    /// stand-in, which is why it is gated.
    #[test]
    fn it_costs_something_of_the_right_order() {
        let s = stub();
        let t = std::time::Instant::now();
        s.attest(b"m").unwrap();
        let d = t.elapsed();
        assert!(
            d >= std::time::Duration::from_micros(20),
            "too cheap to be representative: {d:?}"
        );
        assert!(
            d < std::time::Duration::from_millis(50),
            "implausibly slow: {d:?}"
        );
    }
}
