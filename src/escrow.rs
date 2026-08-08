use crate::modelled::{
    EscrowTag, ModelledError, ModelledPermit, Provenance, Tag, MODELLED_WARNING,
};
use blstrs::{G1Projective, Scalar};
use ff::Field;
use group::Group;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

const WHY: &str = "threshold ElGamal and DLEQ are not implemented; \
                   the tag carries the identity in the clear";

/// A stand-in for k-of-n threshold ElGamal escrow with DLEQ proofs of correct
/// opening. **Provides no security whatsoever.**
///
/// The tag **contains the identity in plaintext**. That is deliberate: a stub
/// that appeared to encrypt would invite someone to trust it. It performs the
/// group operations a real tag construction plus DLEQ proof would, so its cost
/// is representative, and nothing else about it is.
///
/// Constructing one requires a `ModelledPermit`.
pub struct ModelledThresholdElGamal {
    _permit: ModelledPermit,
    k: usize,
    n: usize,
}

impl ModelledThresholdElGamal {
    pub fn new(permit: ModelledPermit, k: usize, n: usize) -> Result<Self, ModelledError> {
        if k == 0 {
            return Err(ModelledError::BadThreshold {
                k,
                n,
                reason: "any single node could open",
            });
        }
        if k > n {
            return Err(ModelledError::BadThreshold {
                k,
                n,
                reason: "more shares than nodes",
            });
        }
        Ok(ModelledThresholdElGamal {
            _permit: permit,
            k,
            n,
        })
    }

    pub fn threshold(&self) -> (usize, usize) {
        (self.k, self.n)
    }
}

impl EscrowTag for ModelledThresholdElGamal {
    const MODELLED: bool = true;

    fn provenance(&self) -> Provenance {
        Provenance::Modelled {
            component: "threshold ElGamal escrow",
            reason: WHY,
        }
    }

    fn tag(&self, identity: &[u8]) -> Result<Tag, ModelledError> {
        log::warn!("{MODELLED_WARNING}");
        // Representative work: a real tag is two G1 elements plus a DLEQ proof,
        // which is four scalar multiplications and change.
        let mut rng = ChaCha20Rng::seed_from_u64(0xE5C0);
        let mut acc = G1Projective::identity();
        for _ in 0..4 {
            acc += G1Projective::generator() * Scalar::random(&mut rng);
        }
        let mut bytes = b"MODELLED-ESCROW-TAG:".to_vec();
        bytes.extend_from_slice(identity); // in the clear, on purpose
        bytes.extend_from_slice(&acc.to_compressed());
        Ok(Tag {
            bytes,
            provenance: self.provenance(),
        })
    }

    fn open(&self, tag: &Tag, shares: usize) -> Result<String, ModelledError> {
        log::warn!("{MODELLED_WARNING}");
        if shares < self.k {
            return Err(ModelledError::BadThreshold {
                k: self.k,
                n: self.n,
                reason: "fewer cooperating shares than the threshold",
            });
        }
        let _ = tag;
        // Not the identity. A caller that treats this as an accountable
        // opening gets a string that says it is not one.
        Ok(format!(
            "MODELLED opening ({}-of-{}): no identity was recovered, because nothing was escrowed",
            self.k, self.n
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modelled::{EscrowTag, ModelledPermit, Provenance};

    fn stub(
        k: usize,
        n: usize,
    ) -> Result<ModelledThresholdElGamal, crate::modelled::ModelledError> {
        ModelledThresholdElGamal::new(ModelledPermit::from_flag(true).unwrap(), k, n)
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn it_declares_itself_modelled() {
        assert!(ModelledThresholdElGamal::MODELLED);
        assert!(matches!(
            stub(3, 5).unwrap().provenance(),
            Provenance::Modelled { .. }
        ));
    }

    #[test]
    fn a_threshold_larger_than_the_committee_is_rejected() {
        assert!(stub(6, 5).is_err(), "6-of-5 can never open");
        assert!(stub(0, 5).is_err(), "0-of-5 opens unilaterally");
        assert!(stub(5, 5).is_ok());
    }

    /// The tag encrypts nothing. Asserting that the identity is *recoverable
    /// from the tag alone* is how the test pins "no confidentiality" rather
    /// than letting a reader assume the stub is doing ElGamal.
    #[test]
    fn the_tag_hides_nothing_and_the_test_says_so() {
        let s = stub(3, 5).unwrap();
        let tag = s.tag(b"did:web:agent-42").unwrap();
        assert!(
            tag.bytes.windows(16).any(|w| w == &b"did:web:agent-42"[..]),
            "the modelled tag carries the identity in the clear, on purpose"
        );
    }

    #[test]
    fn opening_below_the_threshold_still_returns_a_modelled_marker() {
        let s = stub(3, 5).unwrap();
        let tag = s.tag(b"did:web:agent-42").unwrap();
        // A real escrow would refuse. The stub refuses too — but its success
        // path is a marker, not an identity, so nothing downstream can treat
        // a modelled opening as an accountable one.
        assert!(s.open(&tag, 2).is_err(), "2 shares is below 3-of-5");
        let opened = s.open(&tag, 3).unwrap();
        assert!(opened.contains("MODELLED"), "got {opened}");
    }

    #[test]
    fn the_tag_is_labelled_modelled() {
        let tag = stub(3, 5).unwrap().tag(b"x").unwrap();
        assert!(matches!(tag.provenance, Provenance::Modelled { .. }));
    }
}
