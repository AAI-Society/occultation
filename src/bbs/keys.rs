use blstrs::{G2Projective, Scalar};
use ff::Field;
use group::{Curve, Group};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

/// An issuer's signing key.
#[derive(Clone, Debug)]
pub struct SecretKey(pub Scalar);

/// An issuer's public key, `W = P2 * x`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey(pub G2Projective);

impl PublicKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_affine().to_compressed().to_vec()
    }
}

#[derive(Clone, Debug)]
pub struct KeyPair {
    pub sk: SecretKey,
    pub pk: PublicKey,
}

impl KeyPair {
    /// Deterministic from a seed, so every measurement is rerunnable.
    ///
    /// A zero secret key would make the public key the identity and every
    /// signature unforgeable-by-anyone rather than by-nobody, so resample.
    /// The loop runs once with overwhelming probability.
    pub fn generate(seed: u64) -> Self {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let x = loop {
            let candidate = Scalar::random(&mut rng);
            if candidate != Scalar::ZERO {
                break candidate;
            }
        };
        KeyPair {
            sk: SecretKey(x),
            pk: PublicKey(G2Projective::generator() * x),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_seed_reproduces_a_keypair() {
        assert_eq!(KeyPair::generate(7).pk.0, KeyPair::generate(7).pk.0);
        assert_ne!(KeyPair::generate(7).pk.0, KeyPair::generate(8).pk.0);
    }

    #[test]
    fn the_public_key_is_the_secret_key_times_the_generator() {
        let kp = KeyPair::generate(7);
        assert_eq!(kp.pk.0, G2Projective::generator() * kp.sk.0);
    }

    #[test]
    fn the_secret_key_is_never_zero() {
        for seed in 0..32u64 {
            assert_ne!(KeyPair::generate(seed).sk.0, Scalar::ZERO);
        }
    }

    #[test]
    fn a_public_key_serializes_to_ninety_six_bytes() {
        assert_eq!(KeyPair::generate(7).pk.to_bytes().len(), 96);
    }
}
