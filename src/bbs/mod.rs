//! BBS+ over BLS12-381.
//!
//! **Real cryptography, not interoperable.** The algebra is genuine: forged
//! signatures fail, tampered proofs fail, and undisclosed attributes stay
//! undisclosed, each asserted by test. The encoding of generators, domain and
//! challenge is our own domain-separated construction and has **not** been
//! validated against the test vectors in `draft-irtf-cfrg-bbs-signatures`, so
//! output will not interoperate with another BBS+ implementation.
//!
//! The cost profile is what this module exists to produce. Interoperability is
//! not claimed anywhere and must not be inferred.

pub mod keys;
pub mod sign;
// `pub mod proof;` is added in Task 6, when the file exists. Adding it now
// breaks the build at the end of this task.

pub use keys::{KeyPair, PublicKey, SecretKey};
pub use sign::{calculate_domain, message_to_scalar, sign, verify, Signature};

#[derive(Debug, thiserror::Error)]
pub enum BbsError {
    #[error(transparent)]
    Bls(#[from] crate::bls::BlsError),
    #[error("the signing key and signature scalar sum to zero; regenerate the key")]
    DegenerateKey,
    #[error("disclosed index {index} is out of range for a {len}-attribute credential")]
    IndexOutOfRange { index: usize, len: usize },
    #[error("disclosed indexes must be sorted and distinct; {0} repeats or goes backwards")]
    UnsortedIndexes(usize),
    #[error("expected {expected} undisclosed responses, got {got}")]
    ResponseCount { expected: usize, got: usize },
    #[error("a blinding scalar was zero and cannot be inverted")]
    ZeroBlinding,
}
