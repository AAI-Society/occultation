use blstrs::{Bls12, G1Projective, G2Prepared, G2Projective, Scalar};
use ff::Field;
use group::{Curve, Group};
use sha2::{Digest, Sha256};

/// Ciphersuite identifier. Structurally in the shape the BBS draft uses, but
/// this implementation is **not** validated against the draft's test vectors
/// and will not interoperate. See the README.
pub const API_ID: &[u8] = b"OCCULTATION_BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_";

#[derive(Debug, thiserror::Error)]
pub enum BlsError {
    #[error("domain separation tag is {0} bytes; RFC 9380 allows at most 255")]
    DstTooLong(usize),
    #[error("cannot expand to {0} bytes; RFC 9380 allows at most 65535")]
    ExpandTooLong(usize),
    #[error("expected {expected} messages, got {got}")]
    MessageCount { expected: usize, got: usize },
}

/// RFC 9380 §5.3.1 `expand_message_xmd` with SHA-256.
///
/// Present because `blstrs` exposes hash-to-curve but not the expander, and
/// BBS+ needs the expander to derive scalars.
pub fn expand_message_xmd(
    msg: &[u8],
    dst: &[u8],
    len_in_bytes: usize,
) -> Result<Vec<u8>, BlsError> {
    const B_IN_BYTES: usize = 32; // SHA-256 output
    const S_IN_BYTES: usize = 64; // SHA-256 block

    if dst.len() > 255 {
        return Err(BlsError::DstTooLong(dst.len()));
    }
    if len_in_bytes > 65_535 {
        return Err(BlsError::ExpandTooLong(len_in_bytes));
    }
    let ell = len_in_bytes.div_ceil(B_IN_BYTES);
    if ell > 255 {
        return Err(BlsError::ExpandTooLong(len_in_bytes));
    }

    let mut dst_prime = dst.to_vec();
    dst_prime.push(dst.len() as u8);

    let mut h = Sha256::new();
    h.update([0u8; S_IN_BYTES]); // Z_pad
    h.update(msg);
    h.update((len_in_bytes as u16).to_be_bytes()); // l_i_b_str
    h.update([0u8]);
    h.update(&dst_prime);
    let b_0 = h.finalize();

    let mut h = Sha256::new();
    h.update(b_0);
    h.update([1u8]);
    h.update(&dst_prime);
    let mut b_i = h.finalize();

    let mut out = Vec::with_capacity(ell * B_IN_BYTES);
    out.extend_from_slice(&b_i);
    for i in 2..=ell {
        let mut strxor = [0u8; B_IN_BYTES];
        for (k, s) in strxor.iter_mut().enumerate() {
            *s = b_0[k] ^ b_i[k];
        }
        let mut h = Sha256::new();
        h.update(strxor);
        h.update([i as u8]);
        h.update(&dst_prime);
        b_i = h.finalize();
        out.extend_from_slice(&b_i);
    }
    out.truncate(len_in_bytes);
    Ok(out)
}

/// Reduce a big-endian byte string mod r by Horner's rule.
///
/// `blstrs` exposes no wide reduction — `Scalar::from_bytes_be` rejects
/// anything non-canonical — and this crate forbids `unsafe`, so raw `blst`
/// FFI is out. Forty-eight field multiply-adds cost tens of nanoseconds and
/// are exactly correct.
pub fn reduce_be_bytes(bytes: &[u8]) -> Scalar {
    let radix = Scalar::from(256u64);
    let mut acc = Scalar::ZERO;
    for b in bytes {
        acc = acc * radix + Scalar::from(*b as u64);
    }
    acc
}

/// Hash a message to a scalar. 48 bytes of expansion gives a reduction bias
/// below 2^-128, which is the margin the BBS draft asks for.
pub fn hash_to_scalar(msg: &[u8], dst: &[u8]) -> Result<Scalar, BlsError> {
    Ok(reduce_be_bytes(&expand_message_xmd(msg, dst, 48)?))
}

/// Length-prefixed concatenation.
///
/// Plain concatenation would let two different inputs produce the same bytes,
/// and a Fiat-Shamir challenge over an ambiguous encoding is not binding.
pub fn octets(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in parts {
        out.extend_from_slice(&(p.len() as u64).to_be_bytes());
        out.extend_from_slice(p);
    }
    out
}

/// The public generators a credential is signed under.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Generators {
    /// The base point.
    pub p1: G1Projective,
    /// The domain generator.
    pub q1: G1Projective,
    /// One per message.
    pub h: Vec<G1Projective>,
}

impl Generators {
    /// Deterministic, and stable under a change of `count`: `h[0]` is the same
    /// point whether you asked for three generators or five. Otherwise adding
    /// an attribute to a credential would invalidate every signature that
    /// existed before it.
    pub fn create(count: usize) -> Self {
        let dst = [API_ID, b"SIG_GENERATOR_DST_"].concat();
        let at = |label: &[u8]| G1Projective::hash_to_curve(label, &dst, &[]);
        Generators {
            p1: at(b"BP"),
            q1: at(b"Q1"),
            h: (0..count)
                .map(|i| at(&octets(&[b"H", &(i as u64).to_be_bytes()])))
                .collect(),
        }
    }

    /// `B = P1 + Q1*domain + sum(H_i * m_i)`, the commitment a signature is
    /// taken over. One multi-exponentiation rather than a loop of scalar
    /// multiplications, because this is on the measured path.
    pub fn b(&self, domain: Scalar, msgs: &[Scalar]) -> Result<G1Projective, BlsError> {
        if msgs.len() != self.h.len() {
            return Err(BlsError::MessageCount {
                expected: self.h.len(),
                got: msgs.len(),
            });
        }
        let mut points = Vec::with_capacity(msgs.len() + 2);
        let mut scalars = Vec::with_capacity(msgs.len() + 2);
        points.push(self.p1);
        scalars.push(Scalar::ONE);
        points.push(self.q1);
        scalars.push(domain);
        points.extend(self.h.iter().copied());
        scalars.extend(msgs.iter().copied());
        Ok(G1Projective::multi_exp(&points, &scalars))
    }

    pub fn len(&self) -> usize {
        self.h.len()
    }

    pub fn is_empty(&self) -> bool {
        self.h.is_empty()
    }
}

/// `-P2`, the negated G2 generator, used on the right of every pairing check.
pub fn neg_p2() -> G2Projective {
    -G2Projective::generator()
}

/// A relying party's cached pairing pre-computation for one registered issuer.
///
/// This is the optimization the desk study calls "cached pairing
/// pre-computations": both G2 inputs to proof verification are fixed per
/// issuer, so the Miller loop's line-function coefficients can be computed
/// once. Note that it applies to **proof verification** and not to signature
/// verification, whose second G2 input is `W + P2*e` and therefore depends on
/// the signature.
pub struct PreparedIssuer {
    pub w: G2Prepared,
    pub neg_p2: G2Prepared,
}

impl PreparedIssuer {
    pub fn new(pk: &G2Projective) -> Self {
        PreparedIssuer {
            w: G2Prepared::from(pk.to_affine()),
            neg_p2: G2Prepared::from(neg_p2().to_affine()),
        }
    }
}

/// Re-exported so callers do not have to depend on `pairing` directly.
pub type Engine = Bls12;

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 9380 Appendix K.1 — expand_message_xmd(SHA-256), 128-bit security.
    /// Verify these against the RFC before trusting them; the RFC is
    /// authoritative and this plan is not.
    const RFC9380_DST: &[u8] = b"QUUX-V01-CS02-with-expander-SHA256-128";

    #[test]
    fn expand_message_xmd_matches_rfc9380_appendix_k1() {
        let cases: [(&[u8], usize, &str); 6] = [
            (
                b"",
                0x20,
                "68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235",
            ),
            (
                b"abc",
                0x20,
                "d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615",
            ),
            (
                b"abcdef0123456789",
                0x20,
                "eff31487c770a893cfb36f912fbfcbff40d5661771ca4b2cb4eafe524333f5c1",
            ),
            (
                b"",
                0x80,
                "af84c27ccfd45d41914fdff5df25293e221afc53d8ad2ac06d5e3e29485dadbee0d1215877\
              13a3e0dd4d5e69e93eb7cd4f5df4cd103e188cf60cb02edc3edf18eda8576c412b18ffb658\
              e3dd6ec849469b979d444cf7b26911a08e63cf31f9dcc541708d3491184472c2c29bb749d4\
              286b004ceb5ee6b9a7fa5b646c993f0ced",
            ),
            (
                b"abc",
                0x80,
                "abba86a6129e366fc877aab32fc4ffc70120d8996c88aee2fe4b32d6c7b6437a647e6c3163\
              d40b76a73cf6a5674ef1d890f95b664ee0afa5359a5c4e07985635bbecbac65d747d3d2da7\
              ec2b8221b17b0ca9dc8a1ac1c07ea6a1e60583e2cb00058e77b7b72a298425cd1b941ad4ec\
              65e8afc50303a22c0f99b0509b4c895f40",
            ),
            (
                b"abcdef0123456789",
                0x80,
                "ef904a29bffc4cf9ee82832451c946ac3c8f8058ae97d8d629831a74c6572bd9ebd0df635c\
              d1f208e2038e760c4994984ce73f0d55ea9f22af83ba4734569d4bc95e18350f740c07eef6\
              53cbb9f87910d833751825f0ebefa1abe5420bb52be14cf489b37fe1a72f7de2d10be453b2\
              c9d9eb20c7e3f6edc5a60629178d9478df",
            ),
        ];
        for (msg, len, want) in cases {
            // The literals above are line-wrapped with `\` continuations, so
            // strip whitespace before comparing.
            let want: String = want.chars().filter(|c| !c.is_whitespace()).collect();
            let got = hex::encode(expand_message_xmd(msg, RFC9380_DST, len).unwrap());
            assert_eq!(
                got,
                want,
                "msg={:?} len={len}",
                String::from_utf8_lossy(msg)
            );
        }
    }

    #[test]
    fn expand_message_xmd_rejects_impossible_lengths() {
        assert!(
            expand_message_xmd(b"m", &[0u8; 256], 32).is_err(),
            "DST over 255 bytes"
        );
        assert!(
            expand_message_xmd(b"m", RFC9380_DST, 65_536).is_err(),
            "output over 65535"
        );
        assert!(
            expand_message_xmd(b"m", RFC9380_DST, 0).is_ok(),
            "zero length is legal"
        );
    }

    #[test]
    fn hash_to_scalar_is_deterministic_and_nonzero() {
        let a = hash_to_scalar(b"message", b"DST").unwrap();
        let b = hash_to_scalar(b"message", b"DST").unwrap();
        let c = hash_to_scalar(b"message", b"OTHER-DST").unwrap();
        let d = hash_to_scalar(b"other", b"DST").unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c, "the DST must separate domains");
        assert_ne!(a, d);
        assert_ne!(a, Scalar::ZERO);
    }

    #[test]
    fn reducing_a_small_canonical_value_agrees_with_from_bytes_be() {
        // 32 zero bytes ending in 5 is 5, well below r, so the Horner
        // reduction and blstrs' canonical decoder must agree exactly.
        let mut be = [0u8; 32];
        be[31] = 5;
        assert_eq!(reduce_be_bytes(&be), Scalar::from_bytes_be(&be).unwrap());
        assert_eq!(reduce_be_bytes(&be), Scalar::from(5u64));
    }

    #[test]
    fn reducing_an_oversized_value_wraps_rather_than_failing() {
        // 48 bytes of 0xff is far above r. Canonical decoding cannot express
        // it; Horner reduction must, because that is the whole point.
        let big = [0xffu8; 48];
        let s = reduce_be_bytes(&big);
        assert_ne!(s, Scalar::ZERO);
        // Reducing a value and reducing it with leading zeros prepended must
        // give the same field element.
        let mut padded = vec![0u8; 16];
        padded.extend_from_slice(&big);
        assert_eq!(reduce_be_bytes(&padded), s);
    }

    #[test]
    fn octets_is_unambiguous_across_different_splits() {
        // Without length prefixes, ("ab","c") and ("a","bc") would collide,
        // and a challenge hash over a colliding encoding is not binding.
        assert_ne!(octets(&[b"ab", b"c"]), octets(&[b"a", b"bc"]));
        assert_eq!(octets(&[b"ab", b"c"]), octets(&[b"ab", b"c"]));
    }

    #[test]
    fn generators_are_distinct_deterministic_and_not_the_identity() {
        let g = Generators::create(5);
        assert_eq!(g.h.len(), 5);
        let again = Generators::create(5);
        assert_eq!(g.p1, again.p1, "generators must be reproducible");
        assert_eq!(g.h, again.h);

        let mut all = vec![g.p1, g.q1];
        all.extend(g.h.iter().copied());
        for (i, x) in all.iter().enumerate() {
            assert!(
                bool::from(!x.is_identity()),
                "generator {i} is the identity"
            );
            for (j, y) in all.iter().enumerate().skip(i + 1) {
                assert_ne!(x, y, "generators {i} and {j} collide");
            }
        }
    }

    #[test]
    fn generators_of_different_counts_share_a_prefix() {
        // H_0 must not change when the credential gains an attribute, or a
        // signature over 3 messages could not be verified by code built for 5.
        let three = Generators::create(3);
        let five = Generators::create(5);
        assert_eq!(three.p1, five.p1);
        assert_eq!(three.q1, five.q1);
        assert_eq!(three.h[..], five.h[..3]);
    }

    #[test]
    fn b_rejects_the_wrong_number_of_messages() {
        let g = Generators::create(3);
        let d = Scalar::from(7u64);
        assert!(g.b(d, &[Scalar::from(1u64); 3]).is_ok());
        assert!(
            g.b(d, &[Scalar::from(1u64); 2]).is_err(),
            "too few messages"
        );
        assert!(
            g.b(d, &[Scalar::from(1u64); 4]).is_err(),
            "too many messages"
        );
    }

    #[test]
    fn a_prepared_issuer_gives_the_same_pairing_as_an_unprepared_one() {
        // The cached-pairing optimization must not change the answer. If it
        // did, `bench --composed` would be comparing two different functions.
        use pairing::{MillerLoopResult, MultiMillerLoop};
        let x = Scalar::from(42u64);
        let w = G2Projective::generator() * x;
        let a = G1Projective::generator() * Scalar::from(9u64);
        let prepared = PreparedIssuer::new(&w);

        let cached = Bls12::multi_miller_loop(&[
            (&a.to_affine(), &prepared.w),
            (&a.to_affine(), &prepared.neg_p2),
        ])
        .final_exponentiation();

        let fresh = Bls12::multi_miller_loop(&[
            (&a.to_affine(), &G2Prepared::from(w.to_affine())),
            (&a.to_affine(), &G2Prepared::from(neg_p2().to_affine())),
        ])
        .final_exponentiation();

        assert_eq!(cached, fresh);
    }
}
