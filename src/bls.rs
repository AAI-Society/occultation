use blstrs::{G1Projective, G2Prepared, G2Projective, Scalar};
use ff::Field;
use group::{Curve, Group};
use sha2::{Digest, Sha256};

/// The largest number of 32-byte blocks `expand_message_xmd` can emit: the
/// block counter is one byte. 255 * 32 = 8160 bytes.
pub const MAX_ELL: usize = 255;

/// Ciphersuite identifier. Structurally in the shape the BBS draft uses, but
/// this implementation is **not** validated against the draft's test vectors
/// and will not interoperate. See the README.
pub const API_ID: &[u8] = b"OCCULTATION_BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_";

#[derive(Debug, thiserror::Error)]
pub enum BlsError {
    /// RFC 9380 section 3.1: "Tags MUST have nonzero length." An empty tag
    /// gives `DST_prime = [0x00]` and destroys domain separation, and
    /// `hash_to_scalar` takes a caller-supplied tag, so this is reachable.
    #[error("domain separation tag is empty; RFC 9380 requires a nonzero length")]
    DstEmpty,
    #[error("domain separation tag is {0} bytes; RFC 9380 allows at most 255")]
    DstTooLong(usize),
    /// The true cap for SHA-256 is `255 * 32 = 8160`, not 65535: the `ell`
    /// counter is a single byte. Reporting 65535 while rejecting 9000 would
    /// be a lie.
    #[error("cannot expand to {0} bytes; the limit for SHA-256 is 8160 ({MAX_ELL} blocks of 32)")]
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

    if dst.is_empty() {
        return Err(BlsError::DstEmpty);
    }
    if dst.len() > 255 {
        return Err(BlsError::DstTooLong(dst.len()));
    }
    let ell = len_in_bytes.div_ceil(B_IN_BYTES);
    // `ell` is emitted as a single byte in the block counter, so this bound
    // is load-bearing rather than defensive: without it the `i as u8` cast
    // below wraps silently at i = 256 and the output is quietly wrong.
    if ell > MAX_ELL {
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
/// Note on what this costs: `neg_p2`'s table is a global constant, so it is
/// duplicated once per issuer. The **marginal** per-issuer memory is the `w`
/// table alone, and any memory figure this tool reports must say which of the
/// two it is quoting.
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

#[cfg(test)]
mod tests {
    use super::*;
    use blstrs::{Bls12, Gt};

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

    /// Every published K.1 vector has a length that is a multiple of 32, so
    /// the final `truncate` is an identity operation in all of them: an
    /// implementation returning the *last* `len_in_bytes` bytes instead of
    /// the first would pass all six and silently corrupt every
    /// `hash_to_scalar`, which is the only caller and asks for 48.
    ///
    /// These two vectors were produced by a second implementation written in
    /// Python directly from RFC 9380 section 5.3.1, which was first validated
    /// against all six published K.1 vectors. They are not self-generated
    /// from this code.
    #[test]
    fn expand_message_xmd_truncates_correctly_at_the_length_we_actually_use() {
        assert_eq!(
            hex::encode(expand_message_xmd(b"", RFC9380_DST, 48).unwrap()),
            "3808e9bb0ade2df3aa6f1b459eb5058a78142f439213ddac0c97dcab92ae5a84\
             08d86b32bbcc87de686182cbdf65901f"
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect::<String>()
        );
        assert_eq!(
            hex::encode(expand_message_xmd(b"abc", RFC9380_DST, 48).unwrap()),
            "2b877f5f0dfd881405426c6b87b39205ef53a548b0e4d567fc007cb37c6fa1f3\
             b19f42871efefca518ac950c27ac4e28"
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect::<String>()
        );
    }

    #[test]
    fn the_output_length_is_bound_into_the_derivation() {
        // `l_i_b_str` is part of b_0's preimage, so asking for 48 bytes and
        // asking for 64 must not share a prefix. If they did, the expander
        // would be truncating one stream rather than deriving per length.
        let a = expand_message_xmd(b"abc", RFC9380_DST, 48).unwrap();
        let b = expand_message_xmd(b"abc", RFC9380_DST, 64).unwrap();
        assert_ne!(a[..32], b[..32]);
    }

    #[test]
    fn expand_message_xmd_rejects_impossible_lengths() {
        assert!(
            matches!(expand_message_xmd(b"m", b"", 32), Err(BlsError::DstEmpty)),
            "RFC 9380 section 3.1: tags MUST have nonzero length"
        );
        assert!(
            matches!(
                expand_message_xmd(b"m", &[0u8; 256], 32),
                Err(BlsError::DstTooLong(256))
            ),
            "DST over 255 bytes, and the variant must say which limit was hit"
        );
        assert!(
            matches!(
                expand_message_xmd(b"m", RFC9380_DST, 8_161),
                Err(BlsError::ExpandTooLong(_))
            ),
            "8161 bytes needs 256 blocks and the counter is one byte"
        );
        assert!(
            expand_message_xmd(b"m", RFC9380_DST, 0).is_ok(),
            "zero length is legal"
        );
    }

    #[test]
    fn the_block_counter_boundary_is_exactly_where_it_should_be() {
        // 8160 = 255 * 32 is the last length that fits a one-byte counter.
        // Without the guard, 8161 wraps `i as u8` to 0 and returns a wrong
        // answer rather than an error.
        assert_eq!(
            expand_message_xmd(b"m", RFC9380_DST, 8_160).unwrap().len(),
            8_160
        );
        assert!(expand_message_xmd(b"m", RFC9380_DST, 8_161).is_err());
    }

    #[test]
    fn a_dst_of_exactly_255_bytes_is_accepted() {
        assert!(expand_message_xmd(b"m", &[0x41u8; 255], 32).is_ok());
        assert!(expand_message_xmd(b"m", &[0x41u8; 256], 32).is_err());
    }

    #[test]
    fn hash_to_scalar_expands_to_48_bytes_not_32() {
        // The doc comment claims a reduction bias below 2^-128, which is only
        // true at 48 bytes. Narrowing it to 32 would keep every other test
        // passing while quietly voiding the claim.
        let direct = reduce_be_bytes(&expand_message_xmd(b"m", b"DST", 48).unwrap());
        assert_eq!(hash_to_scalar(b"m", b"DST").unwrap(), direct);
        let narrow = reduce_be_bytes(&expand_message_xmd(b"m", b"DST", 32).unwrap());
        assert_ne!(hash_to_scalar(b"m", b"DST").unwrap(), narrow);
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
    fn reduction_is_positional_not_just_the_last_byte() {
        // Without this, `acc = Scalar::from(*b as u64)` — a function that
        // discards the reduction entirely and reads one byte in forty-eight —
        // passes every other test in this module.
        assert_eq!(reduce_be_bytes(&[0x01, 0x00]), Scalar::from(256u64));
        assert_eq!(
            reduce_be_bytes(&[0x01, 0x00, 0x00]),
            Scalar::from(65_536u64)
        );
        assert_eq!(reduce_be_bytes(&[0x12, 0x34]), Scalar::from(0x1234u64));
        assert_ne!(
            reduce_be_bytes(&[0x01, 0x02]),
            reduce_be_bytes(&[0x02, 0x01])
        );
    }

    #[test]
    fn reduction_agrees_with_the_canonical_decoder_on_a_dense_value() {
        // Every byte position nonzero, so a radix error or a dropped term
        // cannot survive. The value stays below r because the top byte is
        // small (r begins 0x73).
        let mut be = [0u8; 32];
        for (i, b) in be.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(1);
        }
        be[0] = 0x12;
        assert_eq!(reduce_be_bytes(&be), Scalar::from_bytes_be(&be).unwrap());
    }

    /// The decisive one: reducing the field order itself must give zero.
    /// Nothing else in this module establishes that reduction mod r happens
    /// at all.
    #[test]
    fn reducing_the_field_order_gives_zero() {
        // r for BLS12-381, big-endian.
        let r: [u8; 32] = [
            0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1,
            0xd8, 0x05, 0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x00, 0x00, 0x01,
        ];
        assert_eq!(reduce_be_bytes(&r), Scalar::ZERO, "r mod r must be 0");

        // And r + 1 must reduce to 1.
        let mut r_plus_one = r;
        r_plus_one[31] = 0x02;
        assert_eq!(reduce_be_bytes(&r_plus_one), Scalar::ONE);
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
        assert_eq!(g.q1, again.q1);
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
    fn two_generator_sets_of_the_same_size_compare_equal() {
        // `Generators` derives PartialEq over p1, q1 and h, and the report
        // layer and the domain calculation both depend on that being total.
        // A hand-written impl ignoring q1 would pass every other test here.
        assert_eq!(Generators::create(5), Generators::create(5));
        assert_ne!(Generators::create(5), Generators::create(4));

        let mut tweaked = Generators::create(5);
        tweaked.q1 += G1Projective::generator();
        assert_ne!(
            tweaked,
            Generators::create(5),
            "q1 must participate in equality"
        );

        let mut tweaked = Generators::create(5);
        tweaked.p1 += G1Projective::generator();
        assert_ne!(
            tweaked,
            Generators::create(5),
            "p1 must participate in equality"
        );

        let mut tweaked = Generators::create(5);
        tweaked.h[2] += G1Projective::generator();
        assert_ne!(
            tweaked,
            Generators::create(5),
            "h must participate in equality"
        );
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
    fn b_computes_the_documented_commitment() {
        // The only coverage `b` had was arity. Swapping the ONE and `domain`
        // scalars, reversing `h`, or dropping the `p1` term each yields a
        // different commitment — and each would be self-consistent between
        // signing and verification in Tasks 5 and 6, so it would never
        // surface as a failing test downstream. It would just mean the crate
        // measures something other than the commitment it documents.
        let g = Generators::create(4);
        let domain = Scalar::from(31u64);
        let msgs: Vec<Scalar> = (1..=4).map(|i| Scalar::from(i as u64 * 17)).collect();

        let mut expected = g.p1 + g.q1 * domain;
        for (h, m) in g.h.iter().zip(&msgs) {
            expected += *h * m;
        }
        assert_eq!(g.b(domain, &msgs).unwrap(), expected);

        // Order matters: the same messages permuted give a different B.
        let mut permuted = msgs.clone();
        permuted.swap(0, 3);
        assert_ne!(g.b(domain, &permuted).unwrap(), expected);

        // And the domain is bound in, not ignored.
        assert_ne!(g.b(domain + Scalar::ONE, &msgs).unwrap(), expected);
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
    fn neg_p2_is_actually_negated() {
        // It appears on both sides of the prepared-issuer test, so deleting
        // the `-` changes both identically and that test still passes. This
        // value sits on the right of every pairing check in Tasks 5 and 6,
        // where a sign error either rejects every valid proof or is silently
        // absorbed by a matching error on the signing side.
        assert_eq!(
            neg_p2() + G2Projective::generator(),
            G2Projective::identity()
        );
        assert_ne!(neg_p2(), G2Projective::generator());
    }

    #[test]
    fn a_prepared_issuer_gives_the_same_pairing_as_an_unprepared_one() {
        // The cached-pairing optimization must not change the answer. If it
        // did, `bench --composed` would be comparing two different functions.
        use pairing::{MillerLoopResult, MultiMillerLoop};
        let x = Scalar::from(42u64);
        let w = G2Projective::generator() * x;
        // Two DISTINCT G1 points. With the same point in both entries the
        // Miller loop's product is commutative, so swapping the two cached
        // tables would leave the result unchanged and this test would not
        // notice the swap.
        let a = G1Projective::generator() * Scalar::from(9u64);
        let b = G1Projective::generator() * Scalar::from(11u64);
        let prepared = PreparedIssuer::new(&w);

        let cached = Bls12::multi_miller_loop(&[
            (&a.to_affine(), &prepared.w),
            (&b.to_affine(), &prepared.neg_p2),
        ])
        .final_exponentiation();

        let fresh = Bls12::multi_miller_loop(&[
            (&a.to_affine(), &G2Prepared::from(w.to_affine())),
            (&b.to_affine(), &G2Prepared::from(neg_p2().to_affine())),
        ])
        .final_exponentiation();

        assert_eq!(cached, fresh);
        // If both sides ever degenerated to the trivial value the equality
        // above would hold vacuously.
        assert_ne!(cached, Gt::identity());

        // And the swap itself must be visible, which is the property the
        // two distinct points buy.
        let swapped = Bls12::multi_miller_loop(&[
            (&a.to_affine(), &prepared.neg_p2),
            (&b.to_affine(), &prepared.w),
        ])
        .final_exponentiation();
        assert_ne!(cached, swapped, "the two cached tables are interchangeable");
    }
}
