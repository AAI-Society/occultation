use crate::bbs::keys::{PublicKey, SecretKey};
use crate::bbs::BbsError;
use crate::bls::{hash_to_scalar, octets, Generators, API_ID};
use blstrs::{Bls12, G1Projective, G2Prepared, G2Projective, Gt, Scalar};
use ff::Field;
use group::{Curve, Group};
use pairing::{MillerLoopResult, MultiMillerLoop};

/// A BBS+ signature: one G1 element and one scalar.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    pub a: G1Projective,
    pub e: Scalar,
}

fn h2s_dst() -> Vec<u8> {
    [API_ID, b"H2S_"].concat()
}

/// Map an attribute's bytes into the scalar field.
pub fn message_to_scalar(msg: &[u8]) -> Result<Scalar, BbsError> {
    Ok(hash_to_scalar(
        msg,
        &[API_ID, b"MAP_MSG_TO_SCALAR_AS_HASH_"].concat(),
    )?)
}

/// Bind the public key, the generator set and the header into one scalar, so a
/// signature cannot be replayed under a different credential shape.
pub fn calculate_domain(
    pk: &PublicKey,
    gens: &Generators,
    header: &[u8],
) -> Result<Scalar, BbsError> {
    let mut parts: Vec<Vec<u8>> = vec![
        pk.to_bytes(),
        (gens.len() as u64).to_be_bytes().to_vec(),
        gens.p1.to_affine().to_compressed().to_vec(),
        gens.q1.to_affine().to_compressed().to_vec(),
    ];
    for h in &gens.h {
        parts.push(h.to_affine().to_compressed().to_vec());
    }
    parts.push(API_ID.to_vec());
    parts.push(header.to_vec());
    let refs: Vec<&[u8]> = parts.iter().map(|p| p.as_slice()).collect();
    Ok(hash_to_scalar(
        &octets(&refs),
        &[API_ID, b"H2S_DOMAIN_"].concat(),
    )?)
}

/// Sign `msgs` under `sk`.
///
/// `e` is derived deterministically from the key, the messages and the domain,
/// as the draft does. Determinism matters here beyond hygiene: a measurement
/// that changes its inputs between runs is not reproducible.
pub fn sign(
    sk: &SecretKey,
    pk: &PublicKey,
    gens: &Generators,
    header: &[u8],
    msgs: &[Scalar],
) -> Result<Signature, BbsError> {
    let domain = calculate_domain(pk, gens, header)?;

    let mut parts: Vec<Vec<u8>> = vec![sk.0.to_bytes_be().to_vec()];
    for m in msgs {
        parts.push(m.to_bytes_be().to_vec());
    }
    parts.push(domain.to_bytes_be().to_vec());
    let refs: Vec<&[u8]> = parts.iter().map(|p| p.as_slice()).collect();
    let e = hash_to_scalar(&octets(&refs), &h2s_dst())?;

    let b = gens.b(domain, msgs)?;
    // A = B * 1/(x + e). `x + e == 0` has negligible probability but is not
    // impossible, and unwrapping a CtOption on it would be a panic on input.
    let denom = sk.0 + e;
    let inv = Option::<Scalar>::from(denom.invert()).ok_or(BbsError::DegenerateKey)?;
    Ok(Signature { a: b * inv, e })
}

/// `e(A, W + P2*e) * e(B, -P2) == 1`.
///
/// Note what is *not* cacheable here: the second G2 input is `W + P2*e`, which
/// depends on the signature, so a per-issuer `G2Prepared` does not help
/// signature verification. It helps proof verification, where both G2 inputs
/// are fixed.
pub fn verify(
    pk: &PublicKey,
    gens: &Generators,
    header: &[u8],
    msgs: &[Scalar],
    sig: &Signature,
) -> Result<bool, BbsError> {
    let domain = calculate_domain(pk, gens, header)?;
    let b = gens.b(domain, msgs)?;

    let lhs_g2 = (pk.0 + G2Projective::generator() * sig.e).to_affine();
    let prep_lhs = G2Prepared::from(lhs_g2);
    let prep_rhs = G2Prepared::from(crate::bls::neg_p2().to_affine());

    let result =
        Bls12::multi_miller_loop(&[(&sig.a.to_affine(), &prep_lhs), (&b.to_affine(), &prep_rhs)])
            .final_exponentiation();

    Ok(result == Gt::identity())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bbs::keys::KeyPair;
    use crate::bls::Generators;

    const HEADER: &[u8] = b"occultation test header";

    fn fixture(n: usize) -> (KeyPair, Generators, Vec<Scalar>) {
        let kp = KeyPair::generate(7);
        let gens = Generators::create(n);
        let msgs: Vec<Scalar> = (0..n)
            .map(|i| message_to_scalar(format!("attribute-{i}").as_bytes()).unwrap())
            .collect();
        (kp, gens, msgs)
    }

    #[test]
    fn a_signature_verifies() {
        let (kp, gens, msgs) = fixture(5);
        let sig = sign(&kp.sk, &kp.pk, &gens, HEADER, &msgs).unwrap();
        assert!(verify(&kp.pk, &gens, HEADER, &msgs, &sig).unwrap());
    }

    #[test]
    fn a_tampered_message_fails() {
        let (kp, gens, mut msgs) = fixture(5);
        let sig = sign(&kp.sk, &kp.pk, &gens, HEADER, &msgs).unwrap();
        msgs[2] += Scalar::ONE;
        assert!(!verify(&kp.pk, &gens, HEADER, &msgs, &sig).unwrap());
    }

    #[test]
    fn a_tampered_header_fails() {
        let (kp, gens, msgs) = fixture(5);
        let sig = sign(&kp.sk, &kp.pk, &gens, HEADER, &msgs).unwrap();
        assert!(!verify(&kp.pk, &gens, b"a different header", &msgs, &sig).unwrap());
    }

    #[test]
    fn another_issuers_key_fails() {
        let (kp, gens, msgs) = fixture(5);
        let other = KeyPair::generate(8);
        let sig = sign(&kp.sk, &kp.pk, &gens, HEADER, &msgs).unwrap();
        assert!(!verify(&other.pk, &gens, HEADER, &msgs, &sig).unwrap());
    }

    #[test]
    fn a_forged_signature_element_fails() {
        let (kp, gens, msgs) = fixture(5);
        let mut sig = sign(&kp.sk, &kp.pk, &gens, HEADER, &msgs).unwrap();
        sig.a += G1Projective::generator();
        assert!(!verify(&kp.pk, &gens, HEADER, &msgs, &sig).unwrap());
    }

    #[test]
    fn a_tweaked_e_fails() {
        let (kp, gens, msgs) = fixture(5);
        let mut sig = sign(&kp.sk, &kp.pk, &gens, HEADER, &msgs).unwrap();
        sig.e += Scalar::ONE;
        assert!(!verify(&kp.pk, &gens, HEADER, &msgs, &sig).unwrap());
    }

    #[test]
    fn signing_the_wrong_number_of_messages_is_an_error() {
        let (kp, gens, msgs) = fixture(5);
        assert!(sign(&kp.sk, &kp.pk, &gens, HEADER, &msgs[..3]).is_err());
    }

    /// Named for the generator *set*, not the count: the count part of the
    /// domain preimage is provably redundant with the length-prefixed
    /// generator list, so this test passes on the list difference alone and
    /// cannot see the count being dropped. That redundancy is harmless — do
    /// not "fix" it by adding a term.
    #[test]
    fn the_domain_binds_the_generator_set() {
        // A signature over 5 messages must not verify against generators built
        // for a different length, even on the same first five messages.
        let (kp, gens, msgs) = fixture(5);
        let sig = sign(&kp.sk, &kp.pk, &gens, HEADER, &msgs).unwrap();
        let wider = Generators::create(6);
        let mut wider_msgs = msgs.clone();
        wider_msgs.push(Scalar::ZERO);
        assert!(!verify(&kp.pk, &wider, HEADER, &wider_msgs, &sig).unwrap());
    }

    #[test]
    fn signing_is_deterministic_for_the_same_inputs() {
        let (kp, gens, msgs) = fixture(3);
        let a = sign(&kp.sk, &kp.pk, &gens, HEADER, &msgs).unwrap();
        let b = sign(&kp.sk, &kp.pk, &gens, HEADER, &msgs).unwrap();
        assert_eq!(a.e, b.e);
        assert_eq!(a.a, b.a);
    }

    /// `calculate_domain` is called identically by `sign` and `verify`, so an
    /// error inside it is symmetric: both sides recompute the same wrong
    /// value and never disagree. `another_issuers_key_fails` above does *not*
    /// prove `pk` participates in the domain, because a mismatched `pk` also
    /// breaks the pairing check directly through `W` — that failure would
    /// still happen even if `calculate_domain` silently dropped `pk`
    /// entirely. This test isolates the derivation itself, field by field,
    /// the same way `b_computes_the_documented_commitment` isolates
    /// `Generators::b` in `bls.rs`.
    #[test]
    fn calculate_domain_binds_every_field_independently() {
        let kp = KeyPair::generate(7);
        let other = KeyPair::generate(8);
        let gens = Generators::create(3);
        let header = b"a header";

        let base = calculate_domain(&kp.pk, &gens, header).unwrap();
        assert_eq!(calculate_domain(&kp.pk, &gens, header).unwrap(), base);

        assert_ne!(
            calculate_domain(&other.pk, &gens, header).unwrap(),
            base,
            "the public key must participate in the domain, not only in the pairing check"
        );
        assert_ne!(
            calculate_domain(&kp.pk, &gens, b"a different header").unwrap(),
            base
        );

        let mut tweaked = gens.clone();
        tweaked.p1 += G1Projective::generator();
        assert_ne!(calculate_domain(&kp.pk, &tweaked, header).unwrap(), base);

        let mut tweaked = gens.clone();
        tweaked.q1 += G1Projective::generator();
        assert_ne!(calculate_domain(&kp.pk, &tweaked, header).unwrap(), base);

        // Every generator, not just one: `for h in gens.h.iter().skip(1)` in
        // the derivation would otherwise survive.
        for i in 0..gens.h.len() {
            let mut tweaked = gens.clone();
            tweaked.h[i] += G1Projective::generator();
            assert_ne!(
                calculate_domain(&kp.pk, &tweaked, header).unwrap(),
                base,
                "generator h[{i}] does not participate in the domain"
            );
        }
    }

    /// `verify` never recomputes `e` — it reads `sig.e` and checks
    /// `A = B/(x+e)`, which holds for *any* `e` with `x + e != 0`. So nothing
    /// in a round trip constrains what `e` is derived from, and the
    /// determinism test above is satisfied by any deterministic function,
    /// including a constant.
    ///
    /// That gap is a forgery, not an untidiness. If `e` did not depend on the
    /// messages, every credential an issuer signed under the same generators
    /// and header would share one `e`, and two signatures could be
    /// interpolated into a third the issuer never made:
    ///
    /// ```text
    /// A1 = B1/(x+e), A2 = B2/(x+e)
    /// => l*A1 + (1-l)*A2 = (l*B1 + (1-l)*B2)/(x+e)
    /// ```
    ///
    /// and `l*B1 + (1-l)*B2` is a well-formed `B` on the interpolated
    /// attribute vector. Distinct `e` per message vector is what prevents it.
    #[test]
    fn e_depends_on_every_input_it_is_derived_from() {
        let (kp, gens, msgs) = fixture(3);
        let base = sign(&kp.sk, &kp.pk, &gens, HEADER, &msgs).unwrap().e;

        let mut other_msgs = msgs.clone();
        other_msgs[1] += Scalar::ONE;
        assert_ne!(
            sign(&kp.sk, &kp.pk, &gens, HEADER, &other_msgs).unwrap().e,
            base,
            "two credentials sharing an e can be interpolated into a third"
        );

        assert_ne!(
            sign(&kp.sk, &kp.pk, &gens, b"a different header", &msgs)
                .unwrap()
                .e,
            base
        );

        // Varying the key alone is NOT enough to show `sk` participates:
        // `calculate_domain` already hashes `pk`, `domain` feeds `e`'s
        // preimage, and `KeyPair::generate` moves `sk` and `pk` together — so
        // this assertion passes even if `sk` is dropped from the preimage
        // entirely. It is here to pin the whole-key channel, and the next
        // assertion is what actually isolates `sk`.
        let other = KeyPair::generate(8);
        assert_ne!(
            sign(&other.sk, &other.pk, &gens, HEADER, &msgs).unwrap().e,
            base
        );

        // Hold `pk` — and therefore `domain` — fixed while varying `sk` only.
        // `sign` takes the two separately, so a deliberately mismatched pair
        // isolates the secret key's contribution. The resulting signature
        // verifies under nothing, which is fine: only `e` is read.
        //
        // On severity, stated honestly: dropping `sk` here is a deviation
        // from the draft rather than a break. `e` is published as part of the
        // signature, so it is not secret in any case, and `domain` already
        // separates issuers. What matters is that a clause of a
        // security-relevant derivation should not go untested.
        let mismatched_a = sign(&kp.sk, &other.pk, &gens, HEADER, &msgs).unwrap().e;
        let mismatched_b = sign(&other.sk, &other.pk, &gens, HEADER, &msgs).unwrap().e;
        assert_ne!(
            mismatched_a, mismatched_b,
            "the same pk gives the same domain, so only sk differs here; e must too"
        );

        // Message order must matter too, not just message content.
        let mut permuted = msgs.clone();
        permuted.swap(0, 2);
        assert_ne!(
            sign(&kp.sk, &kp.pk, &gens, HEADER, &permuted).unwrap().e,
            base
        );
    }
}
