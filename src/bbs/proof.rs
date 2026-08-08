use crate::bbs::keys::PublicKey;
use crate::bbs::sign::{calculate_domain, Signature};
use crate::bbs::BbsError;
use crate::bls::{hash_to_scalar, octets, Generators, PreparedIssuer, API_ID};
use blstrs::{Bls12, G1Projective, Gt, Scalar};
use ff::Field;
use group::{Curve, Group};
use pairing::{MillerLoopResult, MultiMillerLoop};
use rand_chacha::ChaCha20Rng;

/// The random scalars one presentation consumes.
///
/// This is exactly what the pre-computation pool holds, and exactly what must
/// never be used twice: two presentations sharing these scalars share `Abar`
/// and `D` (so they are linkable) and expose `e` and every undisclosed message
/// to anyone who sees both transcripts. See `pool.rs`.
#[derive(Clone, Debug)]
pub struct ProofScalars {
    pub r1: Scalar,
    pub r2: Scalar,
    pub e_tilde: Scalar,
    pub r1_tilde: Scalar,
    pub r3_tilde: Scalar,
    /// One per undisclosed message, in ascending index order.
    pub m_tilde: Vec<Scalar>,
}

impl ProofScalars {
    /// `r2` is inverted during finalization, so a zero draw is resampled. The
    /// loop runs once with overwhelming probability, and the alternative is
    /// unwrapping a `CtOption` that can be `None`.
    pub fn random(rng: &mut ChaCha20Rng, undisclosed: usize) -> Self {
        let nonzero = |rng: &mut ChaCha20Rng| loop {
            let s = Scalar::random(&mut *rng);
            if s != Scalar::ZERO {
                break s;
            }
        };
        ProofScalars {
            r1: nonzero(rng),
            r2: nonzero(rng),
            e_tilde: Scalar::random(&mut *rng),
            r1_tilde: Scalar::random(&mut *rng),
            r3_tilde: Scalar::random(&mut *rng),
            m_tilde: (0..undisclosed)
                .map(|_| Scalar::random(&mut *rng))
                .collect(),
        }
    }
}

/// A presentation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    pub a_bar: G1Projective,
    pub b_bar: G1Projective,
    pub d: G1Projective,
    pub e_hat: Scalar,
    pub r1_hat: Scalar,
    pub r3_hat: Scalar,
    /// One response per undisclosed message, in ascending index order.
    pub m_hat: Vec<Scalar>,
    pub challenge: Scalar,
}

/// Indexes must be sorted, distinct and in range. Checked rather than assumed,
/// because an out-of-range index would otherwise index a slice and panic.
fn check_indexes(disclosed: &[usize], len: usize) -> Result<Vec<usize>, BbsError> {
    let mut previous: Option<usize> = None;
    for &i in disclosed {
        if i >= len {
            return Err(BbsError::IndexOutOfRange { index: i, len });
        }
        if let Some(p) = previous {
            if i <= p {
                return Err(BbsError::UnsortedIndexes(i));
            }
        }
        previous = Some(i);
    }
    Ok((0..len).filter(|i| !disclosed.contains(i)).collect())
}

#[allow(clippy::too_many_arguments)]
fn challenge(
    a_bar: &G1Projective,
    b_bar: &G1Projective,
    d: &G1Projective,
    t1: &G1Projective,
    t2: &G1Projective,
    domain: Scalar,
    disclosed: &[(usize, Scalar)],
    ph: &[u8],
) -> Result<Scalar, BbsError> {
    let mut parts: Vec<Vec<u8>> = vec![(disclosed.len() as u64).to_be_bytes().to_vec()];
    for (i, m) in disclosed {
        parts.push((*i as u64).to_be_bytes().to_vec());
        parts.push(m.to_bytes_be().to_vec());
    }
    for p in [a_bar, b_bar, d, t1, t2] {
        parts.push(p.to_affine().to_compressed().to_vec());
    }
    parts.push(domain.to_bytes_be().to_vec());
    parts.push(ph.to_vec());
    let refs: Vec<&[u8]> = parts.iter().map(|p| p.as_slice()).collect();
    Ok(hash_to_scalar(
        &octets(&refs),
        &[API_ID, b"H2S_CHALLENGE_"].concat(),
    )?)
}

/// Present a credential, disclosing `disclosed` and hiding the rest, using
/// caller-supplied scalars.
///
/// This is the entry point the pre-computation pool wraps. It is a pure
/// function of its arguments, which is what makes the pool's items meaningful
/// — and what makes reusing one catastrophic.
#[allow(clippy::too_many_arguments)]
pub fn prove_with_scalars(
    pk: &PublicKey,
    gens: &Generators,
    header: &[u8],
    ph: &[u8],
    sig: &Signature,
    msgs: &[Scalar],
    disclosed: &[usize],
    s: &ProofScalars,
) -> Result<Proof, BbsError> {
    let undisclosed = check_indexes(disclosed, gens.len())?;
    // `s.m_tilde[k]` is indexed below for `k` up to `undisclosed.len() - 1`,
    // so a caller-supplied `ProofScalars` with too few entries would panic on
    // out-of-bounds access rather than return a `Result`, and one with too
    // many would silently drop the extras. Neither is acceptable for a
    // caller-controlled struct — see `prove_with_scalars` being called
    // directly from the pool in Task 9.
    if s.m_tilde.len() != undisclosed.len() {
        return Err(BbsError::ResponseCount {
            expected: undisclosed.len(),
            got: s.m_tilde.len(),
        });
    }

    let domain = calculate_domain(pk, gens, header)?;
    let b = gens.b(domain, msgs)?;

    let d = b * s.r2;
    let a_bar = sig.a * (s.r1 * s.r2);
    let b_bar = d * s.r1 - a_bar * sig.e;

    let t1 = a_bar * s.e_tilde + d * s.r1_tilde;
    let mut points = vec![d];
    let mut scalars = vec![s.r3_tilde];
    for (k, &j) in undisclosed.iter().enumerate() {
        points.push(gens.h[j]);
        scalars.push(s.m_tilde[k]);
    }
    let t2 = G1Projective::multi_exp(&points, &scalars);

    let disclosed_pairs: Vec<(usize, Scalar)> = disclosed.iter().map(|&i| (i, msgs[i])).collect();
    let c = challenge(&a_bar, &b_bar, &d, &t1, &t2, domain, &disclosed_pairs, ph)?;

    let r3 = Option::<Scalar>::from(s.r2.invert()).ok_or(BbsError::ZeroBlinding)?;
    Ok(Proof {
        a_bar,
        b_bar,
        d,
        e_hat: s.e_tilde + sig.e * c,
        r1_hat: s.r1_tilde - s.r1 * c,
        r3_hat: s.r3_tilde - r3 * c,
        m_hat: undisclosed
            .iter()
            .enumerate()
            .map(|(k, &j)| s.m_tilde[k] + msgs[j] * c)
            .collect(),
        challenge: c,
    })
}

/// Present a credential with freshly drawn scalars.
#[allow(clippy::too_many_arguments)]
pub fn prove(
    pk: &PublicKey,
    gens: &Generators,
    header: &[u8],
    ph: &[u8],
    sig: &Signature,
    msgs: &[Scalar],
    disclosed: &[usize],
    rng: &mut ChaCha20Rng,
) -> Result<Proof, BbsError> {
    let undisclosed = check_indexes(disclosed, gens.len())?;
    let s = ProofScalars::random(rng, undisclosed.len());
    prove_with_scalars(pk, gens, header, ph, sig, msgs, disclosed, &s)
}

/// Reconstruct the commitments and the challenge. Shared by both verifiers.
fn recompute(
    pk: &PublicKey,
    gens: &Generators,
    header: &[u8],
    ph: &[u8],
    disclosed: &[(usize, Scalar)],
    p: &Proof,
) -> Result<bool, BbsError> {
    let indexes: Vec<usize> = disclosed.iter().map(|(i, _)| *i).collect();
    let undisclosed = check_indexes(&indexes, gens.len())?;
    // Unlike in `prove_with_scalars`, where a response-count mismatch is a
    // caller bug (the scalars were generated for the wrong `undisclosed`
    // count), here `disclosed` comes from the verifier's own — untrusted —
    // belief about what was disclosed. A prover can make that belief disagree
    // with the proof's actual disclosed set simply by having disclosed a
    // different index (see `claiming_an_undisclosed_attribute_fails`), and
    // that disagreement is exactly a failed verification, not malformed
    // input. Erroring here instead of returning `Ok(false)` would let a
    // straightforward attribute-count attack come back as `Err` from a
    // function whose whole contract is "verification failures are `Ok(false)`".
    if p.m_hat.len() != undisclosed.len() {
        return Ok(false);
    }

    let domain = calculate_domain(pk, gens, header)?;

    let t1 = p.b_bar * p.challenge + p.a_bar * p.e_hat + p.d * p.r1_hat;

    // Bv covers only the disclosed attributes; the undisclosed ones enter
    // through their responses.
    let mut bv_points = vec![gens.p1, gens.q1];
    let mut bv_scalars = vec![Scalar::ONE, domain];
    for (i, m) in disclosed {
        bv_points.push(gens.h[*i]);
        bv_scalars.push(*m);
    }
    let bv = G1Projective::multi_exp(&bv_points, &bv_scalars);

    let mut t2_points = vec![bv, p.d];
    let mut t2_scalars = vec![p.challenge, p.r3_hat];
    for (k, &j) in undisclosed.iter().enumerate() {
        t2_points.push(gens.h[j]);
        t2_scalars.push(p.m_hat[k]);
    }
    let t2 = G1Projective::multi_exp(&t2_points, &t2_scalars);

    let c = challenge(&p.a_bar, &p.b_bar, &p.d, &t1, &t2, domain, disclosed, ph)?;
    Ok(c == p.challenge)
}

/// `e(Abar, W) * e(Bbar, -P2) == 1`, with the G2 inputs prepared on the spot.
pub fn verify_proof(
    pk: &PublicKey,
    gens: &Generators,
    header: &[u8],
    ph: &[u8],
    disclosed: &[(usize, Scalar)],
    p: &Proof,
) -> Result<bool, BbsError> {
    let prepared = PreparedIssuer::new(&pk.0);
    verify_proof_prepared(&prepared, pk, gens, header, ph, disclosed, p)
}

/// The same check with a per-issuer `G2Prepared` supplied by the caller.
///
/// This is the desk study's "cached pairing pre-computation". Measure the
/// difference; do not assume it.
#[allow(clippy::too_many_arguments)]
pub fn verify_proof_prepared(
    prepared: &PreparedIssuer,
    pk: &PublicKey,
    gens: &Generators,
    header: &[u8],
    ph: &[u8],
    disclosed: &[(usize, Scalar)],
    p: &Proof,
) -> Result<bool, BbsError> {
    // The identity satisfies the pairing equation trivially, so reject it
    // before doing any work. This is not defense-in-depth: without it, a
    // party with no valid signature at all can forge a fully self-consistent
    // presentation of fabricated attributes under any issuer's key by
    // choosing r1 = 0 in `prove_with_scalars` (a_bar and b_bar both collapse
    // to the identity, and the Schnorr layer, which only proves knowledge of
    // the opening of D, is satisfied honestly). See
    // `a_self_consistent_forgery_via_r1_zero_is_rejected`, which is accepted
    // whenever this check is removed and rejected only because of it.
    if bool::from(p.a_bar.is_identity()) {
        return Ok(false);
    }
    if !recompute(pk, gens, header, ph, disclosed, p)? {
        return Ok(false);
    }
    let result = Bls12::multi_miller_loop(&[
        (&p.a_bar.to_affine(), &prepared.w),
        (&p.b_bar.to_affine(), &prepared.neg_p2),
    ])
    .final_exponentiation();
    Ok(result == Gt::identity())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bbs::keys::KeyPair;
    use crate::bbs::sign::{message_to_scalar, sign};
    use crate::bls::{Generators, PreparedIssuer};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    const HEADER: &[u8] = b"occultation test header";
    const PH: &[u8] = b"presentation nonce 1";

    struct Fixture {
        kp: KeyPair,
        gens: Generators,
        msgs: Vec<Scalar>,
        sig: crate::bbs::Signature,
    }

    fn fixture(n: usize) -> Fixture {
        let kp = KeyPair::generate(7);
        let gens = Generators::create(n);
        let msgs: Vec<Scalar> = (0..n)
            .map(|i| message_to_scalar(format!("attribute-{i}").as_bytes()).unwrap())
            .collect();
        let sig = sign(&kp.sk, &kp.pk, &gens, HEADER, &msgs).unwrap();
        Fixture {
            kp,
            gens,
            msgs,
            sig,
        }
    }

    fn disclosed_pairs(f: &Fixture, idx: &[usize]) -> Vec<(usize, Scalar)> {
        idx.iter().map(|&i| (i, f.msgs[i])).collect()
    }

    fn rng(seed: u64) -> ChaCha20Rng {
        ChaCha20Rng::seed_from_u64(seed)
    }

    #[test]
    fn a_presentation_verifies() {
        let f = fixture(5);
        let disclosed = [1usize, 3];
        let p = prove(
            &f.kp.pk,
            &f.gens,
            HEADER,
            PH,
            &f.sig,
            &f.msgs,
            &disclosed,
            &mut rng(1),
        )
        .unwrap();
        assert!(verify_proof(
            &f.kp.pk,
            &f.gens,
            HEADER,
            PH,
            &disclosed_pairs(&f, &disclosed),
            &p
        )
        .unwrap());
    }

    #[test]
    fn disclosing_nothing_verifies() {
        let f = fixture(5);
        let p = prove(
            &f.kp.pk,
            &f.gens,
            HEADER,
            PH,
            &f.sig,
            &f.msgs,
            &[],
            &mut rng(1),
        )
        .unwrap();
        assert!(verify_proof(&f.kp.pk, &f.gens, HEADER, PH, &[], &p).unwrap());
        assert_eq!(p.m_hat.len(), 5, "one response per undisclosed attribute");
    }

    #[test]
    fn disclosing_everything_verifies() {
        let f = fixture(3);
        let disclosed = [0usize, 1, 2];
        let p = prove(
            &f.kp.pk,
            &f.gens,
            HEADER,
            PH,
            &f.sig,
            &f.msgs,
            &disclosed,
            &mut rng(1),
        )
        .unwrap();
        assert!(verify_proof(
            &f.kp.pk,
            &f.gens,
            HEADER,
            PH,
            &disclosed_pairs(&f, &disclosed),
            &p
        )
        .unwrap());
        assert!(p.m_hat.is_empty());
    }

    /// Unlinkability, at the level this tool can assert it: two presentations
    /// of one credential share no group element.
    #[test]
    fn two_presentations_of_one_credential_share_no_element() {
        let f = fixture(5);
        let a = prove(
            &f.kp.pk,
            &f.gens,
            HEADER,
            PH,
            &f.sig,
            &f.msgs,
            &[1],
            &mut rng(1),
        )
        .unwrap();
        let b = prove(
            &f.kp.pk,
            &f.gens,
            HEADER,
            PH,
            &f.sig,
            &f.msgs,
            &[1],
            &mut rng(2),
        )
        .unwrap();
        assert_ne!(a.a_bar, b.a_bar);
        assert_ne!(a.b_bar, b.b_bar);
        assert_ne!(a.d, b.d);
        assert_ne!(a.challenge, b.challenge);
    }

    #[test]
    fn claiming_an_undisclosed_attribute_fails() {
        // The verifier is told attribute 0 was disclosed as attribute 0's real
        // value, but the prover never disclosed it. The index sets disagree,
        // so the challenge does not reproduce.
        let f = fixture(5);
        let p = prove(
            &f.kp.pk,
            &f.gens,
            HEADER,
            PH,
            &f.sig,
            &f.msgs,
            &[1],
            &mut rng(1),
        )
        .unwrap();
        let lying = disclosed_pairs(&f, &[0, 1]);
        assert!(!verify_proof(&f.kp.pk, &f.gens, HEADER, PH, &lying, &p).unwrap());
    }

    #[test]
    fn a_wrong_disclosed_value_fails() {
        let f = fixture(5);
        let disclosed = [1usize, 3];
        let p = prove(
            &f.kp.pk,
            &f.gens,
            HEADER,
            PH,
            &f.sig,
            &f.msgs,
            &disclosed,
            &mut rng(1),
        )
        .unwrap();
        let mut lying = disclosed_pairs(&f, &disclosed);
        lying[0].1 += Scalar::ONE;
        assert!(!verify_proof(&f.kp.pk, &f.gens, HEADER, PH, &lying, &p).unwrap());
    }

    #[test]
    fn a_tampered_response_fails() {
        let f = fixture(5);
        let disclosed = [1usize];
        let mut p = prove(
            &f.kp.pk,
            &f.gens,
            HEADER,
            PH,
            &f.sig,
            &f.msgs,
            &disclosed,
            &mut rng(1),
        )
        .unwrap();
        p.m_hat[0] += Scalar::ONE;
        assert!(!verify_proof(
            &f.kp.pk,
            &f.gens,
            HEADER,
            PH,
            &disclosed_pairs(&f, &disclosed),
            &p
        )
        .unwrap());
    }

    #[test]
    fn a_tampered_group_element_fails() {
        let f = fixture(5);
        let mut p = prove(
            &f.kp.pk,
            &f.gens,
            HEADER,
            PH,
            &f.sig,
            &f.msgs,
            &[1],
            &mut rng(1),
        )
        .unwrap();
        p.a_bar += G1Projective::generator();
        assert!(!verify_proof(
            &f.kp.pk,
            &f.gens,
            HEADER,
            PH,
            &disclosed_pairs(&f, &[1]),
            &p
        )
        .unwrap());
    }

    #[test]
    fn a_different_presentation_header_fails() {
        // Replaying a presentation against a second relying party's nonce is
        // the attack `ph` exists to stop.
        let f = fixture(5);
        let p = prove(
            &f.kp.pk,
            &f.gens,
            HEADER,
            PH,
            &f.sig,
            &f.msgs,
            &[1],
            &mut rng(1),
        )
        .unwrap();
        assert!(!verify_proof(
            &f.kp.pk,
            &f.gens,
            HEADER,
            b"presentation nonce 2",
            &disclosed_pairs(&f, &[1]),
            &p
        )
        .unwrap());
    }

    #[test]
    fn another_issuers_key_fails() {
        let f = fixture(5);
        let other = KeyPair::generate(8);
        let p = prove(
            &f.kp.pk,
            &f.gens,
            HEADER,
            PH,
            &f.sig,
            &f.msgs,
            &[1],
            &mut rng(1),
        )
        .unwrap();
        assert!(!verify_proof(
            &other.pk,
            &f.gens,
            HEADER,
            PH,
            &disclosed_pairs(&f, &[1]),
            &p
        )
        .unwrap());
    }

    #[test]
    fn an_identity_a_bar_is_rejected() {
        // Abar = identity satisfies the pairing equation for any Bbar = identity
        // and must be rejected explicitly, not left to the Schnorr layer.
        let f = fixture(3);
        let mut p = prove(
            &f.kp.pk,
            &f.gens,
            HEADER,
            PH,
            &f.sig,
            &f.msgs,
            &[],
            &mut rng(1),
        )
        .unwrap();
        p.a_bar = G1Projective::identity();
        assert!(!verify_proof(&f.kp.pk, &f.gens, HEADER, PH, &[], &p).unwrap());
    }

    #[test]
    fn out_of_range_and_unsorted_indexes_are_errors_not_panics() {
        let f = fixture(3);
        assert!(prove(
            &f.kp.pk,
            &f.gens,
            HEADER,
            PH,
            &f.sig,
            &f.msgs,
            &[9],
            &mut rng(1)
        )
        .is_err());
        assert!(prove(
            &f.kp.pk,
            &f.gens,
            HEADER,
            PH,
            &f.sig,
            &f.msgs,
            &[1, 1],
            &mut rng(1)
        )
        .is_err());
        assert!(prove(
            &f.kp.pk,
            &f.gens,
            HEADER,
            PH,
            &f.sig,
            &f.msgs,
            &[2, 0],
            &mut rng(1)
        )
        .is_err());
    }

    /// The cached-pairing path must agree with the uncached one on every
    /// answer, or `bench --composed` would be timing two different functions
    /// and calling the difference an optimization.
    #[test]
    fn the_prepared_verifier_agrees_with_the_plain_one() {
        let f = fixture(5);
        let prepared = PreparedIssuer::new(&f.kp.pk.0);
        let disclosed = [1usize, 3];
        let pairs = disclosed_pairs(&f, &disclosed);

        let good = prove(
            &f.kp.pk,
            &f.gens,
            HEADER,
            PH,
            &f.sig,
            &f.msgs,
            &disclosed,
            &mut rng(1),
        )
        .unwrap();
        assert_eq!(
            verify_proof(&f.kp.pk, &f.gens, HEADER, PH, &pairs, &good).unwrap(),
            verify_proof_prepared(&prepared, &f.kp.pk, &f.gens, HEADER, PH, &pairs, &good).unwrap()
        );

        let mut bad = good.clone();
        bad.b_bar += G1Projective::generator();
        assert!(
            !verify_proof_prepared(&prepared, &f.kp.pk, &f.gens, HEADER, PH, &pairs, &bad).unwrap()
        );
    }

    #[test]
    fn the_same_scalars_and_inputs_give_the_same_proof() {
        // prove_with_scalars must be a pure function of its inputs — the pool
        // in Task 9 depends on it.
        let f = fixture(4);
        let s = ProofScalars::random(&mut rng(11), 3);
        let a =
            prove_with_scalars(&f.kp.pk, &f.gens, HEADER, PH, &f.sig, &f.msgs, &[2], &s).unwrap();
        let b =
            prove_with_scalars(&f.kp.pk, &f.gens, HEADER, PH, &f.sig, &f.msgs, &[2], &s).unwrap();
        assert_eq!(a.a_bar, b.a_bar);
        assert_eq!(a.challenge, b.challenge);
        assert_eq!(a.m_hat, b.m_hat);
    }

    /// Unlike `an_identity_a_bar_is_rejected` above -- which tampers a real
    /// proof's `a_bar` after the fact and is caught by the Schnorr layer (its
    /// `t1` no longer reconstructs) whether or not the explicit identity
    /// check exists -- this test does not use `f.sig` or any real signature
    /// at all. Setting `r1 = 0` in `prove_with_scalars` makes `a_bar` and
    /// `b_bar` both the identity honestly, by construction: `a_bar = A*r1*r2`
    /// is 0 regardless of `A`, and `b_bar = D*r1 - a_bar*e` collapses to 0
    /// too. The Schnorr layer only ever proves knowledge of the opening of
    /// `D` (which a forger trivially has, since they chose the fabricated
    /// messages themselves) and, once `a_bar` is 0, imposes no constraint
    /// tying that opening to any real issuer signature. So a party with no
    /// valid credential at all can honestly and self-consistently "present"
    /// fabricated attributes under any issuer's key. Confirmed by removing
    /// the identity check during review: this exact proof was then accepted.
    /// The explicit check is the only thing that rejects it.
    #[test]
    fn a_self_consistent_forgery_via_r1_zero_is_rejected() {
        let f = fixture(3);
        let fake_sig = crate::bbs::Signature {
            a: G1Projective::generator() * Scalar::from(1234u64),
            e: Scalar::from(5678u64),
        };
        let fabricated_msgs: Vec<Scalar> =
            (0..3).map(|i| Scalar::from(90000u64 + i as u64)).collect();
        let s = ProofScalars {
            r1: Scalar::ZERO,
            r2: Scalar::ONE,
            e_tilde: Scalar::from(1u64),
            r1_tilde: Scalar::from(2u64),
            r3_tilde: Scalar::from(3u64),
            m_tilde: vec![Scalar::from(4u64), Scalar::from(5u64)],
        };
        let disclosed = [0usize];
        let forged = prove_with_scalars(
            &f.kp.pk,
            &f.gens,
            HEADER,
            PH,
            &fake_sig,
            &fabricated_msgs,
            &disclosed,
            &s,
        )
        .unwrap();
        assert!(bool::from(forged.a_bar.is_identity()));
        assert!(bool::from(forged.b_bar.is_identity()));
        let pairs = vec![(0usize, fabricated_msgs[0])];
        assert!(
            !verify_proof(&f.kp.pk, &f.gens, HEADER, PH, &pairs, &forged).unwrap(),
            "a proof with no real signature behind it, and identity a_bar/b_bar, must not verify"
        );
    }

    /// `s.m_tilde[k]` is indexed for `k` up to `undisclosed.len() - 1` while
    /// building `t2` and `m_hat`. Without the length check at the top of
    /// `prove_with_scalars`, a caller-supplied `ProofScalars` with too few
    /// entries panics on out-of-bounds indexing rather than returning an
    /// error -- confirmed by deleting that check during review: every other
    /// test in this module still passed, because none of them calls
    /// `prove_with_scalars` with a mismatched `ProofScalars`. This is exactly
    /// the entry point the pool in Task 9 calls directly, so a malformed pool
    /// item must be a `Result::Err`, not a crash.
    #[test]
    fn a_mismatched_scalars_count_is_an_error_not_a_panic() {
        let f = fixture(4);
        let disclosed = [2usize]; // 3 undisclosed messages
        let too_few = ProofScalars::random(&mut rng(1), 2);
        assert!(prove_with_scalars(
            &f.kp.pk, &f.gens, HEADER, PH, &f.sig, &f.msgs, &disclosed, &too_few
        )
        .is_err());

        let too_many = ProofScalars::random(&mut rng(1), 4);
        assert!(prove_with_scalars(
            &f.kp.pk, &f.gens, HEADER, PH, &f.sig, &f.msgs, &disclosed, &too_many
        )
        .is_err());
    }

    /// Isolates the pairing layer, which none of the tests above do.
    ///
    /// Every other negative test in this module tampers a value that also
    /// sits inside the Schnorr challenge preimage (`a_bar`, `b_bar`, `d`, a
    /// disclosed value, a response, `ph`), so the Schnorr layer rejects it
    /// before the pairing is ever examined. Confirmed during review by
    /// stubbing the pairing result to an unconditional `Ok(true)`: every
    /// other test in this module still passed. A bug that made the pairing
    /// check always succeed would be invisible to this module without this
    /// test.
    ///
    /// This proof is built with a genuine, well-formed `ProofScalars`
    /// (nonzero `r1`/`r2`, not the `r1 = 0` degenerate case above) and a
    /// `Signature` that does not actually correspond to `msgs` under this
    /// key: `e` is tweaked, exactly as `bbs::sign::tests::a_tweaked_e_fails`
    /// does for raw signature verification. `prove_with_scalars` is purely
    /// mechanical -- it does not check that `sig` opens `B`, so the Schnorr
    /// layer reconstructs `t1`/`t2` and the challenge correctly regardless,
    /// and only the pairing equation `e(Abar, W) * e(Bbar, -P2) == 1`
    /// distinguishes a genuine signature from this tampered one.
    #[test]
    fn a_proof_built_from_a_signature_that_does_not_open_b_is_rejected() {
        let f = fixture(5);
        let mut bad_sig = f.sig.clone();
        bad_sig.e += Scalar::ONE;
        let disclosed = [1usize, 3];
        let s = ProofScalars::random(&mut rng(1), 3);

        let p = prove_with_scalars(
            &f.kp.pk, &f.gens, HEADER, PH, &bad_sig, &f.msgs, &disclosed, &s,
        )
        .unwrap();
        assert!(
            !bool::from(p.a_bar.is_identity()),
            "r1, r2 nonzero: this must not hit the identity short-circuit"
        );
        assert!(!verify_proof(
            &f.kp.pk,
            &f.gens,
            HEADER,
            PH,
            &disclosed_pairs(&f, &disclosed),
            &p
        )
        .unwrap());
    }
}
