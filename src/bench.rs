use crate::baseline::{measure_baseline, Baseline};
use crate::bbs::keys::KeyPair;
use crate::bbs::proof::{prove, verify_proof, verify_proof_prepared};
use crate::bbs::sign::{message_to_scalar, sign, verify};
use crate::bbs::BbsError;
use crate::bls::{hash_to_scalar, Generators, PreparedIssuer, API_ID};
use crate::cost::Source;
use crate::harness::{measure, Sample};
use crate::modelled::{AnonymousAttestation, EscrowTag, ModelledError, ModelledPermit, Provenance};
use crate::report::{Row, Table};
use blstrs::{G1Projective, Scalar};
use ff::Field;
use group::Group;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct BenchOptions {
    pub iters: u32,
    pub seed: u64,
    /// Attributes in the credential.
    pub attributes: usize,
    /// How many of them a presentation discloses.
    pub disclose: usize,
    pub allow_modelled: bool,
}

impl Default for BenchOptions {
    fn default() -> Self {
        // Ten attributes with two disclosed is the shape P05 describes: an
        // agent proving authorization scope while revealing almost nothing.
        BenchOptions {
            iters: 100,
            seed: 7,
            attributes: 10,
            disclose: 2,
            allow_modelled: false,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BenchError {
    #[error(transparent)]
    Bbs(#[from] BbsError),
    #[error(transparent)]
    Harness(#[from] crate::harness::HarnessError),
    #[error(transparent)]
    Modelled(#[from] ModelledError),
    #[error("cannot disclose {disclose} of {attributes} attributes")]
    BadDisclosure { disclose: usize, attributes: usize },
}

/// Everything `bench` measures, kept as structured samples so `bench
/// --composed` can reuse them without re-timing.
#[derive(Debug)]
pub struct PrimitiveCosts {
    pub baseline: Baseline,
    pub g1_mul: Sample,
    pub hash_to_scalar: Sample,
    pub bbs_sign: Sample,
    pub bbs_verify: Sample,
    pub present: Sample,
    pub verify_proof_uncached: Sample,
    pub verify_proof_cached: Sample,
    pub modelled_ecdaa_attest: Option<Sample>,
    pub modelled_escrow_tag: Option<Sample>,
}

pub fn run_bench(opts: &BenchOptions) -> Result<PrimitiveCosts, BenchError> {
    if opts.disclose > opts.attributes {
        return Err(BenchError::BadDisclosure {
            disclose: opts.disclose,
            attributes: opts.attributes,
        });
    }

    let baseline = measure_baseline(opts.seed, opts.iters)?;

    let kp = KeyPair::generate(opts.seed);
    let gens = Generators::create(opts.attributes);
    let msgs: Vec<Scalar> = (0..opts.attributes)
        .map(|i| message_to_scalar(format!("attribute-{i}").as_bytes()))
        .collect::<Result<_, _>>()?;
    let header = b"occultation bench";
    let ph = b"occultation bench nonce";
    let disclosed: Vec<usize> = (0..opts.disclose).collect();
    let disclosed_pairs: Vec<(usize, Scalar)> = disclosed.iter().map(|&i| (i, msgs[i])).collect();

    let sig = sign(&kp.sk, &kp.pk, &gens, header, &msgs)?;
    let mut rng = ChaCha20Rng::seed_from_u64(opts.seed);
    let proof = prove(&kp.pk, &gens, header, ph, &sig, &msgs, &disclosed, &mut rng)?;
    let prepared = PreparedIssuer::new(&kp.pk.0);

    let s = Scalar::random(&mut ChaCha20Rng::seed_from_u64(opts.seed));
    let g1_mul = measure("G1 scalar multiplication", opts.iters, || {
        G1Projective::generator() * s
    });
    let h2s = measure("hash_to_scalar", opts.iters, || {
        hash_to_scalar(b"an agent action", API_ID).expect("fixed-length DST")
    });

    let bbs_sign = measure("BBS+ sign (issuer)", opts.iters, || {
        sign(&kp.sk, &kp.pk, &gens, header, &msgs).expect("valid inputs")
    });
    let bbs_verify = measure("BBS+ signature verify (holder)", opts.iters, || {
        verify(&kp.pk, &gens, header, &msgs, &sig).expect("valid inputs")
    });

    let mut prove_rng = ChaCha20Rng::seed_from_u64(opts.seed);
    let present = measure("BBS+ presentation", opts.iters, || {
        prove(
            &kp.pk,
            &gens,
            header,
            ph,
            &sig,
            &msgs,
            &disclosed,
            &mut prove_rng,
        )
        .expect("valid inputs")
    });
    let verify_proof_uncached = measure("BBS+ proof verify", opts.iters, || {
        verify_proof(&kp.pk, &gens, header, ph, &disclosed_pairs, &proof).expect("valid inputs")
    });
    let verify_proof_cached = measure("BBS+ proof verify, cached pairings", opts.iters, || {
        verify_proof_prepared(
            &prepared,
            &kp.pk,
            &gens,
            header,
            ph,
            &disclosed_pairs,
            &proof,
        )
        .expect("valid inputs")
    });

    // Modelled components are only executed with a permit. Note that this is
    // the *execution* gate: `bench --composed` can still do arithmetic over
    // the desk study's published escrow figure without one, because reading a
    // number out of a paper is not running a stub.
    let (modelled_ecdaa_attest, modelled_escrow_tag) = if opts.allow_modelled {
        let permit = ModelledPermit::from_flag(true)?;
        let ecdaa = crate::ecdaa::ModelledEcdaa::new(permit);
        let escrow = crate::escrow::ModelledThresholdElGamal::new(permit, 3, 5)?;
        (
            Some(measure("ECDAA attest", opts.iters, || {
                ecdaa.attest(b"measurement").expect("stub cannot fail")
            })),
            Some(measure("escrow tag + DLEQ", opts.iters, || {
                escrow.tag(b"did:web:agent-42").expect("stub cannot fail")
            })),
        )
    } else {
        (None, None)
    };

    Ok(PrimitiveCosts {
        baseline,
        g1_mul,
        hash_to_scalar: h2s,
        bbs_sign,
        bbs_verify,
        present,
        verify_proof_uncached,
        verify_proof_cached,
        modelled_ecdaa_attest,
        modelled_escrow_tag,
    })
}

impl PrimitiveCosts {
    /// The comparison the paper reports: every primitive against an Ed25519
    /// sign-and-verify round trip, not against verification alone.
    pub fn table(&self) -> Table {
        let b = self.baseline.round_trip();
        let src = |s: &Sample| Source::MeasuredHere { iters: s.iters };
        let mut t = Table::new("Primitive costs against the Ed25519 baseline")
            .with(
                Row::real(
                    self.baseline.sign.label.clone(),
                    self.baseline.sign.median,
                    src(&self.baseline.sign),
                )
                .against(b),
            )
            .with(
                Row::real(
                    self.baseline.verify.label.clone(),
                    self.baseline.verify.median,
                    src(&self.baseline.verify),
                )
                .against(b),
            )
            .with(
                Row::real(
                    "Ed25519 sign + verify (baseline)",
                    b,
                    src(&self.baseline.sign),
                )
                .against(b),
            )
            .with(
                Row::real(
                    self.g1_mul.label.clone(),
                    self.g1_mul.median,
                    src(&self.g1_mul),
                )
                .against(b),
            )
            .with(
                Row::real(
                    self.hash_to_scalar.label.clone(),
                    self.hash_to_scalar.median,
                    src(&self.hash_to_scalar),
                )
                .against(b),
            )
            .with(
                Row::real(
                    self.bbs_sign.label.clone(),
                    self.bbs_sign.median,
                    src(&self.bbs_sign),
                )
                .against(b),
            )
            .with(
                Row::real(
                    self.bbs_verify.label.clone(),
                    self.bbs_verify.median,
                    src(&self.bbs_verify),
                )
                .against(b),
            )
            .with(
                Row::real(
                    self.present.label.clone(),
                    self.present.median,
                    src(&self.present),
                )
                .against(b),
            )
            .with(
                Row::real(
                    self.verify_proof_uncached.label.clone(),
                    self.verify_proof_uncached.median,
                    src(&self.verify_proof_uncached),
                )
                .against(b),
            )
            .with(
                Row::real(
                    self.verify_proof_cached.label.clone(),
                    self.verify_proof_cached.median,
                    src(&self.verify_proof_cached),
                )
                .against(b),
            );

        for (sample, component) in [
            (&self.modelled_ecdaa_attest, "ECDAA"),
            (&self.modelled_escrow_tag, "threshold ElGamal escrow"),
        ] {
            if let Some(s) = sample {
                t = t.with(
                    Row::new(
                        s.label.clone(),
                        s.median,
                        Source::MeasuredHere { iters: s.iters },
                        Provenance::Modelled {
                            component,
                            reason: "stub; cost stand-in only",
                        },
                    )
                    .against(b),
                );
            }
        }

        if self.modelled_ecdaa_attest.is_none() {
            t = t.note(
                "ECDAA and escrow are not shown: they are modelled and require \
                 --allow-modelled to execute.",
            );
        }
        t
    }

    /// What `bench --composed` needs from a measured run.
    pub fn composed_halves(&self) -> (Duration, Duration, Duration) {
        (
            self.present.median,
            self.verify_proof_uncached.median,
            self.verify_proof_cached.median,
        )
    }
}
