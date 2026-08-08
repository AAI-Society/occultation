use criterion::{criterion_group, criterion_main, Criterion};
use occultation::bbs::keys::KeyPair;
use occultation::bbs::proof::{prove, verify_proof_prepared};
use occultation::bbs::sign::{message_to_scalar, sign};
use occultation::bls::{Generators, PreparedIssuer};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

fn bbs(c: &mut Criterion) {
    let kp = KeyPair::generate(7);
    let gens = Generators::create(10);
    let msgs: Vec<_> = (0..10)
        .map(|i| message_to_scalar(format!("attribute-{i}").as_bytes()).unwrap())
        .collect();
    let sig = sign(&kp.sk, &kp.pk, &gens, b"h", &msgs).unwrap();
    let disclosed = [0usize, 1];
    let pairs: Vec<_> = disclosed.iter().map(|&i| (i, msgs[i])).collect();
    let prepared = PreparedIssuer::new(&kp.pk.0);
    let mut rng = ChaCha20Rng::seed_from_u64(7);
    let proof = prove(
        &kp.pk, &gens, b"h", b"ph", &sig, &msgs, &disclosed, &mut rng,
    )
    .unwrap();

    c.bench_function("bbs_present", |b| {
        b.iter(|| {
            prove(
                &kp.pk, &gens, b"h", b"ph", &sig, &msgs, &disclosed, &mut rng,
            )
            .unwrap()
        })
    });
    c.bench_function("bbs_verify_proof_cached", |b| {
        b.iter(|| {
            verify_proof_prepared(&prepared, &kp.pk, &gens, b"h", b"ph", &pairs, &proof).unwrap()
        })
    });
}

criterion_group!(benches, bbs);
criterion_main!(benches);
