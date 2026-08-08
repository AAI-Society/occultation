use occultation::anonymity::{partition, Fleet};
use occultation::bench::{run_bench, BenchOptions};
use occultation::bls::expand_message_xmd;
use occultation::pool::{simulate_burst, BurstConfig};
use std::time::Duration;

/// Malformed fleet descriptions must surface as errors, never panics.
#[test]
fn malformed_fleets_error_rather_than_panic() {
    let cases = [
        ("empty file", ""),
        (
            "missing name",
            "[[host]]\nid = \"a\"\n[host.tcb]\nx = \"1\"\n",
        ),
        ("wrong type for name", "name = 1\n"),
        (
            "wrong type for count",
            "name = \"a\"\n[[host]]\nid = \"h\"\ncount = \"lots\"\n",
        ),
        ("typo'd table name", "name = \"a\"\n[[hosts]]\nid = \"h\"\n"),
        (
            "host missing id",
            "name = \"a\"\n[[host]]\n[host.tcb]\nx = \"1\"\n",
        ),
        (
            "non-string tcb value",
            "name = \"a\"\n[[host]]\nid = \"h\"\n[host.tcb]\nx = 13\n",
        ),
        ("unparseable toml", "[[[["),
    ];
    for (label, src) in cases {
        assert!(
            toml::from_str::<Fleet>(src).is_err(),
            "{label}: expected a parse error, got a Fleet"
        );
    }
}

/// A fleet that parses but describes nothing must fail in `partition`.
#[test]
fn semantically_empty_fleets_error_rather_than_panic() {
    for src in [
        "name = \"a\"\n",
        "name = \"a\"\n[[host]]\nid = \"h\"\ncount = 0\n[host.tcb]\nx = \"1\"\n",
        "name = \"a\"\n[[host]]\nid = \"h\"\n[host.tcb]\n",
    ] {
        let f: Fleet = toml::from_str(src).expect("well-formed TOML");
        assert!(partition(&f).is_err(), "{src:?}");
    }
}

/// Absurd or degenerate burst descriptions must error, not hang or allocate
/// the machine to death.
#[test]
fn degenerate_burst_configurations_error_rather_than_hang() {
    let base = BurstConfig {
        capacity: 8,
        refill_cost: Duration::from_micros(500),
        online_cost: Duration::from_micros(50),
        burst_rate_hz: 1_000.0,
        duration: Duration::from_millis(100),
        seed: 7,
    };
    for (label, cfg) in [
        (
            "zero rate",
            BurstConfig {
                burst_rate_hz: 0.0,
                ..base.clone()
            },
        ),
        (
            "negative rate",
            BurstConfig {
                burst_rate_hz: -1.0,
                ..base.clone()
            },
        ),
        (
            "NaN rate",
            BurstConfig {
                burst_rate_hz: f64::NAN,
                ..base.clone()
            },
        ),
        (
            "infinite rate",
            BurstConfig {
                burst_rate_hz: f64::INFINITY,
                ..base.clone()
            },
        ),
        (
            "zero refill cost",
            BurstConfig {
                refill_cost: Duration::ZERO,
                ..base.clone()
            },
        ),
        (
            "absurd request count",
            BurstConfig {
                burst_rate_hz: 1e9,
                duration: Duration::from_secs(86_400),
                ..base.clone()
            },
        ),
    ] {
        assert!(simulate_burst(&cfg).is_err(), "{label}");
    }
    assert!(
        simulate_burst(&base).is_ok(),
        "the base config must still work"
    );
}

#[test]
fn a_zero_duration_burst_is_a_no_op_rather_than_an_error() {
    let cfg = BurstConfig {
        capacity: 8,
        refill_cost: Duration::from_micros(500),
        online_cost: Duration::from_micros(50),
        burst_rate_hz: 1_000.0,
        duration: Duration::ZERO,
        seed: 7,
    };
    let r = simulate_burst(&cfg).unwrap();
    assert_eq!(r.requests, 0);
    assert!(!r.exhausted);
}

#[test]
fn bad_bench_options_error_rather_than_panic() {
    assert!(run_bench(&BenchOptions {
        disclose: 11,
        attributes: 10,
        ..Default::default()
    })
    .is_err());
    // Zero attributes is legal: a credential with no attributes still has a
    // domain and still presents.
    assert!(run_bench(&BenchOptions {
        attributes: 0,
        disclose: 0,
        iters: 3,
        ..Default::default()
    })
    .is_ok());
}

#[test]
fn expand_message_xmd_refuses_impossible_parameters_rather_than_panicking() {
    assert!(expand_message_xmd(b"m", &[0u8; 256], 32).is_err());
    assert!(expand_message_xmd(b"m", b"DST", 65_536).is_err());
}
