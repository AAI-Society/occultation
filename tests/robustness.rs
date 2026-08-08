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
        (
            // The exact operator input a prior review reproduced a panic
            // with: `pool --burst 1000 --duration 1s --refill
            // 100000000000000000s --online 1us` panicked at
            // `Duration::from_secs_f64` once the backlog's implied stall
            // exceeded `Duration::MAX`. A units typo in `--refill`, not a
            // contrived value.
            "refill cost so large the implied stall overflows Duration (a units typo)",
            BurstConfig {
                refill_cost: Duration::from_secs(100_000_000_000_000_000),
                online_cost: Duration::from_micros(1),
                burst_rate_hz: 1000.0,
                duration: Duration::from_secs(1),
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

/// The library-level tests above (`malformed_fleets_error_rather_than_panic`)
/// exercise `Fleet`'s parser directly. Nothing in this suite previously drove
/// a malformed fleet file through the actual binary, so a panic reachable
/// only through `main`'s own error handling — a bad `unwrap` between reading
/// the CLI args and calling into the library, say — would not be caught here.
#[test]
fn the_binary_reports_a_malformed_fleet_file_as_a_clean_error_not_a_panic() {
    let dir = std::env::temp_dir().join(format!(
        "occultation-robustness-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let bad_fleet = dir.join("malformed.toml");
    std::fs::write(&bad_fleet, "[[[[not valid toml at all").expect("write fixture");

    let out = std::process::Command::new(env!("CARGO_BIN_EXE_occultation"))
        .args(["anonymity", "--fleet"])
        .arg(&bad_fleet)
        .output()
        .expect("the binary runs");

    std::fs::remove_dir_all(&dir).ok();

    assert_eq!(
        out.status.code(),
        Some(2),
        "malformed input must exit 2, not panic: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.starts_with("error:"),
        "must print a clean error, not a panic backtrace: {stderr}"
    );
    assert!(!stderr.contains("panicked"), "must not panic: {stderr}");
}
