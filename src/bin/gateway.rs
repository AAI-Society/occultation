use anyhow::Result;
use clap::Parser;
use occultation::gateway::collateral::CollateralCache;
use occultation::gateway::config::GatewayConfig;
use occultation::gateway::finding::Metrics;
use occultation::gateway::meter::LinkabilityMeter;
use occultation::gateway::pipeline::{LogSink, Pipeline, SINK_LOG_LEVEL};
use occultation::gateway::proxy::{serve, Hooks};
use occultation::gateway::refresh;
use occultation::gateway::source::HeaderSource;
use occultation::gateway::verify::QuoteVerifier;
use prometheus_client::registry::Registry;
use std::net::SocketAddr;
use std::sync::Arc;

/// A fail-open reverse proxy that measures what a relying party learns.
///
/// Forwards every request. Measures alongside. Never rejects — `--enforce`
/// does not exist in phase 1.
#[derive(Parser)]
#[command(
    name = "occultation-gateway",
    version,
    about = "Fail-open reverse proxy that measures what a relying party learns"
)]
struct Cli {
    /// Address the gateway accepts connections on
    #[arg(long)]
    listen: SocketAddr,
    /// The relying party's API the gateway forwards every request to
    #[arg(long)]
    upstream: hyper::Uri,
    /// Provisioning Certification Caching Service, for attestation collateral
    #[arg(long)]
    pccs_url: String,
    /// How often the meter's salt rotates, ageing out correlation
    #[arg(long, default_value = "1h")]
    salt_rotation: humantime::Duration,
    /// Request header the attestation arrives in
    #[arg(long, default_value = "x-attestation")]
    attestation_header: String,
    /// How long cached collateral stays usable before a quote against it is
    /// reported `Unverified` rather than verified against possibly-revoked
    /// TCB data
    #[arg(long, default_value = "6h")]
    collateral_ttl: humantime::Duration,
}

/// A per-process meter seed drawn from the operating system's entropy, not
/// from anything in the configuration.
///
/// `meter.rs` is explicit that the salt is a pure function of this seed, so a
/// seed derived from a config file (a hash of the upstream URL, the listen
/// port, a fixed constant) would make the salt derivable from that file
/// alone, and every rotation epoch predictable with it. `RandomState`'s keys
/// come from the platform's randomness on first use, which is the strongest
/// source reachable without adding a dependency — `rand_core` is pinned at
/// 0.6 here for `blstrs`'s sake and its `OsRng` is not enabled.
fn os_seed() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish()
}

/// The default `RUST_LOG` filter, derived from the level [`LogSink`] emits at
/// rather than written as a literal.
///
/// This is not cosmetic. Until a metrics endpoint exists, the log is the
/// gateway's *only* output channel: a default filter below `SINK_LOG_LEVEL`
/// produces a gateway that forwards perfectly and reports nothing at all,
/// with no error anywhere to say so. Deriving both ends from one constant is
/// what stops the two drifting apart — see
/// `the_default_log_filter_is_derived_from_the_sinks_level`.
fn default_log_filter() -> String {
    SINK_LOG_LEVEL.as_str().to_ascii_lowercase()
}

/// Reject an attestation header name that no request could ever match.
///
/// `HeaderSource::new` lowercases but does not validate, and `HeaderMap::get`
/// with an invalid name returns `None` rather than failing. So
/// `--attestation-header "x attestation"` yields a gateway that reports "no
/// attestation accompanied this request" for every request, forever, with no
/// startup error and no way to tell it from a client that never sends one.
/// Caught here, where an operator reads the message.
fn valid_header_name(name: &str) -> Result<String> {
    hyper::header::HeaderName::from_bytes(name.as_bytes())
        .map(|parsed| parsed.as_str().to_string())
        .map_err(|_| {
            anyhow::anyhow!(
                "--attestation-header {name:?} is not a valid HTTP header name, so no \
                 request could ever carry it and every request would be reported as \
                 carrying no attestation"
            )
        })
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(default_log_filter()),
    )
    .init();
    let cli = Cli::parse();
    let cfg = GatewayConfig {
        listen: cli.listen,
        upstream: cli.upstream,
        salt_rotation: cli.salt_rotation.into(),
        pccs_url: cli.pccs_url,
    };
    let attestation_header = valid_header_name(&cli.attestation_header)?;

    let cache = Arc::new(CollateralCache::new(
        cfg.pccs_url.clone(),
        cli.collateral_ttl.into(),
    ));
    let meter = Arc::new(LinkabilityMeter::new(cfg.salt_rotation, os_seed()));

    // The only handle that can fetch goes to the background task, and the
    // only handle the request path gets back is a queue. `QuoteVerifier` gets
    // a handle too, but it can only ever call the cache's synchronous,
    // offline `get`.
    //
    // Fallible: `spawn` refuses a salt rotation short enough to make the
    // meter report every request as an anonymity set of one. A configuration
    // mistake that would make the tool lie is a startup failure, the same
    // shape as `serve`'s `https://` upstream check. It reads the interval off
    // the meter rather than taking one here, so there is no second copy of
    // the value for this call site to get wrong.
    let queue = refresh::spawn(Arc::clone(&cache), Arc::clone(&meter))?;

    // Registered but not yet served: exposing a scrape endpoint is Task 8's,
    // and it must not be reachable through the proxy's forwarding path. The
    // registry is held here so the counters stay registered for it.
    let mut registry = Registry::default();
    let metrics = Arc::new(Metrics::new(&mut registry));

    let pipeline = Arc::new(Pipeline {
        source: Arc::new(HeaderSource::new(&attestation_header)),
        verifier: Arc::new(QuoteVerifier::new(cache)),
        meter,
        metrics,
        sink: Arc::new(LogSink),
        refresh: queue,
    });

    serve(cfg, Hooks::from_pipeline(pipeline)).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The salt is a pure function of this seed, so a constant — or anything
    /// derived from the configuration — would make every rotation epoch's
    /// salt derivable by anyone holding the config. Two calls differing is
    /// the cheapest observable that distinguishes real entropy from `0`,
    /// from a hash of the listen address, or from a build-time constant.
    #[test]
    fn the_meter_seed_is_not_a_constant() {
        assert_ne!(os_seed(), os_seed());
        assert_ne!(os_seed(), 0);
    }

    /// clap's own consistency check. A misspelled `default_value` or a
    /// duplicated short flag is a startup failure for a binary whose whole
    /// job is being up.
    #[test]
    fn the_command_line_is_well_formed() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }

    /// The gateway's only output channel must be open by default.
    ///
    /// Two halves, because either alone is escapable: the derived string has
    /// to parse to a filter at or above the sink's level, *and* `main` has to
    /// actually use it rather than a literal that drifted from it. The second
    /// half is a source check for the same reason `verify.rs`'s formatter ban
    /// is one — `default_filter_or("warn")` is a one-word edit that no
    /// behavioural test in this crate would notice.
    #[test]
    fn the_default_log_filter_is_derived_from_the_sinks_level() {
        let filter: log::LevelFilter = default_log_filter()
            .parse()
            .expect("the derived default filter is a filter env_logger accepts");
        assert!(
            filter >= SINK_LOG_LEVEL.to_level_filter(),
            "the default filter {filter} silences the sink at {SINK_LOG_LEVEL}"
        );

        let src = include_str!("gateway.rs");
        const MARKER: &str = "#[cfg(test)]\nmod tests {";
        assert_eq!(src.matches(MARKER).count(), 1, "ambiguous test module");
        let non_test = src.split(MARKER).next().expect("split yields a head");
        assert!(
            non_test.contains("fn main"),
            "the scanned region does not reach main"
        );
        assert!(
            non_test.contains("default_filter_or(default_log_filter())"),
            "main no longer derives its default filter from SINK_LOG_LEVEL"
        );
        assert!(
            !non_test.contains("default_filter_or(\""),
            "main hard-codes a log level literal, which can drift below the sink's"
        );
    }

    /// A header name no request could ever carry produces a gateway that
    /// reports "no attestation" forever. That must be a startup error, not a
    /// discovery.
    ///
    /// The source check is the load-bearing half. `valid_header_name` passing
    /// its own unit tests says nothing about whether `main` calls it — delete
    /// the call, pass `&cli.attestation_header` straight to `HeaderSource`,
    /// and every behavioural test in this crate stays green. Compare
    /// `refresh::spawn`, which was made fallible and so has its call site
    /// enforced by the compiler; that is the strong form and this is not
    /// available to it, because a validator that returns a `String` the
    /// caller may simply ignore has no type-level hold on being used.
    #[test]
    fn an_unusable_attestation_header_is_refused_at_startup() {
        let src = include_str!("gateway.rs");
        const MARKER: &str = "#[cfg(test)]\nmod tests {";
        let non_test = src.split(MARKER).next().expect("split yields a head");
        assert!(
            non_test.contains("fn main"),
            "the scanned region does not reach main"
        );
        assert!(
            non_test.contains("valid_header_name(&cli.attestation_header)"),
            "main no longer validates the attestation header name"
        );
        assert!(
            !non_test.contains("HeaderSource::new(&cli.attestation_header)"),
            "main passes the raw command-line value straight to HeaderSource, \
             bypassing validation"
        );

        for bad in ["x attestation", "x:attestation", "", "x\nattestation"] {
            assert!(
                valid_header_name(bad).is_err(),
                "{bad:?} was accepted as a header name"
            );
        }
        // The positive half: ordinary names, in any case, must still work and
        // must come back canonicalized the way `HeaderMap` stores them.
        assert_eq!(
            valid_header_name("X-Attestation").expect("a valid name"),
            "x-attestation"
        );
        assert_eq!(
            valid_header_name("x-attestation").expect("a valid name"),
            "x-attestation"
        );
    }
}
