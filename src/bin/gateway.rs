use anyhow::Result;
use clap::Parser;
use occultation::gateway::collateral::CollateralCache;
use occultation::gateway::config::GatewayConfig;
use occultation::gateway::finding::Metrics;
use occultation::gateway::meter::LinkabilityMeter;
use occultation::gateway::pipeline::{LogSink, Pipeline};
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

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let cli = Cli::parse();
    let cfg = GatewayConfig {
        listen: cli.listen,
        upstream: cli.upstream,
        salt_rotation: cli.salt_rotation.into(),
        pccs_url: cli.pccs_url,
    };

    let cache = Arc::new(CollateralCache::new(
        cfg.pccs_url.clone(),
        cli.collateral_ttl.into(),
    ));
    let meter = Arc::new(LinkabilityMeter::new(cfg.salt_rotation, os_seed()));

    // The only handle that can fetch goes to the background task, and the
    // only handle the request path gets back is a queue. `QuoteVerifier` gets
    // a handle too, but it can only ever call the cache's synchronous,
    // offline `get`.
    let queue = refresh::spawn(Arc::clone(&cache), Arc::clone(&meter), cfg.salt_rotation);

    // Registered but not yet served: exposing a scrape endpoint is Task 8's,
    // and it must not be reachable through the proxy's forwarding path. The
    // registry is held here so the counters stay registered for it.
    let mut registry = Registry::default();
    let metrics = Arc::new(Metrics::new(&mut registry));

    let pipeline = Arc::new(Pipeline {
        source: Arc::new(HeaderSource::new(&cli.attestation_header)),
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
}
