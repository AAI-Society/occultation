use anyhow::Result;
use clap::Parser;
use occultation::gateway::collateral::{self, CollateralCache};
use occultation::gateway::config::GatewayConfig;
use occultation::gateway::finding::Metrics;
use occultation::gateway::meter::LinkabilityMeter;
use occultation::gateway::pipeline::{LogSink, Pipeline, SINK_LOG_LEVEL};
use occultation::gateway::proxy::{self, serve, Hooks};
use occultation::gateway::refresh;
use occultation::gateway::scrape;
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
    /// Address the Prometheus scrape endpoint listens on, separately from
    /// `--listen`. Loopback by default; a `/metrics` route on the proxy port
    /// would carve a path out of the upstream's URL space, so it is a second
    /// listener rather than a route
    #[arg(long, default_value = scrape::DEFAULT_METRICS_LISTEN)]
    metrics_listen: SocketAddr,
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
    /// How long a client has to finish sending its request headers before
    /// the gateway closes the connection. Without this a single client
    /// holding half-open connections exhausts the process's file descriptors
    /// and the fronted API becomes unreachable
    #[arg(long, default_value = "30s")]
    header_read_timeout: humantime::Duration,
    /// How many connections the proxy serves at once. Not a rate limit and
    /// it refuses nothing: past the cap, connections wait in the listen
    /// backlog and are served as earlier ones finish
    #[arg(
        long,
        default_value_t = proxy::DEFAULT_MAX_CONNECTIONS as u32,
        value_parser = clap::value_parser!(u32).range(1..)
    )]
    max_connections: u32,
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
    // Checked before anything is bound or spawned, for the same reason
    // `validate_upstream` runs before the bind: an operator learns about a
    // value that would take their API down at startup, not from whoever
    // notices the outage.
    proxy::validate_header_read_timeout(cli.header_read_timeout.into())?;
    collateral::validate_ttl(cli.collateral_ttl.into())?;
    let cfg = GatewayConfig {
        listen: cli.listen,
        upstream: cli.upstream,
        salt_rotation: cli.salt_rotation.into(),
        pccs_url: cli.pccs_url,
        header_read_timeout: cli.header_read_timeout.into(),
        max_connections: cli.max_connections as usize,
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

    let mut registry = Registry::default();
    let metrics = Arc::new(Metrics::new(&mut registry));

    // Served on a listener of its own, never through the forwarding path —
    // see `scrape.rs`'s module docs for why a `/metrics` route on the proxy
    // port cannot be made to work without breaking either fail-open or the
    // upstream's URL space.
    //
    // A bind failure is a startup decision and not a request-path one, and
    // the decision is to run anyway. This gateway sits in front of somebody
    // else's API; refusing to start because port 9469 was already taken would
    // take that API down to protect a counter. Loud, and then onward.
    // Defence in depth only — the loopback default is pinned by two tests —
    // but an operator who binds this off-host should learn it from a log line
    // now rather than from whoever finds the port later. The counters carry no
    // per-counterparty data by construction, and they do describe a fleet's
    // TCB diversity, which is the thing this whole tool exists to say is
    // sensitive.
    if !cli.metrics_listen.ip().is_loopback() {
        log::warn!(
            "the metrics listener is bound to {}, which is not loopback: the \
             gateway's TCB-diversity counters will be readable by anything \
             that can route to this host, and nothing authenticates a scrape",
            cli.metrics_listen
        );
    }
    match scrape::bind(cli.metrics_listen).await {
        Ok(listener) => {
            log::info!(
                "metrics available at http://{}{}",
                cli.metrics_listen,
                scrape::METRICS_PATH
            );
            tokio::spawn(scrape::serve_on(listener, Arc::new(registry)));
        }
        Err(err) => log::error!(
            "could not bind the metrics listener on {}: {err}. The gateway is \
             starting anyway and will forward and measure as usual, but nothing \
             can scrape it — the log is the only output channel until this is fixed",
            cli.metrics_listen
        ),
    }

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

    /// The counters have to actually be served, and that is a property of
    /// `main` alone.
    ///
    /// This is the mutation the integration suite cannot see. Delete the
    /// `tokio::spawn(scrape::serve_on(..))` below and every test in this
    /// crate stays green — `tests/gateway_hostile.rs` binds its own listener
    /// and calls `serve_on` itself, exactly as Task 7's suite calls
    /// `proxy::serve_on`, so none of them exercises this call site. The
    /// result would be a gateway that registers three counters, records to
    /// them on every request, and exposes them to nobody: precisely the state
    /// this task exists to fix, restored by a one-line deletion.
    ///
    /// Source-checked for the same reason
    /// `the_default_log_filter_is_derived_from_the_sinks_level` is, and with
    /// the same acknowledged weakness: a validator or a spawn the caller may
    /// simply drop has no type-level hold on being used.
    #[test]
    fn main_serves_the_metrics_on_a_listener_of_its_own() {
        let src = include_str!("gateway.rs");
        const MARKER: &str = "#[cfg(test)]\nmod tests {";
        assert_eq!(src.matches(MARKER).count(), 1, "ambiguous test module");
        let non_test = src.split(MARKER).next().expect("split yields a head");
        assert!(
            non_test.contains("fn main"),
            "the scanned region does not reach main"
        );
        assert!(
            non_test.contains("scrape::bind(cli.metrics_listen)"),
            "main no longer binds the metrics listener"
        );
        assert!(
            non_test.contains("tokio::spawn(scrape::serve_on(listener,"),
            "main binds the metrics listener but never serves on it, so the \
             counters stay write-only"
        );
        // ...and it is a *separate* listener. Binding the scrape endpoint on
        // `cfg.listen` would either fail (the proxy already has that port) or,
        // if the ordering were ever reversed, take the proxy's port away.
        assert!(
            !non_test.contains("scrape::bind(cli.listen)")
                && !non_test.contains("scrape::bind(cfg.listen)"),
            "the scrape endpoint must not share the proxy's listen address"
        );
    }

    /// A bind failure must not stop the gateway starting.
    ///
    /// The gateway fronts somebody else's API. Refusing to start because the
    /// metrics port was taken would take that API down to protect a counter,
    /// which is the exact inversion of this crate's one hard guarantee. The
    /// `?` operator is one character and would do it silently, so the absence
    /// of one on this call is the property being pinned.
    #[test]
    fn a_metrics_bind_failure_does_not_stop_the_gateway_starting() {
        let src = include_str!("gateway.rs");
        const MARKER: &str = "#[cfg(test)]\nmod tests {";
        let non_test = src.split(MARKER).next().expect("split yields a head");
        assert!(
            !non_test.contains("scrape::bind(cli.metrics_listen).await?"),
            "a bind failure on the metrics port must not abort startup; the \
             gateway's job is being up"
        );
        assert!(
            non_test.contains("Err(err) => log::error!("),
            "a bind failure must be logged loudly rather than swallowed — a \
             silently absent scrape endpoint is indistinguishable from a \
             gateway that is measuring nothing"
        );
    }

    /// The default scrape address must stay loopback, and must stay *derived*
    /// from the constant `scrape.rs` pins as loopback rather than repeated as
    /// a literal here. Two copies of an address is how one of them becomes
    /// `0.0.0.0` — which publishes a fleet's TCB-diversity counters to
    /// anything that can route to the host.
    #[test]
    fn the_default_metrics_address_is_the_loopback_constant_not_a_literal() {
        let src = include_str!("gateway.rs");
        const MARKER: &str = "#[cfg(test)]\nmod tests {";
        let non_test = src.split(MARKER).next().expect("split yields a head");
        assert!(
            non_test.contains("default_value = scrape::DEFAULT_METRICS_LISTEN"),
            "the default metrics address is no longer derived from scrape.rs"
        );
        let addr: SocketAddr = scrape::DEFAULT_METRICS_LISTEN
            .parse()
            .expect("the default metrics address parses");
        assert!(addr.ip().is_loopback(), "{addr} is not loopback");
    }

    /// Two more configuration values that start cleanly and produce a
    /// useless gateway, checked at the one place an operator finds out in
    /// time.
    ///
    /// `--collateral-ttl 0s` yields a gateway reporting `Unverified` for
    /// every quote forever, indistinguishable in the log from an unreachable
    /// provisioning service. `--header-read-timeout 0s` closes every
    /// connection on arrival, which is the fronted API down — the outage the
    /// timeout exists to prevent, reached from the other side.
    ///
    /// Source-checked for the same reason
    /// `an_unusable_attestation_header_is_refused_at_startup` is, and with
    /// the same acknowledged weakness: a validator returning `Result<(), _>`
    /// that `main` may simply not call has no type-level hold on being
    /// called. `refresh::spawn` is the strong form and neither of these can
    /// take it — there is no value they produce that `main` has to consume.
    /// `proxy::run` and `CollateralCache` clamp what they can independently;
    /// this is the half that reaches the operator.
    #[test]
    fn a_zero_collateral_ttl_or_header_read_timeout_is_refused_at_startup() {
        let src = include_str!("gateway.rs");
        const MARKER: &str = "#[cfg(test)]\nmod tests {";
        let non_test = src.split(MARKER).next().expect("split yields a head");
        assert!(
            non_test.contains("fn main"),
            "the scanned region does not reach main"
        );
        assert!(
            non_test
                .contains("proxy::validate_header_read_timeout(cli.header_read_timeout.into())?"),
            "main no longer refuses a header-read timeout that would close \
             every connection on arrival"
        );
        assert!(
            non_test.contains("collateral::validate_ttl(cli.collateral_ttl.into())?"),
            "main no longer refuses a collateral TTL that would report \
             Unverified for every quote forever"
        );
        // Both are checked before anything is bound or spawned, so an
        // operator gets the error instead of a running, useless gateway.
        let ttl_check = non_test
            .find("collateral::validate_ttl")
            .expect("the ttl check is present");
        for later in [
            "scrape::bind(",
            "refresh::spawn(",
            "TcpListener",
            "serve(cfg",
        ] {
            if let Some(at) = non_test.find(later) {
                assert!(
                    ttl_check < at,
                    "the startup checks run after `{later}`, so a bad value \
                     stands something up before it is caught"
                );
            }
        }
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
