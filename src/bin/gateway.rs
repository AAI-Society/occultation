use anyhow::Result;
use clap::Parser;
use occultation::gateway::config::GatewayConfig;
use occultation::gateway::proxy::{serve, Hooks};
use std::net::SocketAddr;

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
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();
    let cli = Cli::parse();
    let cfg = GatewayConfig {
        listen: cli.listen,
        upstream: cli.upstream,
        salt_rotation: cli.salt_rotation.into(),
        pccs_url: cli.pccs_url,
    };
    serve(cfg, Hooks::noop()).await?;
    Ok(())
}
