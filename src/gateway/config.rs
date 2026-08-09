use serde::Deserialize;
use std::net::SocketAddr;
use std::time::Duration;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayConfig {
    pub listen: SocketAddr,
    #[serde(with = "http_serde::uri")]
    pub upstream: hyper::Uri,
    /// How often the meter's salt rotates, ageing out correlation.
    #[serde(with = "humantime_serde")]
    pub salt_rotation: Duration,
    /// Provisioning Certification Caching Service, for collateral.
    pub pccs_url: String,
}
