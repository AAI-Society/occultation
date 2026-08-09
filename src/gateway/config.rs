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
    /// How long a connection has to finish sending its request headers
    /// before the gateway closes it. See
    /// [`proxy::DEFAULT_HEADER_READ_TIMEOUT`](crate::gateway::proxy::DEFAULT_HEADER_READ_TIMEOUT).
    #[serde(with = "humantime_serde", default = "default_header_read_timeout")]
    pub header_read_timeout: Duration,
    /// How many connections the proxy serves at once. See
    /// [`proxy::DEFAULT_MAX_CONNECTIONS`](crate::gateway::proxy::DEFAULT_MAX_CONNECTIONS).
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
}

/// Defaulted rather than required, so a configuration written before these
/// two bounds existed still deserializes — and deserializes into a gateway
/// that has them, which is the direction that matters.
fn default_header_read_timeout() -> Duration {
    crate::gateway::proxy::DEFAULT_HEADER_READ_TIMEOUT
}

/// See [`default_header_read_timeout`].
fn default_max_connections() -> usize {
    crate::gateway::proxy::DEFAULT_MAX_CONNECTIONS
}
