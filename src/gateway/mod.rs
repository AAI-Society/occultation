//! A fail-open reverse proxy that measures what a relying party learns.
//!
//! Forwards every request. Measures alongside. Never rejects — `--enforce`
//! does not exist in phase 1.

pub mod config;
pub mod proxy;
