//! A fail-open reverse proxy that measures what a relying party learns.
//!
//! Forwards every request. Measures alongside. Never rejects — `--enforce`
//! does not exist in phase 1.
//!
//! The whole guarantee rests on a hook panic unwinding rather than
//! terminating the process (see `proxy::handle`'s use of `catch_unwind`).
//! That assumption is `panic = "unwind"`, which is the default — adding
//! `panic = "abort"` to any profile in `Cargo.toml` turns a hook panic into
//! a process abort and silently voids this entire guarantee.

pub mod config;
pub mod proxy;
pub mod source;
