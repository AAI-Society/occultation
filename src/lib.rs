//! Measure what verifiable unlinkability costs at agent action rates.
//!
//! Supporting tool for **P05 — Accountable but Unlinkable Agent Identity**.
//!
//! Read `README.md` before trusting any output of this crate: parts of it are
//! real cryptography, parts are real but not interoperable, and parts are
//! modelled and provide no security whatsoever.
#![forbid(unsafe_code)]

pub mod baseline;
pub mod cost;
pub mod harness;

pub use cost::{
    compose, fmt_ms, judge, BudgetVerdict, Composed, CostProfile, Measurement, Source, BUDGET,
};
