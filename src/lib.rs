//! Measure what verifiable unlinkability costs at agent action rates.
//!
//! Supporting tool for **P05 — Accountable but Unlinkable Agent Identity**.
//!
//! Read `README.md` before trusting any output of this crate: parts of it are
//! real cryptography, parts are real but not interoperable, and parts are
//! modelled and provide no security whatsoever.
#![forbid(unsafe_code)]

pub mod cost;

pub use cost::{compose, BudgetVerdict, Composed, CostProfile, Measurement, Source, BUDGET};
