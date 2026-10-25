//! The shared vocabulary every CANARY front-end produces.
//!
//! CANARY turns captures into [`Anomaly`] values and bundles them into a
//! [`Report`]. Whether an anomaly came from an imported third-party tool or
//! from CANARY's own analysis, it is described with these types so later
//! stages never have to care who produced it.
//!
//! Two independent axes matter here, and they are deliberately not the same
//! thing:
//!
//! - [`Severity`] — how bad a signal would be *if it is genuine*. This is the
//!   scale used by upstream tooling we import from, so imported data carries
//!   it.
//! - [`Confidence`] — how sure CANARY is that the signal really indicates a
//!   catcher. This is ours alone.
//!
//! A `High` severity event is not automatically `Confirmed`: confirmation
//! requires corroboration across independent signals, which an imported
//! single-tool observation cannot provide. See
//! `canary_cellular::rayhunter_import` for the conservative mapping we apply
//! on the way in.

use chrono::{DateTime, FixedOffset};
use serde::{Deserialize, Serialize};

/// How impactful an observation would be if it is genuine.
///
/// Mirrors the scale used by the external tooling we import from; it says
/// nothing about whether CANARY believes the observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Severity {
    /// Worth recording, but not suspicious on its own.
    Informational,
    /// Weakly suggestive.
    Low,
    /// Meaningful on its own, more convincing when corroborated.
    Medium,
    /// Strongly indicative of a catcher if genuine.
    High,
}

/// How sure CANARY is that an anomaly reflects a real catcher.
///
/// This is CANARY's own axis and is separate from [`Severity`]. Imported data
/// is never [`Confidence::Confirmed`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Confidence {
    /// Recorded, but nothing here lets us judge it either way.
    Unconfirmed,
    /// Plausibly a real catcher; not corroborated enough to call it one.
    Suspicious,
    /// Corroborated across independent signals. CANARY-only.
    Confirmed,
}

/// Which component produced an anomaly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Source {
    /// Imported from the external `rayhunter-check` JSON output.
    RayhunterImport,
    /// Produced by CANARY's own cellular analysis.
    CanaryCellular,
    /// Produced by CANARY's own network analysis.
    CanaryNetwork,
}

/// A single observation that may indicate a catcher.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Anomaly {
    /// When the underlying observation was made, with its original offset.
    pub timestamp: DateTime<FixedOffset>,
    /// Human-readable description of what was observed.
    pub what: String,
    /// Set when the observation came from a severity-based tool such as an
    /// import, and `None` when CANARY produced it without that judgement.
    pub severity: Option<Severity>,
    /// CANARY's own certainty. Never `Confirmed` for imported data.
    pub confidence: Confidence,
    /// Which component produced this.
    pub source: Source,
}

/// The anomalies found in one capture, together with how much of the capture
/// the producing tool could not parse.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Report {
    /// Path of the capture this report describes, as named by the producing
    /// tool.
    pub capture_path: String,
    /// One anomaly per observation.
    pub anomalies: Vec<Anomaly>,
    /// Packets the producing tool skipped because it could not parse them.
    /// A high count means the anomalies above are from partial coverage.
    pub skipped: u64,
}
