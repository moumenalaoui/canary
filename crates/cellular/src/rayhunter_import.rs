//! Import of the JSON document emitted by the external `rayhunter-check` CLI.
//!
//! Our only interface to that tool is the *shape of the JSON it prints*:
//! nothing here depends on, links against, or reproduces any Rayhunter code,
//! and nothing runs it as a subprocess. The types below are our own serde
//! mirrors of that shape, and [`import_report`] converts it into CANARY's
//! vocabulary from `canary-core`.
//!
//! Imports are mapped conservatively. Upstream severity is carried across for
//! the record, but it never lifts confidence on its own: an un-corroborated
//! third-party finding is at most [`Confidence::Suspicious`], never
//! [`Confidence::Confirmed`]. Confirmation belongs to later multi-signal
//! analysis, which does not exist yet.

use std::fs;
use std::path::{Path, PathBuf};

use canary_core::{Anomaly, Confidence, Report, Severity, Source};
use chrono::{DateTime, FixedOffset};
use serde::Deserialize;

/// One `rayhunter-check` document: a capture plus the reports made from it.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct RayhunterFile {
    /// Capture path for the document as a whole. We read it to mirror the
    /// document, but each report carries its own `path`, and that is what a
    /// [`Report::capture_path`] is taken from.
    #[serde(default)]
    pub path: String,
    /// Free-form tool and version metadata. Deliberately not modelled — we do
    /// not consume any of it yet, and its internals are the upstream tool's
    /// business.
    #[serde(default)]
    pub metadata: serde_json::Value,
    /// The reports in the document; each becomes one [`Report`].
    pub reports: Vec<RayhunterReport>,
}

/// Upstream's analysis of a single capture.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct RayhunterReport {
    /// The capture these events were found in.
    pub path: String,
    /// Packets upstream could not parse, so were never examined.
    pub skipped: u64,
    /// Upstream's findings, in the order it reported them.
    pub events: Vec<RayhunterEventWithTimestamp>,
}

/// An upstream finding paired with when it was observed.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct RayhunterEventWithTimestamp {
    pub event: RayhunterEvent,
    /// RFC 3339, carrying the capture's original UTC offset.
    pub timestamp: DateTime<FixedOffset>,
}

/// A single upstream finding.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct RayhunterEvent {
    pub event_type: RayhunterEventType,
    /// Upstream's human-readable description of the finding.
    pub message: String,
}

/// Upstream's severity scale, spelled exactly as its JSON spells it.
///
/// Kept separate from [`Severity`] on purpose: the wire vocabulary stays a
/// faithful mirror of a foreign format, and `canary-core` stays free of
/// another tool's naming.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum RayhunterEventType {
    Informational,
    Low,
    Medium,
    High,
}

impl RayhunterEventType {
    /// Upstream's own judgement, carried across unchanged.
    pub fn severity(self) -> Severity {
        match self {
            RayhunterEventType::Informational => Severity::Informational,
            RayhunterEventType::Low => Severity::Low,
            RayhunterEventType::Medium => Severity::Medium,
            RayhunterEventType::High => Severity::High,
        }
    }

    /// CANARY's certainty about an imported finding of this type.
    ///
    /// Only `High` earns more than `Unconfirmed`, and nothing earns
    /// `Confirmed`: a single tool's finding is never corroborated by
    /// definition here.
    pub fn confidence(self) -> Confidence {
        match self {
            RayhunterEventType::High => Confidence::Suspicious,
            RayhunterEventType::Informational
            | RayhunterEventType::Low
            | RayhunterEventType::Medium => Confidence::Unconfirmed,
        }
    }
}

/// Why a document could not be imported.
#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    /// The file could not be read.
    #[error("could not read rayhunter JSON from {path:?}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    /// The file was read, but was not a `rayhunter-check` document we
    /// recognise — including an unrecognised `event_type`.
    #[error("could not parse rayhunter JSON from {path:?}: {source}")]
    Json {
        path: PathBuf,
        source: serde_json::Error,
    },
}

/// Import every report from the `rayhunter-check` JSON document at
/// `json_path`.
///
/// One CANARY [`Report`] per upstream report, which is why this returns a
/// [`Vec`]: a single document can cover more than one capture.
pub fn import_report(json_path: &Path) -> Result<Vec<Report>, ImportError> {
    let text =
        fs::read_to_string(json_path).map_err(|source| ImportError::Io {
            path: json_path.to_path_buf(),
            source,
        })?;
    let file: RayhunterFile =
        serde_json::from_str(&text).map_err(|source| ImportError::Json {
            path: json_path.to_path_buf(),
            source,
        })?;

    Ok(file.reports.iter().map(report_from).collect())
}

/// Convert one upstream report into a CANARY report.
fn report_from(report: &RayhunterReport) -> Report {
    Report {
        capture_path: report.path.clone(),
        anomalies: report.events.iter().map(anomaly_from).collect(),
        skipped: report.skipped,
    }
}

/// Convert one upstream event into an anomaly: severity is carried across,
/// confidence is assigned by the conservative mapping.
fn anomaly_from(event: &RayhunterEventWithTimestamp) -> Anomaly {
    let event_type = event.event.event_type;

    Anomaly {
        timestamp: event.timestamp,
        what: event.event.message.clone(),
        severity: Some(event_type.severity()),
        confidence: event_type.confidence(),
        source: Source::RayhunterImport,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The document under test: one report, two events, spanning the
    /// Informational and High ends of the scale.
    const FIXTURE: &str = r#"{
  "path": "test.qmdl",
  "metadata": {"report_version": 2, "analyzers": []},
  "reports": [
    { "path": "test.qmdl", "skipped": 2, "warnings": 2, "events": [
      { "event": {"event_type":"Informational","message":"Tower seen: PLMN 310260"},
        "timestamp":"2026-10-24T14:03:21-04:00" },
      { "event": {"event_type":"High","message":"IMSI requested without authentication"},
        "timestamp":"2026-10-24T14:05:10-04:00" }
    ]}
  ]
}"#;

    /// Write `contents` to a temp file, returning it so the caller keeps it
    /// alive for as long as its path is in use.
    fn temp_document(contents: &str) -> tempfile::NamedTempFile {
        use std::io::Write;

        let mut file = tempfile::NamedTempFile::new().expect("temp file");
        file.write_all(contents.as_bytes())
            .expect("write temp file");
        file.flush().expect("flush temp file");
        file
    }

    #[test]
    fn imports_reports_and_maps_confidence_conservatively() {
        let document = temp_document(FIXTURE);

        let reports = import_report(document.path()).expect("fixture imports");

        assert_eq!(reports.len(), 1, "one upstream report, one Report");
        let report = &reports[0];
        assert_eq!(report.capture_path, "test.qmdl");
        assert_eq!(report.skipped, 2);

        assert_eq!(report.anomalies.len(), 2);
        let informational = &report.anomalies[0];
        let high = &report.anomalies[1];

        // Both anomalies are attributed to the import, never to CANARY's own
        // analysis.
        assert_eq!(informational.source, Source::RayhunterImport);
        assert_eq!(high.source, Source::RayhunterImport);

        // Timestamps and messages come straight through.
        assert_eq!(
            informational.timestamp.to_rfc3339(),
            "2026-10-24T14:03:21-04:00"
        );
        assert_eq!(informational.what, "Tower seen: PLMN 310260");
        assert_eq!(high.what, "IMSI requested without authentication");

        // Severity is carried across as upstream judged it...
        assert_eq!(informational.severity, Some(Severity::Informational));
        assert_eq!(high.severity, Some(Severity::High));

        // ...while confidence stays where we put it: Informational is not
        // evidence, High is only suspicious on its own.
        assert_eq!(informational.confidence, Confidence::Unconfirmed);
        assert_eq!(high.confidence, Confidence::Suspicious);

        // The safety invariant, stated directly: nothing imported here is
        // ever confirmed.
        assert!(
            !report
                .anomalies
                .iter()
                .any(|a| a.confidence == Confidence::Confirmed),
            "imported anomalies must never be Confirmed"
        );
    }

    #[test]
    fn unrecognised_event_type_is_a_parse_error() {
        // Pinning the *variant*, not just "some error": an event type we have
        // never seen must be reported as unparseable rather than silently
        // mapped to a lower severity or dropped.
        let document = temp_document(
            r#"{
  "path": "other.qmdl",
  "metadata": {},
  "reports": [
    { "path": "other.qmdl", "skipped": 0, "warnings": 0, "events": [
      { "event": {"event_type":"Critical","message":"unknown upstream severity"},
        "timestamp":"2026-10-24T14:03:21-04:00" }
    ]}
  ]
}"#,
        );

        let error = import_report(document.path())
            .expect_err("an unknown event_type must not import");

        assert!(
            matches!(error, ImportError::Json { .. }),
            "expected ImportError::Json, got {error:?}"
        );
    }

    #[test]
    fn missing_file_is_an_io_error() {
        let path = std::env::temp_dir().join("canary-absent-rayhunter-document.json");
        assert!(
            !path.exists(),
            "nothing should have created {:?}",
            path
        );

        let error = import_report(&path).expect_err("a missing file must not import");

        assert!(
            matches!(error, ImportError::Io { .. }),
            "expected ImportError::Io, got {error:?}"
        );
    }
}
