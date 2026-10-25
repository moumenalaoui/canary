//! Reconstruct the LTE NAS signaling sequence of a PCAP capture.
//!
//!     canary-cellular-nas <capture.pcap>
//!
//! Reads the capture as a stream — records are pulled off disk one at a time and
//! dropped — and prints one line per NAS message, then the counts that make the
//! sequence readable at a glance.
//!
//! The per-kind and per-code tables are what the oracle comparison in `scripts/`
//! diffs against `tshark`, so each is a count and then the thing counted, in a
//! stable order: alphabetical by label, ascending by message code. Sorting by
//! count would shuffle the table between two runs of the same file, and a table
//! you cannot diff is not a comparison.
//!
//! Nothing here decides whether anything is a catcher. This is the input stage:
//! it reports what signaling occurred, and stops at the message type.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;
use std::process::ExitCode;

use chrono::SecondsFormat;

use canary_cellular::gsmtap::{LTE_NAS_TYPE, LTE_RRC_TYPE};
use canary_cellular::nas_stream::{self, ParseError, StreamStats};
use canary_cellular::signaling::SignalingKind;

fn main() -> ExitCode {
    const USAGE: &str = "usage: canary-cellular-nas <capture.pcap>";

    let mut args = std::env::args().skip(1);
    let Some(capture_path) = args.next() else {
        eprintln!("{USAGE}");
        return ExitCode::FAILURE;
    };
    if let Some(extra) = args.next() {
        eprintln!("error: unexpected extra argument {extra:?}");
        eprintln!("{USAGE}");
        return ExitCode::FAILURE;
    }

    // Opening the file is the one step that is not a property of the capture's
    // contents, so it gets its own sentence rather than arriving as the first
    // item of the stream.
    let path = Path::new(&capture_path);
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) => {
            eprintln!("error: cannot open {}: {error}", path.display());
            return ExitCode::FAILURE;
        }
    };

    let stdout = std::io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    let run = match reconstruct(BufReader::new(file), &mut out) {
        Ok(run) => run,
        // Only the output pipe can fail here; the capture cannot.
        Err(error) => {
            eprintln!("error: cannot write the report: {error}");
            return ExitCode::FAILURE;
        }
    };

    if let Err(error) = out.flush() {
        eprintln!("error: cannot write the report: {error}");
        return ExitCode::FAILURE;
    }

    let Run { stats, error } = run;
    // A terminal error still leaves the tables above intact, and they are why it
    // is worth printing them: a half-read capture tells you what it held before
    // it stopped.
    if let Some(error) = error {
        eprintln!("error: {error}");
        return ExitCode::FAILURE;
    }
    // Unreachable by construction, but a counting bug that only ever showed up
    // as a silently wrong tally is the kind worth hearing about.
    if !stats.partitions_cleanly() {
        eprintln!(
            "error: internal counting error: {} records read, {} events plus {} skips accounted",
            stats.packets_read,
            stats.events,
            stats.skipped_total()
        );
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

/// What one run produced: the tally, and the error that ended it, if any.
struct Run {
    stats: StreamStats,
    error: Option<ParseError>,
}

/// Stream `reader`, writing event lines and tables to `out`.
///
/// An error that ends the stream is returned in [`Run::error`] rather than
/// propagated, because the caller still owes the reader the summary: a capture
/// that stops half way through is a capture whose first half was real.
fn reconstruct<R: Read, W: Write>(reader: R, out: &mut W) -> std::io::Result<Run> {
    let mut stream = nas_stream::nas_events(reader);
    let mut kinds: BTreeMap<String, u64> = BTreeMap::new();
    let mut codes: BTreeMap<u8, u64> = BTreeMap::new();
    let mut error = None;

    for item in stream.by_ref() {
        match item {
            Ok(event) => {
                writeln!(
                    out,
                    "{} {:<8} {:<46} len={}",
                    event.timestamp.to_rfc3339_opts(SecondsFormat::Micros, true),
                    field(&event.kind),
                    event.kind.to_string(),
                    event.payload_len
                )?;
                *kinds.entry(event.kind.to_string()).or_default() += 1;
                if let Some(code) = event.kind.emm_code() {
                    *codes.entry(code).or_default() += 1;
                }
            }
            Err(source) => error = Some(source),
        }
    }

    write_tables(out, &kinds, &codes)?;
    write_stats(out, stream.stats())?;
    Ok(Run {
        stats: stream.stats().clone(),
        error,
    })
}

/// The machine-readable field of an event line, chosen by what the message is.
///
/// A plain EMM message is named by its message type. A protected one has no
/// decoded type to show, so its security header type stands in, and a non-EMM
/// one names its protocol discriminator instead. Each is the single number that
/// explains the label after it — and never a number invented for a body that
/// was not read.
///
/// The widest form is `emm=0xNN`, eight characters, which is the column the
/// label is aligned to.
fn field(kind: &SignalingKind) -> String {
    match kind {
        SignalingKind::ProtectedNas {
            security_header_type,
        } => format!("sht={security_header_type}"),
        SignalingKind::NonEmm {
            protocol_discriminator,
        } => format!("pd={protocol_discriminator:#04x}"),
        // Every other kind came from a plain EMM message, so it has a code.
        other => match other.emm_code() {
            Some(code) => format!("emm={code:#04x}"),
            None => String::new(),
        },
    }
}

/// The two count tables: by message kind, and by EMM message code.
///
/// The kind table counts messages as reported, so an Identity Request for IMSI
/// and one for TMSI are separate rows; the code table counts the octet
/// `tshark`'s field is keyed on, which is where the two are comparable. A
/// `ProtectedNas` or `NonEmm` row appears in the first and not the second,
/// because there is no decoded EMM code for it to fall under.
fn write_tables<W: Write>(
    out: &mut W,
    kinds: &BTreeMap<String, u64>,
    codes: &BTreeMap<u8, u64>,
) -> std::io::Result<()> {
    writeln!(out, "\n== by message kind ==")?;
    if kinds.is_empty() {
        writeln!(out, "       0  no NAS messages decoded")?;
    }
    for (kind, count) in kinds {
        writeln!(out, "{count:>8}  {kind}")?;
    }

    writeln!(out, "\n== by EMM message code ==")?;
    if codes.is_empty() {
        writeln!(out, "       0  no plain EMM messages")?;
    }
    for (code, count) in codes {
        writeln!(out, "{code:#04x} {count:>8}")?;
    }
    Ok(())
}

/// The skip breakdown and the GSMTAP type histogram: why the event count is
/// what it is.
fn write_stats<W: Write>(out: &mut W, stats: &StreamStats) -> std::io::Result<()> {
    writeln!(out, "\n== stream ==")?;
    writeln!(out, "{:>8}  records read", stats.packets_read)?;
    writeln!(out, "{:>8}  NAS events", stats.events)?;
    writeln!(
        out,
        "{:>8}  skipped, not IPv4/UDP/4729",
        stats.skipped_not_udp_gsmtap
    )?;
    writeln!(
        out,
        "{:>8}  skipped, other GSMTAP type",
        stats.skipped_other_gsmtap_type
    )?;
    writeln!(out, "{:>8}  skipped, malformed", stats.skipped_malformed)?;
    writeln!(out, "{:>8}  skipped, bad timestamp", stats.failed_records)?;
    writeln!(
        out,
        "{:>8}  LTE NAS frames (GSMTAP type {LTE_NAS_TYPE:#04x})",
        stats.lte_nas_frames()
    )?;

    writeln!(out, "\n== GSMTAP frame types ==")?;
    if stats.gsmtap_types.is_empty() {
        writeln!(out, "       0  no valid GSMTAP frame in this capture")?;
    }
    for (gsmtap_type, count) in &stats.gsmtap_types {
        match type_name(*gsmtap_type) {
            "" => writeln!(out, "{count:>8}  {gsmtap_type:#04x}")?,
            name => writeln!(out, "{count:>8}  {gsmtap_type:#04x} {name}")?,
        }
    }
    Ok(())
}

/// The name of a GSMTAP type, or an empty string for one this front-end has no
/// corroborated name for.
///
/// Only the two types validated against Wireshark's GSMTAP dissector are named.
/// Labelling every other type byte from the standard's table would be guessing
/// at a capture that may be using the field differently — and the histogram
/// exists precisely to notice that, so it has to report numbers it is not sure
/// about as numbers.
fn type_name(gsmtap_type: u8) -> &'static str {
    match gsmtap_type {
        LTE_NAS_TYPE => "LTE_NAS",
        LTE_RRC_TYPE => "LTE_RRC",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use canary_cellular::signaling::{IdentityType, SignalingEvent};

    #[test]
    fn the_field_names_the_number_behind_the_label() {
        assert_eq!(
            field(&SignalingKind::IdentityRequest {
                id_type: IdentityType::Imsi
            }),
            "emm=0x55"
        );
        assert_eq!(field(&SignalingKind::AttachRequest), "emm=0x41");
        assert_eq!(
            field(&SignalingKind::OtherEmm { message_type: 0x61 }),
            "emm=0x61"
        );
        assert_eq!(
            field(&SignalingKind::ProtectedNas {
                security_header_type: 2
            }),
            "sht=2"
        );
        assert_eq!(
            field(&SignalingKind::NonEmm {
                protocol_discriminator: 0x02
            }),
            "pd=0x02"
        );
    }

    #[test]
    fn an_event_line_is_time_field_label_then_length() {
        let event = SignalingEvent {
            timestamp: chrono::DateTime::from_timestamp(1_700_000_000, 123_456_000)
                .expect("valid epoch second")
                .into(),
            kind: SignalingKind::IdentityRequest {
                id_type: IdentityType::Imsi,
            },
            payload_len: 3,
        };

        let line = format!(
            "{} {:<8} {:<46} len={}",
            event.timestamp.to_rfc3339_opts(SecondsFormat::Micros, true),
            field(&event.kind),
            event.kind,
            event.payload_len
        );

        assert_eq!(
            line.trim_end(),
            "2023-11-14T22:13:20.123456Z emm=0x55 Identity Request (IMSI) len=3"
        );
        // PCAP's epoch is UTC, and the line says so with `Z`, not `+00:00`.
        assert!(line.contains('Z'), "{line}");
    }

    #[test]
    fn every_field_form_fits_the_column_it_is_padded_to() {
        // A field longer than the pad width would shift the label column
        // mid-report, and the report is meant to be read down a margin.
        for kind in [
            SignalingKind::AttachRequest,
            SignalingKind::OtherEmm { message_type: 0x61 },
            SignalingKind::ProtectedNas {
                security_header_type: 7,
            },
            SignalingKind::NonEmm {
                protocol_discriminator: 0x7f,
            },
        ] {
            let field = field(&kind);
            assert!(field.len() <= 8, "{field:?} overflows the field column");
            assert!(!field.is_empty(), "{kind} has no field to print");
        }
    }

    #[test]
    fn type_names_only_cover_the_types_we_corroborate() {
        assert_eq!(type_name(LTE_NAS_TYPE), "LTE_NAS");
        assert_eq!(type_name(LTE_RRC_TYPE), "LTE_RRC");
        // An unnamed type keeps its number and no label, so the histogram never
        // claims knowledge of a numbering scheme it has not seen.
        assert_eq!(type_name(0x11), "");
        assert_eq!(type_name(0x01), "");
    }

    #[test]
    fn the_tables_are_ordered_and_say_so_when_empty() {
        let kinds = BTreeMap::from([
            ("Identity Request (IMSI)".to_string(), 2u64),
            ("Attach Request".to_string(), 12u64),
        ]);
        let codes = BTreeMap::from([(0x41u8, 12u64), (0x55u8, 2u64), (0x04u8, 1u64)]);

        let mut out = Vec::new();
        write_tables(&mut out, &kinds, &codes).expect("writing to a Vec cannot fail");
        let text = String::from_utf8(out).expect("the tables are UTF-8");

        // Alphabetical by label, ascending by code: independent of insertion
        // order, so two runs of one file produce byte-identical output.
        assert_eq!(
            text,
            "\n== by message kind ==\n      12  Attach Request\n       2  Identity Request \
             (IMSI)\n\n== by EMM message code ==\n0x04        1\n0x41       12\n0x55        2\n"
        );

        let mut out = Vec::new();
        write_tables(&mut out, &BTreeMap::new(), &BTreeMap::new()).expect("writes to a Vec");
        let text = String::from_utf8(out).expect("the tables are UTF-8");
        assert!(text.contains("no NAS messages decoded"), "{text}");
        assert!(text.contains("no plain EMM messages"), "{text}");
    }

    #[test]
    fn the_stats_block_accounts_for_every_record() {
        let mut gsmtap_types = BTreeMap::new();
        gsmtap_types.insert(LTE_NAS_TYPE, 3u64);
        gsmtap_types.insert(0x11, 1u64);
        let stats = StreamStats {
            packets_read: 9,
            events: 3,
            skipped_not_udp_gsmtap: 2,
            skipped_other_gsmtap_type: 1,
            skipped_malformed: 3,
            failed_records: 0,
            gsmtap_types,
        };

        let mut out = Vec::new();
        write_stats(&mut out, &stats).expect("writing to a Vec cannot fail");
        let text = String::from_utf8(out).expect("the stats are UTF-8");

        assert!(text.contains("       9  records read"), "{text}");
        assert!(text.contains("       3  NAS events"), "{text}");
        assert!(text.contains("       3  LTE NAS frames"), "{text}");
        // A named type gets its name; the unrecognised one stays a number.
        assert!(text.contains("       3  0x12 LTE_NAS"), "{text}");
        assert!(text.contains("       1  0x11\n"), "{text}");
        // The lines add up to what was read: the tally is a partition.
        assert!(
            stats.partitions_cleanly(),
            "the fixture itself must account for 9 records"
        );
    }

    #[test]
    fn a_file_that_is_not_a_capture_still_gets_a_full_report() {
        // The end-to-end path with no capture to hold: the stream fails at the
        // magic, and yet the tables, the breakdown and the histogram all print,
        // because an empty report is a claim that has to be shown to be one.
        let mut out = Vec::new();
        let run = reconstruct(&b"not a pcap at all"[..], &mut out).expect("writing to a Vec");

        assert!(
            matches!(run.error, Some(ParseError::NotClassicPcap { .. })),
            "got {:?}",
            run.error
        );
        assert_eq!(run.stats, StreamStats::default());
        let text = String::from_utf8(out).expect("the report is UTF-8");
        for expected in [
            "== by message kind ==",
            "no NAS messages decoded",
            "== by EMM message code ==",
            "no plain EMM messages",
            "       0  records read",
            "no valid GSMTAP frame in this capture",
        ] {
            assert!(text.contains(expected), "missing {expected:?} in:\n{text}");
        }
        assert!(
            !text.contains("== GSMTAP frame types ==\n       3"),
            "no frames were read, so no type rows: {text}"
        );
    }
}
