//! Reconstructing the LTE NAS signaling sequence from a PCAP capture, as a
//! stream.
//!
//! [`nas_events`] takes anything readable and yields one [`SignalingEvent`] per
//! NAS message, in capture order:
//!
//! ```text
//! PCAP records -> raw IPv4 -> UDP/4729 -> GSMTAP v2 -> NAS message type
//! ```
//!
//! It never holds the capture in memory. Records are pulled one at a time from a
//! `Read`, so a multi-gigabyte capture costs the same as a small one and the
//! same code reads a Pi's live stream: `PcapReader` needs `Read`, not `Seek`,
//! and nothing here looks ahead or rewinds.
//!
//! ## What is counted, and what is an error
//!
//! A capture is full of packets that are not NAS: ordinary IP traffic, RRC
//! frames, and frames cut off by the capture's snaplen. Those are *skipped*,
//! counted by reason in [`StreamStats`], and are not errors — the stream goes
//! on. An error is reserved for the cases where the stream cannot continue:
//!
//! - the file is not something this front-end reads (not classic libpcap, or a
//!   link type that carries a real link header), or
//! - the PCAP structure is broken or unreadable part way through.
//!
//! In both, the [`NasStream`] yields exactly one `Err` and then ends, so the
//! events already produced stay valid and the caller decides what the rest is
//! worth. NAS decoding stops at the message type, for the reasons in
//! [`crate::signaling`].

use std::collections::BTreeMap;
use std::io::{Chain, Cursor, Read};
use std::time::Duration;

use chrono::{DateTime, FixedOffset, Utc};
use pcap_file::pcap::PcapReader;
use pcap_file::{DataLink, PcapError};
use serde::{Deserialize, Serialize};

use crate::gsmtap::{self, LTE_NAS_TYPE, Verdict};
use crate::signaling::{SignalingEvent, SignalingKind};

/// The classic libpcap magics, as the file's first four bytes read big-endian:
/// microsecond and nanosecond timestamp resolution, in both byte orders. These
/// are exactly the four values `pcap-file`'s header parser matches on, so a
/// file this accepts is a file that one reads — and a file whose magic is a
/// fifth value is not classic libpcap at all.
const CLASSIC_MAGICS: [u32; 4] = [0xa1b2_c3d4, 0xd4c3_b2a1, 0xa1b2_3c4d, 0x4d3c_b2a1];

/// pcapng's Section Header Block type, i.e. the first four bytes of every
/// pcapng file. Palindromic under byte order by design, so one comparison
/// recognises it whichever way the file was written.
const PCAPNG_SECTION_HEADER: u32 = 0x0a0d_0d0a;

/// How many bytes identify a container: PCAP's magic number is 4 of them.
const MAGIC_LEN: usize = 4;

/// Why a capture could not be read, or why one record could not.
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    /// The bytes could not be read at all: closed pipe, permission, disk error.
    #[error("could not read the capture: {source}")]
    Io {
        #[source]
        source: std::io::Error,
    },
    /// The capture is pcapng. Its block structure needs a different reader, and
    /// `rayhunter-check -P` does not write it — reaching this means the file
    /// came from somewhere else, Wireshark's default save format being the
    /// common one.
    #[error(
        "capture is pcapng (block type {magic:#010x}); this front-end reads classic libpcap only"
    )]
    Pcapng {
        /// The four bytes at the start of the file, big-endian.
        magic: u32,
    },
    /// The file is not classic libpcap and not pcapng.
    #[error("capture is not a classic libpcap file (magic {magic:#010x})")]
    NotClassicPcap {
        /// The four bytes at the start of the file, big-endian.
        magic: u32,
    },
    /// The capture's link type carries a real link header. Raw IPv4 was assumed
    /// and cannot be: Ethernet would move every GSMTAP field by 14 bytes, and
    /// reading it anyway would produce events naming the wrong message types.
    /// Refusing is the honest answer.
    #[error(
        "capture link type {linktype} is not raw IPv4 (101 or 228); \
         a link header would move the GSMTAP fields out of position"
    )]
    UnsupportedLinkType {
        /// The link type number from the PCAP global header.
        linktype: u32,
    },
    /// The capture ends in the middle of a structure: too few bytes for the
    /// global header, or a record whose declared length the file does not hold.
    /// The usual cause is a capture that was still being written when it was
    /// read, which is exactly what a live front-end sees, so this is reported
    /// apart from `NotClassicPcap` and `Pcap`: the file *is* a valid capture up
    /// to the cut, and the events before it are real.
    #[error("capture ends in the middle of a header or record: it is truncated")]
    Truncated,
    /// The PCAP structure is invalid: a record whose declared lengths contradict
    /// each other or exceed the snaplen, a length the file cannot support.
    /// Everything before here was delivered.
    #[error("capture is not valid PCAP: {source}")]
    Pcap {
        #[source]
        source: PcapError,
    },
    /// A record's timestamp is too far out for a date to represent. PCAP stores
    /// seconds as an unsigned 32-bit integer, so a well-formed file cannot
    /// reach this; it is here because a `Duration` carries no such promise, and
    /// pretending otherwise would invent a time.
    #[error("record timestamp {secs}.{nsecs:09} s is outside the range a date can hold")]
    Timestamp { secs: u64, nsecs: u32 },
}

/// How much of a capture became events, and why the rest did not.
///
/// The counters are a partition of [`StreamStats::packets_read`]:
///
/// ```text
/// packets_read == events + skipped_not_udp_gsmtap + skipped_other_gsmtap_type
///             + skipped_malformed + failed_records
/// ```
///
/// which is why they are broken out by reason rather than added into one
/// `skipped` total. When a capture produces zero NAS events, the reason *is* the
/// entire question — wrong port, wrong link type, different GSMTAP numbering, a
/// file that is not what it claims to be — and one count cannot answer it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamStats {
    /// Records read from the PCAP, whether or not they yielded anything.
    pub packets_read: u64,
    /// NAS events emitted.
    pub events: u64,
    /// Not IPv4-over-UDP-to-port-4729: ordinary traffic, or a fragment.
    pub skipped_not_udp_gsmtap: u64,
    /// A valid GSMTAP frame of another radio type, e.g. `0x0d` LTE RRC.
    pub skipped_other_gsmtap_type: u64,
    /// Structurally broken: truncated headers, an unusable `hdr_len` or
    /// version, or a NAS payload too short to identify a message.
    pub skipped_malformed: u64,
    /// Records that were NAS but whose timestamp could not be represented, so no
    /// event was emitted. Each of these also yielded an `Err` item.
    pub failed_records: u64,
    /// Every valid GSMTAP frame, counted by its raw type byte — including
    /// [`LTE_NAS_TYPE`] itself.
    ///
    /// This is the histogram that makes a surprising capture legible: entries
    /// all `0x11`, or all `0x0d` with no `0x12`, say in one line that the
    /// numbering or the contents differ from what was assumed, instead of
    /// leaving a zero event count to be guessed at.
    pub gsmtap_types: BTreeMap<u8, u64>,
}

impl StreamStats {
    /// Everything read that did not become an event, for the summary line.
    pub fn skipped_total(&self) -> u64 {
        self.skipped_not_udp_gsmtap
            + self.skipped_other_gsmtap_type
            + self.skipped_malformed
            + self.failed_records
    }

    /// Whether the partition documented on the type holds. A cheap way for a
    /// caller to notice a counting bug rather than inherit it.
    pub fn partitions_cleanly(&self) -> bool {
        self.packets_read == self.events + self.skipped_total()
    }

    /// The [`LTE_NAS_TYPE`] entry of the histogram: valid LTE NAS frames,
    /// including any that were too short to classify.
    pub fn lte_nas_frames(&self) -> u64 {
        self.gsmtap_types
            .get(&LTE_NAS_TYPE)
            .copied()
            .unwrap_or_default()
    }
}

/// The reader's source: the sniffed magic bytes re-attached to the caller's
/// reader, so `pcap-file` sees a whole file without the reader needing `Seek`.
type Source<R> = Chain<Cursor<Vec<u8>>, R>;

/// A streaming iterator over the NAS events of one capture.
///
/// Built by [`nas_events`]. The stream ends after the first terminal error, and
/// [`NasStream::stats`] stays readable afterwards, so a partial capture still
/// reports how far it got.
pub struct NasStream<R: Read> {
    /// `None` once the stream has ended, or when it never started.
    source: Option<PcapReader<Source<R>>>,
    /// Set when the stream will yield nothing more.
    closed: bool,
    /// An error to yield before ending: the failures found before the first
    /// record, i.e. wrong format, wrong link type, unreadable magic.
    pending: Option<ParseError>,
    stats: StreamStats,
}

impl<R: Read> NasStream<R> {
    /// A stream that yields `error` once and then ends.
    fn failed(error: ParseError) -> Self {
        Self {
            source: None,
            closed: false,
            pending: Some(error),
            stats: StreamStats::default(),
        }
    }

    /// What has been read so far. Updated as the iterator advances, so calling
    /// this mid-stream is a progress report rather than a final tally.
    pub fn stats(&self) -> &StreamStats {
        &self.stats
    }

    /// The link type number from the global header, when one was readable.
    /// Useful in an error message: "this capture is Ethernet" is worth saying
    /// even when the reader was refused.
    pub fn linktype(&self) -> Option<u32> {
        self.source
            .as_ref()
            .map(|reader| u32::from(reader.header().datalink))
    }
}

/// Reconstruct the LTE NAS signaling sequence from a classic PCAP capture.
///
/// Takes a [`Read`] rather than a path: the same code serves a file, a pipe, and
/// a byte source that cannot seek. Records are consumed lazily and dropped, so
/// memory use does not grow with capture size.
///
/// Format problems come through the iterator rather than through this function's
/// return type, because the shape asked for is an iterator: a capture that turns
/// out not to be libpcap yields one `Err` item and ends, which the caller sees
/// on its very first `next()` either way.
pub fn nas_events<R: Read>(reader: R) -> NasStream<R> {
    let mut source = reader;
    let mut buffer = [0u8; MAGIC_LEN];
    let mut filled = 0;
    while filled < MAGIC_LEN {
        match source.read(&mut buffer[filled..]) {
            // EOF: shorter than a global header, so not one.
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(source) => return NasStream::failed(ParseError::Io { source }),
        }
    }

    // Zero-filled past whatever was readable, so a short file still reports its
    // real leading bytes as the magic.
    let magic = u32::from_be_bytes(buffer);
    if filled < MAGIC_LEN || !CLASSIC_MAGICS.contains(&magic) {
        return NasStream::failed(if magic == PCAPNG_SECTION_HEADER {
            ParseError::Pcapng { magic }
        } else {
            ParseError::NotClassicPcap { magic }
        });
    }

    // Hand the magic back to `pcap-file`, which expects to read it itself.
    let chained = Cursor::new(buffer[..filled].to_vec()).chain(source);
    let reader = match PcapReader::new(chained) {
        Ok(reader) => reader,
        Err(source) => return NasStream::failed(pcap_error(source)),
    };

    // 101 (`DLT_RAW`) and 228 (`DLT_IPV4`) both mean "the packet begins at the
    // IPv4 header", which is all this front-end needs. Accepting both is free
    // and covers the two ways a raw-IPv4 capture gets written: the QMDL
    // converters use 101, while a writer that reaches for an IPv4 datalink
    // constant emits 228. Keying on only one would reject a real capture.
    let datalink = reader.header().datalink;
    if !matches!(datalink, DataLink::RAW | DataLink::IPV4) {
        return NasStream::failed(ParseError::UnsupportedLinkType {
            linktype: u32::from(datalink),
        });
    }

    NasStream {
        source: Some(reader),
        closed: false,
        pending: None,
        stats: StreamStats::default(),
    }
}

impl<R: Read> Iterator for NasStream<R> {
    type Item = Result<SignalingEvent, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.closed {
            return None;
        }
        if let Some(error) = self.pending.take() {
            self.closed = true;
            return Some(Err(error));
        }

        // `reader` borrows the `source` field only, which is what lets the
        // packet it yields coexist with updates to `stats` and `closed`.
        let reader = self.source.as_mut()?;

        loop {
            let packet = match reader.next_packet() {
                None => {
                    self.closed = true;
                    return None;
                }
                Some(Err(source)) => {
                    self.closed = true;
                    return Some(Err(pcap_error(source)));
                }
                Some(Ok(packet)) => packet,
            };

            self.stats.packets_read += 1;
            let timestamp = packet.timestamp;

            match gsmtap::dissect(&packet.data) {
                Verdict::NotGsmtapContainer => {
                    self.stats.skipped_not_udp_gsmtap += 1;
                }
                Verdict::Malformed => {
                    self.stats.skipped_malformed += 1;
                }
                Verdict::OtherType { gsmtap_type } => {
                    *self.stats.gsmtap_types.entry(gsmtap_type).or_default() += 1;
                    self.stats.skipped_other_gsmtap_type += 1;
                }
                Verdict::Nas { payload, secure } => {
                    *self.stats.gsmtap_types.entry(LTE_NAS_TYPE).or_default() += 1;

                    let Some(kind) = SignalingKind::classify(payload, secure) else {
                        // A GSMTAP frame with no identifiable message in it.
                        self.stats.skipped_malformed += 1;
                        continue;
                    };
                    let payload_len = payload.len();

                    return match event_time(timestamp) {
                        Some(timestamp) => {
                            self.stats.events += 1;
                            Some(Ok(SignalingEvent {
                                timestamp,
                                kind,
                                payload_len,
                            }))
                        }
                        None => {
                            self.stats.failed_records += 1;
                            Some(Err(ParseError::Timestamp {
                                secs: timestamp.as_secs(),
                                nsecs: timestamp.subsec_nanos(),
                            }))
                        }
                    };
                }
            }
        }
    }
}

/// `pcap-file`'s errors to ours.
///
/// The crate reports running out of bytes two different ways depending on where
/// it ran out — `IncompleteBuffer` from its own length checks, and an
/// `UnexpectedEof` io error from the reader underneath — and both mean the same
/// thing to a caller: the capture stops mid-structure. Saying "could not read
/// the capture" to a truncated file would send someone to check permissions
/// rather than to wait for the rest of the bytes, so they are folded into
/// [`ParseError::Truncated`] and every other io error keeps its own kind.
fn pcap_error(source: PcapError) -> ParseError {
    match source {
        PcapError::IncompleteBuffer => ParseError::Truncated,
        PcapError::IoError(source) if source.kind() == std::io::ErrorKind::UnexpectedEof => {
            ParseError::Truncated
        }
        PcapError::IoError(source) => ParseError::Io { source },
        other => ParseError::Pcap { source: other },
    }
}

/// PCAP record timestamp to a datetime.
///
/// The reader normalises microsecond and nanosecond resolution into one
/// `Duration` since the epoch, and PCAP's epoch is UTC, so the offset is zero.
/// `None` when the value is beyond what a date can hold: see
/// [`ParseError::Timestamp`].
fn event_time(timestamp: Duration) -> Option<DateTime<FixedOffset>> {
    let secs = timestamp.as_secs();
    let nsecs = timestamp.subsec_nanos();
    let Ok(secs) = i64::try_from(secs) else {
        return None;
    };
    DateTime::<Utc>::from_timestamp(secs, nsecs).map(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signaling::IdentityType;
    use crate::test_support::{
        Recorded, gsmtap_frame, ip_udp, pcap, pcap_big_endian, pcap_nanosecond, recorded,
    };

    /// NAS messages, as the tests name them.
    const IDENTITY_REQUEST_IMSI: [u8; 3] = [0x07, 0x55, 0x01];
    const AUTHENTICATION_REQUEST: [u8; 4] = [0x07, 0x52, 0x00, 0x11];
    const SECURITY_MODE_COMMAND: [u8; 5] = [0x07, 0x5d, 0x00, 0x11, 0x22];

    /// DLT_RAW: the link type the captures this front-end is built for use.
    const RAW_IPV4: u32 = 101;

    fn nas(sub_type: u8, payload: &[u8]) -> Vec<u8> {
        ip_udp(
            &gsmtap_frame(LTE_NAS_TYPE, sub_type, payload),
            gsmtap::UDP_PORT,
        )
    }

    fn rrc() -> Vec<u8> {
        ip_udp(
            &gsmtap_frame(gsmtap::LTE_RRC_TYPE, 0x00, &[0x00, 0x01, 0x02]),
            gsmtap::UDP_PORT,
        )
    }

    /// A capture with one of each interesting case in it, in time order.
    fn mixed_records() -> Vec<Recorded> {
        vec![
            recorded(1_700_000_000, 0, nas(0x00, &IDENTITY_REQUEST_IMSI)),
            recorded(1_700_000_001, 250_000, nas(0x00, &AUTHENTICATION_REQUEST)),
            // A secure container holding a plain-looking header: not opened.
            recorded(1_700_000_002, 0, nas(0x01, &SECURITY_MODE_COMMAND)),
            // Then three ways to be skipped.
            recorded(1_700_000_003, 0, rrc()),
            recorded(
                1_700_000_004,
                0,
                // Same well-formed frame, wrong destination port.
                ip_udp(&gsmtap_frame(LTE_NAS_TYPE, 0, &IDENTITY_REQUEST_IMSI), 4730),
            ),
            recorded(
                1_700_000_005,
                0,
                ip_udp(&[0x02, 0x04, 0x12], gsmtap::UDP_PORT),
            ),
        ]
    }

    /// Read a whole capture, expecting every item to be an event.
    fn collect(bytes: &[u8]) -> (Vec<SignalingEvent>, StreamStats) {
        let mut stream = nas_events(bytes);
        let events = stream
            .by_ref()
            .map(|item| item.expect("no error in this capture"))
            .collect::<Vec<_>>();
        let stats = stream.stats().clone();
        (events, stats)
    }

    #[test]
    fn streams_nas_events_from_a_raw_ipv4_capture() {
        let (events, stats) = collect(&pcap(&mixed_records(), RAW_IPV4));

        assert_eq!(
            events.iter().map(|event| event.kind).collect::<Vec<_>>(),
            vec![
                SignalingKind::IdentityRequest {
                    id_type: IdentityType::Imsi
                },
                SignalingKind::AuthenticationRequest,
                SignalingKind::ProtectedNas {
                    security_header_type: 0
                },
            ]
        );
        assert_eq!(stats.packets_read, 6);
        assert_eq!(stats.events, 3);
        assert_eq!(stats.skipped_other_gsmtap_type, 1);
        assert_eq!(stats.skipped_not_udp_gsmtap, 1);
        assert_eq!(stats.skipped_malformed, 1);
        assert_eq!(stats.failed_records, 0);
        assert!(stats.partitions_cleanly(), "{stats:?}");

        // The histogram counts every valid GSMTAP frame by type, NAS included.
        assert_eq!(
            stats.gsmtap_types,
            BTreeMap::from([(gsmtap::LTE_RRC_TYPE, 1), (LTE_NAS_TYPE, 3)])
        );
        assert_eq!(stats.lte_nas_frames(), 3);

        // Payload lengths are the NAS message's own, not the packet's.
        assert_eq!(
            events
                .iter()
                .map(|event| event.payload_len)
                .collect::<Vec<_>>(),
            vec![3, 4, 5]
        );
    }

    #[test]
    fn pcap_timestamps_become_utc_datetimes_with_sub_second_precision() {
        let records = [recorded(
            1_700_000_001,
            250_000,
            nas(0x00, &AUTHENTICATION_REQUEST),
        )];

        let (events, _) = collect(&pcap(&records, RAW_IPV4));

        let timestamp = events[0].timestamp;
        assert_eq!(timestamp.to_rfc3339(), "2023-11-14T22:13:21.250+00:00");
        assert_eq!(
            timestamp.offset().local_minus_utc(),
            0,
            "PCAP's epoch is UTC"
        );
    }

    #[test]
    fn both_raw_ipv4_link_types_are_accepted() {
        // 101 = DLT_RAW, 228 = DLT_IPV4. Same bytes, same events: which one a
        // converter writes is not ours to choose, so both must parse.
        let records = [recorded(
            1_700_000_000,
            0,
            nas(0x00, &IDENTITY_REQUEST_IMSI),
        )];

        for linktype in [RAW_IPV4, 228] {
            let (events, stats) = collect(&pcap(&records, linktype));
            assert_eq!(events.len(), 1, "linktype {linktype}");
            assert_eq!(stats.events, 1, "linktype {linktype}");
        }
    }

    /// A capture that must be refused outright: one `Err` item, then the end.
    ///
    /// Every refusal shares this shape, so it is asserted in one place — the
    /// stream ending after the error is as much part of the contract as the
    /// error itself, and a caller that had to re-check it per test would be a
    /// caller that could hang on a second record.
    fn expect_refusal<R: Read>(stream: &mut NasStream<R>) -> ParseError {
        let error = stream
            .next()
            .expect("a refused capture still yields one item")
            .expect_err("refusal is an error, not an event");
        assert!(stream.next().is_none(), "the stream ends after the error");
        error
    }

    #[test]
    fn a_link_type_with_a_real_link_header_is_refused() {
        // 1 = Ethernet, 0 = NULL, 113 = Linux cooked capture. None of them put
        // the IPv4 header at offset 0, so parsing them as if they did would be
        // worse than refusing: it would report wrong message types.
        for linktype in [1u32, 0, 113] {
            let records = [recorded(
                1_700_000_000,
                0,
                nas(0x00, &IDENTITY_REQUEST_IMSI),
            )];
            let bytes = pcap(&records, linktype);
            let mut stream = nas_events(&bytes[..]);

            let error = expect_refusal(&mut stream);
            assert!(
                matches!(error, ParseError::UnsupportedLinkType { linktype: reported } if reported == linktype),
                "got {error:?} for linktype {linktype}"
            );
            assert_eq!(stream.stats().packets_read, 0);
        }
    }

    #[test]
    fn a_pcapng_file_is_named_not_guessed_at() {
        // A pcapng Section Header Block: block type 0x0a0d0d0a, then its length.
        let pcapng = [0x0a_u8, 0x0d, 0x0d, 0x0a, 0x20, 0x00, 0x00, 0x00];
        let mut stream = nas_events(&pcapng[..]);

        let error = expect_refusal(&mut stream);
        assert!(
            matches!(error, ParseError::Pcapng { magic } if magic == PCAPNG_SECTION_HEADER),
            "got {error:?}"
        );
    }

    #[test]
    fn a_short_or_recognisable_other_file_is_not_a_capture() {
        for bytes in [
            &[][..],
            &[0xd4],
            &[0xd4, 0xc3, 0xb2],
            &[0x50, 0x4b, 0x03, 0x04],
        ] {
            let mut stream = nas_events(bytes);
            let error = expect_refusal(&mut stream);
            assert!(
                matches!(error, ParseError::NotClassicPcap { .. }),
                "got {error:?} for {bytes:?}"
            );
        }

        // A valid magic followed by too little header: the format is right, the
        // file simply is not there yet, which is a different complaint from
        // "this is not PCAP" and needs saying separately.
        let mut only_magic = vec![0xd4, 0xc3, 0xb2, 0xa1];
        only_magic.extend_from_slice(&[0u8; 4]);
        let mut stream = nas_events(&only_magic[..]);
        let error = expect_refusal(&mut stream);
        assert!(matches!(error, ParseError::Truncated), "got {error:?}");
    }

    #[test]
    fn an_empty_capture_has_no_events_and_no_error() {
        let bytes = pcap(&[], RAW_IPV4);
        let mut stream = nas_events(&bytes[..]);

        assert!(
            stream.next().is_none(),
            "a valid empty capture is not an error"
        );
        assert_eq!(stream.stats(), &StreamStats::default());
    }

    #[test]
    fn big_endian_and_nanosecond_containers_read_the_same_events() {
        let records = [
            recorded(1_700_000_000, 123_456, nas(0x00, &IDENTITY_REQUEST_IMSI)),
            recorded(1_700_000_001, 0, nas(0x00, &AUTHENTICATION_REQUEST)),
        ];

        let expected = collect(&pcap(&records, RAW_IPV4)).0;
        for (what, bytes) in [
            ("big-endian", pcap_big_endian(&records, RAW_IPV4)),
            ("nanosecond", pcap_nanosecond(&records, RAW_IPV4)),
        ] {
            let (events, stats) = collect(&bytes);
            assert_eq!(events, expected, "{what}");
            assert_eq!(stats.events, 2, "{what}");
        }

        // A nanosecond-resolution file is the same instant, not a shifted one.
        let (nano, _) = collect(&pcap_nanosecond(&records, RAW_IPV4));
        assert_eq!(
            nano[0].timestamp.to_rfc3339(),
            "2023-11-14T22:13:20.123456+00:00"
        );
    }

    #[test]
    fn a_truncated_final_record_ends_the_stream_with_an_error() {
        let mut bytes = pcap(&mixed_records(), RAW_IPV4);
        bytes.truncate(bytes.len() - 4);

        let mut stream = nas_events(&bytes[..]);
        let mut kinds = Vec::new();
        let mut errors = Vec::new();
        for item in stream.by_ref() {
            match item {
                Ok(event) => kinds.push(event.kind),
                Err(error) => errors.push(error),
            }
        }

        // The events before the cut are all still delivered...
        assert_eq!(kinds.len(), 3, "events before the truncation survive");
        // ...and the cut is reported as a truncation rather than as an unreadable
        // file or, worse, swallowed.
        assert_eq!(errors.len(), 1, "got {errors:?}");
        assert!(
            matches!(errors[0], ParseError::Truncated),
            "got {:?}",
            errors[0]
        );
        assert_eq!(stream.stats().packets_read, 5);
        assert_eq!(stream.stats().events, 3);
        assert!(stream.stats().partitions_cleanly());
    }

    #[test]
    fn a_record_whose_lengths_disagree_is_an_invalid_capture() {
        // `incl_len` over `orig_len` is not a truncation but a contradiction:
        // the record claims to carry more of the packet than the packet had, so
        // waiting for the rest of the file cannot fix it. That difference is the
        // whole reason it is not folded into `Truncated`.
        let records = [recorded(
            1_700_000_000,
            0,
            nas(0x00, &IDENTITY_REQUEST_IMSI),
        )];
        let mut bytes = pcap(&records, RAW_IPV4);
        // The single record's `orig_len`: one byte less than the data present.
        let one_short = (bytes.len() - 24 - 16 - 1) as u32;
        bytes[24 + 12..24 + 16].copy_from_slice(&one_short.to_le_bytes());

        let mut stream = nas_events(&bytes[..]);
        let error = expect_refusal(&mut stream);
        assert!(matches!(error, ParseError::Pcap { .. }), "got {error:?}");
        assert_eq!(
            stream.stats().packets_read,
            0,
            "a record that fails validation is not a record read"
        );
    }

    #[test]
    fn garbage_after_the_header_is_skipped_not_invented() {
        // Bytes that are neither IPv4/UDP/4729 nor a GSMTAP header must not be
        // coaxed into an event.
        let mut records = mixed_records();
        records.push(recorded(1_700_000_006, 0, vec![0xff; 40]));
        records.push(recorded(1_700_000_007, 0, vec![0x00; 8]));
        let bytes = pcap(&records, RAW_IPV4);

        let (events, stats) = collect(&bytes);

        assert_eq!(events.len(), 3);
        assert_eq!(stats.packets_read, 8);
        assert_eq!(stats.skipped_not_udp_gsmtap, 3);
        assert!(stats.partitions_cleanly(), "{stats:?}");
    }

    #[test]
    fn a_capture_of_only_rrc_shows_its_type_numbering() {
        // The histogram's whole purpose: zero NAS events, and the reason for it
        // on the same line as the count.
        let records: Vec<Recorded> = (0..4)
            .map(|i| recorded(1_700_000_000 + i, 0, rrc()))
            .collect();
        let (events, stats) = collect(&pcap(&records, RAW_IPV4));

        assert!(events.is_empty());
        assert_eq!(stats.events, 0);
        assert_eq!(stats.skipped_other_gsmtap_type, 4);
        assert_eq!(stats.gsmtap_types.get(&gsmtap::LTE_RRC_TYPE), Some(&4));
        assert_eq!(stats.lte_nas_frames(), 0);
    }

    #[test]
    fn a_timestamp_no_date_can_hold_is_an_error_not_a_fabricated_time() {
        // Unreachable from a real PCAP, whose seconds field is 32 unsigned bits,
        // but `Duration` makes no such promise: this pins the guard.
        assert!(event_time(Duration::from_secs(4_294_967_295)).is_some());
        assert!(event_time(Duration::new(u64::MAX, 0)).is_none());

        // And the epoch, the smallest value a PCAP can carry, is a real instant.
        assert_eq!(
            event_time(Duration::ZERO)
                .expect("the epoch is representable")
                .to_rfc3339(),
            "1970-01-01T00:00:00+00:00"
        );
    }

    #[test]
    fn linktype_is_reported_while_the_header_is_available() {
        let records = [recorded(
            1_700_000_000,
            0,
            nas(0x00, &IDENTITY_REQUEST_IMSI),
        )];

        let accepted = pcap(&records, 228);
        let mut stream = nas_events(&accepted[..]);
        assert_eq!(stream.linktype(), Some(228));
        let event = stream
            .next()
            .expect("one event")
            .expect("no error in this capture");
        assert_eq!(
            event.kind.emm_code(),
            Some(0x55),
            "the item taken was the event, not just a count"
        );
        assert_eq!(stream.linktype(), Some(228), "readable after the events");

        let refused_bytes = pcap(&records, 1);
        let mut refused = nas_events(&refused_bytes[..]);
        assert_eq!(refused.linktype(), None, "a refused capture has no reader");
        expect_refusal(&mut refused);
    }
}
