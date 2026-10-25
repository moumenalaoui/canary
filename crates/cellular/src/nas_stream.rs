//! Reconstructing the LTE NAS signaling sequence from a PCAP capture, as a
//! stream.
//!
//! [`nas_events`] takes anything readable and yields one [`SignalingEvent`] per
//! NAS message, in capture order:
//!
//! ```text
//! PCAP (classic or pcapng) records -> raw IPv4 -> UDP/4729 -> GSMTAP v2 -> NAS message type
//! ```
//!
//! It never holds the capture in memory. Records are pulled one at a time from a
//! `Read`, so a multi-gigabyte capture costs the same as a small one and the
//! same code reads a Pi's live stream: `PcapReader` and `PcapNgReader` need
//! `Read`, not `Seek`, and nothing here looks ahead or rewinds.
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
use pcap_file::pcapng::PcapNgReader;
use pcap_file::pcapng::blocks::interface_description::{InterfaceDescriptionBlock, InterfaceDescriptionOption};
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
    /// The capture is pcapng, and a block of it is not valid pcapng: a structure
    /// that contradicts itself, an option whose length does not fit one, a block
    /// type whose body this crate's parser does not accept. Everything before here
    /// was delivered.
    #[error("capture is not valid pcapng: {source}")]
    Pcapng {
        #[source]
        source: PcapError,
    },
    /// A pcapng packet names an interface its section never described. The link
    /// type and the timestamp resolution are both properties of that description,
    /// so without it the packet's bytes have no meaning to be read: the file
    /// contradicts itself, and which interface a packet belongs to is not a thing
    /// to guess at. Terminal, because a broken index does not fix itself further
    /// along in the same section.
    #[error("packet references interface {interface}, which this section does not describe")]
    UnknownInterface {
        /// The `interface_id` field of the packet block.
        interface: u32,
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
    /// Packets read, counted by the link type of the interface they arrived on.
    ///
    /// The answer to "what did the container actually say", which is worth having
    /// in writing whenever the capture came from someone else's tool: GSMTAP over
    /// raw IPv4 is `228` or `101`, and a capture that reported `1` would be
    /// Ethernet and never have been read at all.
    ///
    /// A pcapng file describes an interface per block and every packet says which
    /// one it came in on, so this is a histogram rather than one number; a classic
    /// file has exactly one entry, because its whole file is one link type. The
    /// values sum to [`packets_read`](Self::packets_read) — a different cut of the
    /// same total, not part of the events-and-skips partition.
    pub datalinks: BTreeMap<u32, u64>,
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

/// Which container the capture turned out to be, and the reader for it.
///
/// Decided once, from the sniffed magic, and it decides two things that are not
/// interchangeable: where a packet's bytes live (a record's payload, or the body
/// of an Enhanced Packet Block) and which description says what those bytes mean
/// — the whole file in the classic case, one interface per packet in pcapng's.
enum CaptureReader<R: Read> {
    /// Classic libpcap: one link type and one timestamp resolution for the file.
    /// The link type is kept beside the reader because it is needed for every
    /// packet and the header it came from borrows the reader to reach.
    Classic {
        reader: PcapReader<Source<R>>,
        linktype: u32,
    },
    /// Pcapng: blocks, with a link type and a timestamp resolution per interface.
    Pcapng { reader: PcapNgReader<Source<R>> },
}

/// The container a structural error came from, so the message can name the right
/// spec: "not valid PCAP" sent someone to look in the wrong format's table.
#[derive(Clone, Copy)]
enum Format {
    Classic,
    Pcapng,
}

/// What one pull of [`CaptureReader::next_item`] produced.
enum Chunk {
    /// A packet: the link type of the interface it arrived on, the instant it was
    /// seen, and its bytes, copied out of the reader's own buffer so that
    /// counting and dissecting happen without a borrow on the reader.
    Packet {
        linktype: u32,
        timestamp: Duration,
        data: Vec<u8>,
    },
    /// The capture ended.
    End,
}

impl<R: Read> CaptureReader<R> {
    /// What the container declares about link types before a single packet: a
    /// classic file gives one number for the whole file, and a pcapng file gives
    /// one per interface in blocks that may not have been reached yet — `None`
    /// there means "not stated yet", which is why the packet path is where a
    /// pcapng refusal happens.
    fn declared_linktype(&self) -> Option<u32> {
        match self {
            CaptureReader::Classic { linktype, .. } => Some(*linktype),
            CaptureReader::Pcapng { .. } => None,
        }
    }

    /// Pull the next packet out of whichever container is open.
    ///
    /// A link type is checked here rather than at open, because in pcapng the
    /// description of an interface is itself a block that has not necessarily been
    /// read yet — at open there is nothing to check. A classic file does have a
    /// global header, so `nas_events` refuses a wrong one before any packet is
    /// read, and the check here is the same rule stated once for both paths.
    ///
    /// A pcapng file is a stream of blocks, not of packets: section headers,
    /// interface descriptions, name-resolution, statistics and comment blocks sit
    /// between its Enhanced Packet Blocks, and every one that is not a packet is
    /// passed over rather than returned. A caller cannot count what it was never
    /// handed, so this is where "a block is not a packet" is enforced — and the
    /// `continue`, not an error and not an end, is what keeps a capture whose
    /// writer emitted a statistics block from reading as one that stopped there.
    fn next_item(&mut self) -> Result<Chunk, ParseError> {
        match self {
            CaptureReader::Classic { reader, linktype } => match reader.next_packet() {
                None => Ok(Chunk::End),
                Some(Err(source)) => Err(pcap_error(source, Format::Classic)),
                Some(Ok(packet)) => Ok(Chunk::Packet {
                    linktype: *linktype,
                    timestamp: packet.timestamp,
                    data: packet.data.into_owned(),
                }),
            },
            CaptureReader::Pcapng { reader } => loop {
                let Some(block) = reader.next_block() else {
                    return Ok(Chunk::End);
                };
                let block = block.map_err(|source| pcap_error(source, Format::Pcapng))?;
                let Some(packet) = block.into_enhanced_packet() else {
                    continue;
                };

                // Everything the interface description is needed for is copied out
                // first: the packet's bytes borrow the crate's read buffer, and
                // reading the interface list is a second borrow of the same reader.
                let interface_id = packet.interface_id;
                let timestamp = packet.timestamp;
                let data = packet.data.to_vec();

                let Some(interface) = reader.interfaces().get(interface_id as usize) else {
                    return Err(ParseError::UnknownInterface {
                        interface: interface_id,
                    });
                };
                let linktype = u32::from(interface.linktype);
                if !matches!(interface.linktype, DataLink::RAW | DataLink::IPV4) {
                    return Err(ParseError::UnsupportedLinkType { linktype });
                }

                return Ok(Chunk::Packet {
                    linktype,
                    timestamp: pcapng_timestamp(timestamp, interface),
                    data,
                });
            },
        }
    }
}

/// A streaming iterator over the NAS events of one capture.
///
/// Built by [`nas_events`]. The stream ends after the first terminal error, and
/// [`NasStream::stats`] stays readable afterwards, so a partial capture still
/// reports how far it got.
pub struct NasStream<R: Read> {
    /// `None` once the stream has ended, or when it never started.
    source: Option<CaptureReader<R>>,
    /// Set when the stream will yield nothing more.
    closed: bool,
    /// An error to yield before ending: the failures found before the first
    /// record, i.e. wrong format, wrong link type, unreadable magic.
    pending: Option<ParseError>,
    stats: StreamStats,
    /// The link type the capture's packets are read as, as soon as the container
    /// says. A classic file says it in the global header, so it is known before
    /// the first record; a pcapng file says it per interface, in a block that has
    /// not necessarily been reached, so the first packet is the earliest it can be
    /// answered. `None` throughout for a capture that was refused.
    linktype: Option<u32>,
}

impl<R: Read> NasStream<R> {
    /// A stream that yields `error` once and then ends.
    fn failed(error: ParseError) -> Self {
        Self {
            source: None,
            closed: false,
            pending: Some(error),
            stats: StreamStats::default(),
            linktype: None,
        }
    }

    /// What has been read so far. Updated as the iterator advances, so calling
    /// this mid-stream is a progress report rather than a final tally.
    pub fn stats(&self) -> &StreamStats {
        &self.stats
    }

    /// The link type the capture's packets are read as, when the container had
    /// said: the global header of a classic file at open, the first packet's
    /// interface of a pcapng one. Useful in a report, and useful in an error —
    /// "this capture is Ethernet" is worth saying even after the reader was
    /// refused, which is what [`ParseError::UnsupportedLinkType`] carries.
    ///
    /// A pcapng file that reads packets on more than one interface reports the
    /// first of them here; [`StreamStats::datalinks`] counts them all.
    pub fn linktype(&self) -> Option<u32> {
        self.linktype
    }
}

/// Reconstruct the LTE NAS signaling sequence from a capture in either PCAP
/// container.
///
/// Takes a [`Read`] rather than a path: the same code serves a file, a pipe, and
/// a byte source that cannot seek. Records are consumed lazily and dropped, so
/// memory use does not grow with capture size.
///
/// Format problems come through the iterator rather than through this function's
/// return type, because the shape asked for is an iterator: a capture that turns
/// out not to be a container this front-end reads yields one `Err` item and ends,
/// which the caller sees on its very first `next()` either way.
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
    // Hand the magic back to `pcap-file`, which expects to read it itself: both
    // readers parse their own header, and neither can be handed a reader that has
    // already swallowed the first four bytes.
    let chained = Cursor::new(buffer[..filled].to_vec()).chain(source);
    let source = if CLASSIC_MAGICS.contains(&magic) {
        let reader = match PcapReader::new(chained) {
            Ok(reader) => reader,
            Err(source) => return NasStream::failed(pcap_error(source, Format::Classic)),
        };

        // 101 (`DLT_RAW`) and 228 (`DLT_IPV4`) both mean "the packet begins at
        // the IPv4 header", which is all this front-end needs. Accepting both is
        // free and covers the two ways a raw-IPv4 capture gets written: the QMDL
        // converters use 101, while a writer that reaches for an IPv4 datalink
        // constant emits 228 — which is what `rayhunter-check -P` writes. Keying
        // on only one would reject a real capture.
        let datalink = reader.header().datalink;
        if !matches!(datalink, DataLink::RAW | DataLink::IPV4) {
            return NasStream::failed(ParseError::UnsupportedLinkType {
                linktype: u32::from(datalink),
            });
        }

        CaptureReader::Classic {
            reader,
            linktype: u32::from(datalink),
        }
    } else if magic == PCAPNG_SECTION_HEADER {
        // Nothing to refuse yet: a pcapng file's interfaces are described by the
        // blocks after the section header, so a link type exists to check only at
        // the first packet, where `next_item` looks it up.
        match PcapNgReader::new(chained) {
            Ok(reader) => CaptureReader::Pcapng { reader },
            Err(source) => return NasStream::failed(pcap_error(source, Format::Pcapng)),
        }
    } else {
        return NasStream::failed(ParseError::NotClassicPcap { magic });
    };

    NasStream {
        linktype: source.declared_linktype(),
        source: Some(source),
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

        loop {
            // The item is taken out of the reader here, so the borrow of `self`
            // ends before anything is counted or dissected below.
            let item = match self.source.as_mut() {
                None => {
                    self.closed = true;
                    return None;
                }
                Some(reader) => reader.next_item(),
            };

            let (linktype, timestamp, data) = match item {
                Err(error) => {
                    self.closed = true;
                    return Some(Err(error));
                }
                Ok(Chunk::End) => {
                    self.closed = true;
                    return None;
                }
                Ok(Chunk::Packet {
                    linktype,
                    timestamp,
                    data,
                }) => (linktype, timestamp, data),
            };

            // Counted once its link type is known to be one that can be read, so a
            // capture refused at its first packet reports zero, and one refused at
            // the tenth reports nine — the count says how far it got.
            self.stats.packets_read += 1;
            *self.stats.datalinks.entry(linktype).or_default() += 1;
            // A classic capture stated its one link type at open; a pcapng capture
            // states it per interface, so this is where the first answer arrives.
            self.linktype.get_or_insert(linktype);

            if let Some(item) = self.process_packet(&data, timestamp) {
                return Some(item);
            }
        }
    }
}

impl<R: Read> NasStream<R> {
    /// Process a packet (data + timestamp) after link-layer validation.
    /// Returns `Some(Item)` if a NAS event was found, or continues loop otherwise.
    fn process_packet(&mut self, data: &[u8], timestamp: Duration) -> Option<<Self as Iterator>::Item> {
        match gsmtap::dissect(data) {
            Verdict::NotGsmtapContainer => {
                self.stats.skipped_not_udp_gsmtap += 1;
                None
            }
            Verdict::Malformed => {
                self.stats.skipped_malformed += 1;
                None
            }
            Verdict::OtherType { gsmtap_type } => {
                *self.stats.gsmtap_types.entry(gsmtap_type).or_default() += 1;
                self.stats.skipped_other_gsmtap_type += 1;
                None
            }
            Verdict::Nas { payload, sub_type } => {
                *self.stats.gsmtap_types.entry(LTE_NAS_TYPE).or_default() += 1;

                let Some(kind) = SignalingKind::classify(payload, sub_type) else {
                    // A GSMTAP frame with no identifiable message in it.
                    self.stats.skipped_malformed += 1;
                    return None;
                };
                let payload_len = payload.len();

                match event_time(timestamp) {
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
                }
            }
        }
    }
}

/// `if_tsresol` default when an interface description omits it: microseconds, per
/// the spec. The real capture's single interface omits it, so this is not a
/// fallback for broken files but the common case.
const DEFAULT_TS_RESOL: u8 = 6;

/// Nanoseconds in a second: the unit every timestamp in this front-end reaches
/// the caller in, and the numerator of every pcapng resolution ratio.
const NS_PER_S: u128 = 1_000_000_000;

/// The instant of a pcapng packet, as a span since the epoch.
///
/// `pcap-file` decodes the timestamp field with `Duration::from_nanos` on the
/// file's raw integer and never reads `if_tsresol`, so it hands that integer back
/// wearing the wrong unit. For a microsecond file — the spec's default, and every
/// capture `rayhunter-check -P` has written — the answer is 1000 times too small:
/// the capture lands in January 1970, which is what this front-end would have
/// reported for the real one had the option been left unread.
///
/// A tick count is a full 64 bits and scaling it to nanoseconds overflows, so the
/// arithmetic is in `u128`. Nothing below a nanosecond is kept, because an event's
/// timestamp cannot say more than that.
fn pcapng_timestamp(timestamp: Duration, interface: &InterfaceDescriptionBlock) -> Duration {
    let resolution = interface
        .options
        .iter()
        .find_map(|option| match option {
            InterfaceDescriptionOption::IfTsResol(octet) => Some(*octet),
            _ => None,
        })
        .unwrap_or(DEFAULT_TS_RESOL);

    // What the crate left in the `Duration` is the file's tick count, unchanged.
    let ticks = timestamp.as_nanos();
    let (numerator, denominator) = resolution_ratio(resolution);
    let nanos = ticks * numerator / denominator;

    // A tick is at most one second wide, so scaling a tick count to seconds can
    // only shrink it: the seconds fit the 64 bits the file's own field did, and
    // there is no value here that needs clamping.
    Duration::new(
        (nanos / NS_PER_S) as u64,
        (nanos % NS_PER_S) as u32,
    )
}

/// A pcapng timestamp resolution as the ratio a tick count is multiplied by to
/// become nanoseconds: `nanos = ticks * numerator / denominator`.
///
/// `if_tsresol` is one octet in either of two forms — with the top bit set the
/// remaining seven bits are an exponent of two, otherwise the value is an exponent
/// of ten — and either way it states how many seconds one tick is worth. Kept as a
/// pair rather than one divided number because a tick finer than a nanosecond has
/// no whole number of nanoseconds: the 10⁻¹² s of `if_tsresol = 12` is a divide by
/// 1000, not a multiply by a tenth of one.
fn resolution_ratio(resolution: u8) -> (u128, u128) {
    if resolution & 0x80 != 0 {
        // 2^-k seconds per tick. The shift reaches at most 2^127, which a `u128`
        // holds, and the multiply above is the one that needs the width.
        (NS_PER_S, 1_u128 << u32::from(resolution & 0x7f))
    } else if resolution <= 9 {
        (pow10(9 - u32::from(resolution)), 1)
    } else {
        (1, pow10(u32::from(resolution) - 9))
    }
}

/// Ten to the `exponent`, saturating at what a `u128` can hold. Only a resolution
/// past 38 gets there, and such a divisor is larger than any tick count a file can
/// carry — so the quotient is zero, whether the true or the saturated divisor is
/// the one used.
fn pow10(exponent: u32) -> u128 {
    (0..exponent).fold(1, |value, _| value.saturating_mul(10))
}

/// `pcap-file`'s errors to ours.
///
/// The crate reports running out of bytes two different ways depending on where
/// it ran out — `IncompleteBuffer` from its own length checks, and an
/// `UnexpectedEof` io error from the reader underneath — and both mean the same
/// thing to a caller: the capture stops mid-structure. Saying "could not read
/// the capture" to a truncated file would send someone to check permissions
/// rather than to wait for the rest of the bytes, so they are folded into
/// [`ParseError::Truncated`] and every other io error keeps its own kind, in
/// whichever container it was found in.
///
/// What is not shared is the structural error: a block whose declared lengths
/// contradict each other is a pcapng problem and a record header is a classic one,
/// so the last arm is named after the container the error came from rather than
/// always saying `Pcap`.
fn pcap_error(source: PcapError, format: Format) -> ParseError {
    match source {
        PcapError::IncompleteBuffer => ParseError::Truncated,
        PcapError::IoError(source) if source.kind() == std::io::ErrorKind::UnexpectedEof => {
            ParseError::Truncated
        }
        PcapError::IoError(source) => ParseError::Io { source },
        other if matches!(format, Format::Pcapng) => ParseError::Pcapng { source: other },
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
        Recorded, gsmtap_frame, ip_udp, pcap, pcap_big_endian, pcap_nanosecond,
        pcapng, pcapng_big_endian, pcapng_nanosecond, pcapng_interfaces, recorded, recorded_on,
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
                // The frame's sub_type was 1, so the container's number is the
                // one reported — see the classifier's rule on that.
                SignalingKind::ProtectedNas {
                    security_header_type: 1
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
    fn a_pcapng_file_is_now_supported_but_invalid_still_errors() {
        // A pcapng Section Header Block magic but truncated: should error as pcapng parse error
        let pcapng = [0x0a_u8, 0x0d, 0x0d, 0x0a, 0x20, 0x00, 0x00, 0x00];
        let mut stream = nas_events(&pcapng[..]);

        let error = expect_refusal(&mut stream);
        // Truncated, because the block length declares a length the file does not have
        assert!(
            matches!(error, ParseError::Truncated),
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
            ("pcapng", pcapng(&records, RAW_IPV4)),
            ("pcapng big-endian", pcapng_big_endian(&records, RAW_IPV4)),
            ("pcapng nanosecond", pcapng_nanosecond(&records, RAW_IPV4)),
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

    #[test]
    fn a_pcapng_capture_of_the_default_resolution_holds_its_own_dates() {
        // The regression this front-end would otherwise ship: `pcap-file` hands the
        // EPB's integer back as nanoseconds whatever the interface declared, so the
        // microsecond file that `rayhunter-check -P` writes — the spec's default,
        // and the one its own IDB states by omitting `if_tsresol` — would land every
        // event 1000× early, in 1970. The real capture is exactly this file.
        let records = [recorded(1_700_000_000, 123_456, nas(0x00, &IDENTITY_REQUEST_IMSI))];
        let (events, _) = collect(&pcapng(&records, RAW_IPV4));

        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].timestamp.to_rfc3339(),
            "2023-11-14T22:13:20.123456+00:00",
            "microseconds, not the raw tick count read as nanoseconds"
        );
    }

    #[test]
    fn a_pcapng_capture_with_two_interfaces_reads_each_packets_own() {
        // One interface on raw IPv4, one on Ethernet. The link type is a property of
        // the interface a packet arrived on, so the first packet is read and the
        // second is refused for *its* link type, not the file's.
        let records = [
            recorded_on(0, 1_700_000_000, 0, nas(0x00, &IDENTITY_REQUEST_IMSI)),
            recorded_on(1, 1_700_000_001, 0, nas(0x00, &AUTHENTICATION_REQUEST)),
        ];
        let bytes = pcapng_interfaces(&records, &[(RAW_IPV4, None), (1, None)]);

        let mut stream = nas_events(&bytes[..]);
        let event = stream
            .next()
            .expect("the readable packet yields an event")
            .expect("no error in it");
        assert_eq!(
            event.kind,
            SignalingKind::IdentityRequest {
                id_type: IdentityType::Imsi
            },
            "the event is the NAS message the readable interface carried"
        );
        assert_eq!(stream.linktype(), Some(RAW_IPV4), "from the first packet");
        assert_eq!(stream.stats().datalinks.get(&RAW_IPV4), Some(&1));

        let error = stream
            .next()
            .expect("a second item, which is the refusal")
            .expect_err("the Ethernet packet is refused, not read");
        assert!(
            matches!(error, ParseError::UnsupportedLinkType { linktype: 1 }),
            "got {error:?}"
        );
        assert!(stream.next().is_none(), "the stream ends after the error");
        assert_eq!(
            stream.stats().packets_read, 1,
            "the refused packet was never read as a packet, so it is not counted"
        );
    }

    #[test]
    fn a_pcapng_capture_may_describe_no_interface_a_packet_names() {
        // An EPB whose `interface_id` is past the interfaces this section described.
        // Its bytes have no link type or tick width to read them with, and guessing
        // one would be inventing the capture's contents.
        let records = [recorded_on(7, 1_700_000_000, 0, nas(0x00, &IDENTITY_REQUEST_IMSI))];
        let bytes = pcapng_interfaces(&records, &[(RAW_IPV4, None)]);

        let mut stream = nas_events(&bytes[..]);
        let error = expect_refusal(&mut stream);
        assert!(
            matches!(error, ParseError::UnknownInterface { interface: 7 }),
            "got {error:?}"
        );
    }

    #[test]
    fn a_pcapng_power_of_two_resolution_is_scaled_by_it_too() {
        // The other form of `if_tsresol`: the top bit set makes the rest an exponent
        // of two, so 0x80|9 is 2^-9 s per tick — 1.953125 ms, a rate no decimal
        // exponent states. 8 ticks of it is 15625 µs, which a microsecond reading
        // and a raw-nanosecond reading both get wrong.
        let records = [recorded(1_700_000_000, 15_625, nas(0x00, &IDENTITY_REQUEST_IMSI))];
        let bytes = pcapng_interfaces(&records, &[(RAW_IPV4, Some(0x80 | 9))]);
        let (events, _) = collect(&bytes);

        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].timestamp.to_rfc3339(),
            "2023-11-14T22:13:20.015625+00:00"
        );

        // And the decimal side of the boundary: a tick finer than a nanosecond is a
        // divide, not a multiply. 10⁻¹² s per tick is 1000 ticks to the microsecond,
        // so the same sub-second part is a thousand times the count — which a reader
        // that multiplied instead would place 10⁶ away. The date is one second past
        // the epoch because that field cannot hold a real one at this resolution.
        let pico = pcapng_interfaces(
            &[recorded(1, 15_625, nas(0x00, &IDENTITY_REQUEST_IMSI))],
            &[(RAW_IPV4, Some(12))],
        );
        let (events, _) = collect(&pico);
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].timestamp.to_rfc3339(),
            "1970-01-01T00:00:01.015625+00:00",
            "if_tsresol = 12 divides by 1000 rather than multiplying"
        );
    }

    #[test]
    fn a_pcapng_linktype_is_known_only_when_a_packet_arrives() {
        let records = [recorded(1_700_000_000, 0, nas(0x00, &IDENTITY_REQUEST_IMSI))];
        let bytes = pcapng(&records, RAW_IPV4);

        let mut stream = nas_events(&bytes[..]);
        assert_eq!(
            stream.linktype(),
            None,
            "the IDB is a block, so a pcapng file has stated nothing at open"
        );
        stream.next().expect("event").expect("no error");
        assert_eq!(stream.linktype(), Some(RAW_IPV4));
        assert_eq!(stream.stats().datalinks.get(&RAW_IPV4), Some(&1));
    }
}
