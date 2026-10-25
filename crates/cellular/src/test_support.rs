//! Byte builders shared by this crate's tests.
//!
//! These exist so a test's capture and the capture fed to `tshark` in
//! `scripts/` are built by the same rules: framing tests are only worth
//! something if the bytes they assert on are bytes an independent dissector
//! accepts. Everything here encodes the wire format from the field offsets in
//! the specs rather than from this crate's parser, so a mistake in one is not
//! hidden by the other.

/// A GSMTAP v2 header plus `payload`.
///
/// `hdr_len` is 4 (16 bytes), `arfcn` 100, `signal_dbm` 0x3c, `snr_db` 10,
/// `frame_number` 5. The values are inert but plausible: a capture of all zeros
/// is not something a real tool emits, and it would hide nothing.
pub(crate) fn gsmtap_frame(gsmtap_type: u8, sub_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![
        0x02, // version
        0x04, // hdr_len, in 32-bit words
        gsmtap_type,
        0x00, // timeslot
        0x00,
        0x64, // arfcn = 100, big-endian
        0x3c, // signal level, an i8 octet
        0x0a, // snr
        0x00,
        0x00,
        0x00,
        0x05, // frame number, big-endian
        sub_type,
        0x00, // antenna number
        0x00, // sub slot
        0x00, // reserved
    ];
    frame.extend_from_slice(payload);
    frame
}

/// A raw-IPv4 packet: IPv4 header, UDP header, then `payload`.
pub(crate) fn ip_udp(payload: &[u8], destination_port: u16) -> Vec<u8> {
    ip_with_proto(payload, destination_port, PROTO_UDP)
}

/// The same, with the IPv4 protocol octet chosen — so a TCP-carried frame can
/// be built to prove it is skipped rather than parsed.
pub(crate) fn ip_tcp(payload: &[u8], destination_port: u16) -> Vec<u8> {
    ip_with_proto(payload, destination_port, PROTO_TCP)
}

const PROTO_UDP: u8 = 17;
const PROTO_TCP: u8 = 6;

fn ip_with_proto(payload: &[u8], destination_port: u16, protocol: u8) -> Vec<u8> {
    // Source and destination 127.0.0.1: loopback is where a locally produced
    // GSMTAP stream genuinely appears.
    let octets = [127, 0, 0, 1];
    let total_len = 20 + 8 + payload.len();

    let mut packet = Vec::with_capacity(total_len);
    packet.extend_from_slice(&[
        0x45, // version 4, IHL 5
        0x00, // DSCP and ECN
        (total_len >> 8) as u8,
        total_len as u8,
        0x12,
        0x34, // identification
        0x40,
        0x00, // flags: don't fragment, offset 0
        64,   // TTL
        protocol,
        0x00,
        0x00, // checksum, filled in below
    ]);
    packet.extend_from_slice(&octets);
    packet.extend_from_slice(&octets);
    let checksum = internet_checksum(&packet[..20]);
    packet[10] = (checksum >> 8) as u8;
    packet[11] = checksum as u8;

    let udp_len = 8 + payload.len();
    packet.extend_from_slice(&[
        0xd4,
        0x31, // source port 54321
        (destination_port >> 8) as u8,
        destination_port as u8,
        (udp_len >> 8) as u8,
        udp_len as u8,
        0x00,
        0x00, // checksum: optional over IPv4, and unused here
    ]);
    packet.extend_from_slice(payload);
    packet
}

/// One record to put in a capture container.
pub(crate) struct Recorded {
    /// Seconds since the Unix epoch, as PCAP stores it: 32 bits, unsigned.
    pub secs: u32,
    /// Sub-second part, always in *microseconds*. A container that declares
    /// nanosecond resolution scales it, the same way `pcap-file`'s own writer
    /// divides it back out, so one test value names one instant whichever file
    /// it ends up in.
    pub micros: u32,
    /// The whole packet, link-layer payload and all.
    pub packet: Vec<u8>,
    /// Which interface the record arrived on, for a pcapng file that describes
    /// more than one. Ignored by the classic containers, which have no such
    /// thing: their whole file is one link type.
    pub interface: u32,
}

pub(crate) fn recorded(secs: u32, micros: u32, packet: Vec<u8>) -> Recorded {
    Recorded {
        secs,
        micros,
        packet,
        interface: 0,
    }
}

/// The same, on a named interface — so a test can say that this packet came in
/// on the Ethernet interface of a two-interface capture.
pub(crate) fn recorded_on(interface: u32, secs: u32, micros: u32, packet: Vec<u8>) -> Recorded {
    Recorded {
        interface,
        ..recorded(secs, micros, packet)
    }
}

/// The global-header magic of a classic libpcap file: microsecond resolution.
///
/// `pcap-file` reads these four bytes big-endian, so this is the on-disk
/// sequence of a file written by a little-endian host, and the value a
/// big-endian host writes at the same offset read the other way.
const MAGIC_MICRO: u32 = 0xa1b2_c3d4;

/// The same with nanosecond resolution: `3c4d` in place of `c3d4`.
const MAGIC_NANO: u32 = 0xa1b2_3c4d;

/// A little-endian classic libpcap file, microsecond timestamps: global header,
/// then `records`. What a capture written on an `x86` or Apple Silicon host is.
pub(crate) fn pcap(records: &[Recorded], linktype: u32) -> Vec<u8> {
    pcap_bytes(records, linktype, MAGIC_MICRO, false, 1)
}

/// The same container with big-endian record headers, to prove the byte order
/// declared by the file's magic — not the host's — governs reading.
pub(crate) fn pcap_big_endian(records: &[Recorded], linktype: u32) -> Vec<u8> {
    pcap_bytes(records, linktype, MAGIC_MICRO, true, 1)
}

/// A little-endian container that declares nanosecond timestamps.
///
/// Same instants as [`pcap`], written in the units this resolution names: a
/// reader that normalises both to one timestamp must give the same events, and
/// one that simply copies the field would place the decimal point 1000 away.
pub(crate) fn pcap_nanosecond(records: &[Recorded], linktype: u32) -> Vec<u8> {
    pcap_bytes(records, linktype, MAGIC_NANO, false, 1_000)
}

fn pcap_bytes(
    records: &[Recorded],
    linktype: u32,
    magic: u32,
    big_endian: bool,
    subsec_scale: u32,
) -> Vec<u8> {
    let mut out = Vec::new();
    // The magic is written in the container's own byte order, which is what
    // makes it the *declaration* of that order rather than a value in it:
    // `MAGIC_MICRO` on a little-endian host comes out as `d4 c3 b2 a1`.
    push_u32(&mut out, magic, big_endian);
    push_u16(&mut out, 2, big_endian); // version_major
    push_u16(&mut out, 4, big_endian); // version_minor
    push_u32(&mut out, 0, big_endian); // thiszone
    push_u32(&mut out, 0, big_endian); // sigfigs
    push_u32(&mut out, 65535, big_endian); // snaplen
    push_u32(&mut out, linktype, big_endian); // network / datalink

    for record in records {
        push_u32(&mut out, record.secs, big_endian);
        push_u32(&mut out, record.micros * subsec_scale, big_endian);
        push_u32(&mut out, record.packet.len() as u32, big_endian); // incl_len
        push_u32(&mut out, record.packet.len() as u32, big_endian); // orig_len
        out.extend_from_slice(&record.packet);
    }
    out
}

fn push_u16(out: &mut Vec<u8>, value: u16, big_endian: bool) {
    out.extend_from_slice(&if big_endian {
        value.to_be_bytes()
    } else {
        value.to_le_bytes()
    });
}

fn push_u32(out: &mut Vec<u8>, value: u32, big_endian: bool) {
    out.extend_from_slice(&if big_endian {
        value.to_be_bytes()
    } else {
        value.to_le_bytes()
    });
}

fn push_u64(out: &mut Vec<u8>, value: u64, big_endian: bool) {
    out.extend_from_slice(&if big_endian {
        value.to_be_bytes()
    } else {
        value.to_le_bytes()
    });
}

/// pcapng block types this builder writes.
const BLOCK_SECTION_HEADER: u32 = 0x0a0d_0d0a;
const BLOCK_INTERFACE_DESCRIPTION: u32 = 1;
const BLOCK_NAME_RESOLUTION: u32 = 4;
const BLOCK_ENHANCED_PACKET: u32 = 6;

/// The byte-order magic, as a value in the section's own order: `0x1a2b3c4d`.
///
/// Its bytes are the declaration, so a little-endian section holds `4d 3c 2b 1a`
/// and a big-endian one `1a 2b 3c 4d` — and one constant written in whatever the
/// file's order is produces both. Naming it per endianness and then writing it in
/// that endianness swaps it twice and leaves the reader holding the section in the
/// wrong order, i.e. a file that reads as garbage.
const BYTE_ORDER_MAGIC: u32 = 0x1a2b_3c4d;

/// How many bytes a pcapng block costs beyond its body: the type, the total
/// length, and the total length repeated as the trailer.
const BLOCK_OVERHEAD: u32 = 12;

/// Nanoseconds in a second, the unit `Recorded`'s fields add up to.
const NS_PER_S: u64 = 1_000_000_000;

/// A record's instant, in the ticks of an interface that declared `resolution`.
///
/// `if_tsresol` states how many seconds one tick is worth, in one of two forms:
/// the top bit set means the rest is an exponent of two, otherwise the value is an
/// exponent of ten. Both are inverted here to get a tick count out of a
/// microsecond-denominated `Recorded`, which is the inverse of what a reader has
/// to do to get the instant back — and written from the spec, as the rest of this
/// file is, so a mistake in the crate's or this crate's reading is not hidden by
/// the fixture agreeing with it.
fn ticks(resolution: u8, secs: u32, micros: u32) -> u64 {
    let nanos = u128::from(secs) * u128::from(NS_PER_S) + u128::from(micros) * 1_000;
    let ticks = if resolution & 0x80 != 0 {
        // 2^-k seconds per tick, so 2^k ticks per second.
        nanos * (1_u128 << u32::from(resolution & 0x7f)) / u128::from(NS_PER_S)
    } else if resolution <= 9 {
        // A tick is a whole number of nanoseconds: 10^(9-v) of them.
        nanos / u128::from(10u64.pow(9 - u32::from(resolution)))
    } else {
        // Finer than a nanosecond, so several ticks to the nanosecond.
        nanos * u128::from(10u64.pow(u32::from(resolution) - 9))
    };

    // The multiply is in `u128` before the divide, but the result has to fit the
    // file's 64-bit field. A count that does not is a file that cannot exist, so
    // say so here rather than write a wrapped timestamp for a test to then assert
    // an instant it never named. Which is also why the resolutions finer than a
    // nanosecond are exercised with a one-second date: at 10⁻¹² s per tick a 64-bit
    // count spans under a year since the epoch, so no real capture states time that
    // way, and it is this front-end's reading of that branch that is under test.
    u64::try_from(ticks)
        .unwrap_or_else(|_| panic!("no pcapng file holds {secs} s at 10^{resolution} per tick"))
}

/// A pcapng file: one Section Header Block, one Interface Description Block per
/// entry of `interfaces` (link type, `if_tsresol` exponent or `None` for the
/// spec's default microsecond resolution), then one Enhanced Packet Block per
/// record.
///
/// Written as bytes rather than with `pcap-file`'s own writer, for the reason
/// stated at the top of this file: the crate's writer emits a timestamp in
/// nanoseconds while declaring microsecond resolution, so a file built by it is
/// a file the crate's own reader would misplace by a factor of 1000. Bytes from
/// the spec are the thing tshark reads.
fn pcapng_blocks(
    records: &[Recorded],
    interfaces: &[(u32, Option<u8>)],
    big_endian: bool,
    other_blocks: bool,
) -> Vec<u8> {
    let mut out = Vec::new();
    push_shb(&mut out, big_endian);
    for (linktype, ts_resol) in interfaces {
        push_idb(&mut out, *linktype, *ts_resol, big_endian);
    }

    for record in records {
        if other_blocks {
            // A block that is not a packet, where a real capture puts one: see
            // [`pcapng_with_other_blocks`].
            push_nrb(&mut out, big_endian);
        }
        // The timestamp is one integer in the interface's own units, so the
        // record's `micros` is scaled by whatever that interface declared.
        let resol = interfaces
            .get(record.interface as usize)
            .and_then(|(_, resol)| *resol)
            .unwrap_or(DEFAULT_TS_RESOL);
        push_epb(&mut out, record, resol, big_endian);
    }

    out
}

/// Section Header Block: the byte-order magic, the version, and a section length
/// of -1, meaning the section runs to the next SHB rather than a stated count.
fn push_shb(out: &mut Vec<u8>, big_endian: bool) {
    let mut body = Vec::new();
    push_u32(&mut body, BYTE_ORDER_MAGIC, big_endian);
    push_u16(&mut body, 1, big_endian); // major_version
    push_u16(&mut body, 0, big_endian); // minor_version
    push_u64(&mut body, u64::MAX, big_endian); // section_length: -1, unspecified
    push_block(out, BLOCK_SECTION_HEADER, &body, big_endian);
}

/// Interface Description Block: `if_tsresol` is written only when the test asked
/// for a non-default resolution, because an interface that omits it is the
/// ordinary case — the real capture's single interface does, and says microseconds
/// by the spec's default.
fn push_idb(out: &mut Vec<u8>, linktype: u32, ts_resol: Option<u8>, big_endian: bool) {
    let mut body = Vec::new();
    push_u16(&mut body, linktype as u16, big_endian);
    push_u16(&mut body, 0, big_endian); // reserved
    push_u32(&mut body, 65535, big_endian); // snaplen
    if let Some(resol) = ts_resol {
        // if_tsresol (option 9): one octet, so three octets of padding.
        push_u16(&mut body, 9, big_endian);
        push_u16(&mut body, 1, big_endian);
        body.push(resol);
        body.extend_from_slice(&[0, 0, 0]);
    }
    // An option list ends with `opt_endofopt` (code 0, length 0) whether or not
    // anything preceded it.
    push_u16(&mut body, 0, big_endian);
    push_u16(&mut body, 0, big_endian);
    push_block(out, BLOCK_INTERFACE_DESCRIPTION, &body, big_endian);
}

/// Enhanced Packet Block: the interface the packet arrived on, its timestamp in
/// that interface's ticks, its lengths, the bytes, and padding to a 4-byte
/// boundary — no options, which is what a writer that stores nothing else emits.
fn push_epb(out: &mut Vec<u8>, record: &Recorded, resolution: u8, big_endian: bool) {
    let ticks = ticks(resolution, record.secs, record.micros);

    let mut body = Vec::new();
    push_u32(&mut body, record.interface, big_endian);
    push_u32(&mut body, (ticks >> 32) as u32, big_endian);
    push_u32(&mut body, ticks as u32, big_endian);
    push_u32(&mut body, record.packet.len() as u32, big_endian); // captured_len
    push_u32(&mut body, record.packet.len() as u32, big_endian); // original_len
    body.extend_from_slice(&record.packet);
    while body.len() % 4 != 0 {
        body.push(0);
    }
    push_u16(&mut body, 0, big_endian); // opt_endofopt
    push_u16(&mut body, 0, big_endian);
    push_block(out, BLOCK_ENHANCED_PACKET, &body, big_endian);
}

/// A Name Resolution Block carrying no records: a block a capture file holds that
/// is not a packet and says nothing about the packets — which is exactly what a
/// reader counting packets has to be able to ignore.
fn push_nrb(out: &mut Vec<u8>, big_endian: bool) {
    let mut body = Vec::new();
    push_u16(&mut body, 0, big_endian); // end of the records list
    push_u16(&mut body, 0, big_endian);
    push_u16(&mut body, 0, big_endian); // opt_endofopt
    push_u16(&mut body, 0, big_endian);
    push_block(out, BLOCK_NAME_RESOLUTION, &body, big_endian);
}

/// `if_tsresol` the spec defaults to when the option is absent: microseconds.
/// Mirrors the reader's constant, and is what the real capture's interface uses.
const DEFAULT_TS_RESOL: u8 = 6;

/// One pcapng block: type, total length, body, total length again.
fn push_block(out: &mut Vec<u8>, block_type: u32, body: &[u8], big_endian: bool) {
    let total = BLOCK_OVERHEAD + body.len() as u32;
    push_u32(out, block_type, big_endian);
    push_u32(out, total, big_endian);
    out.extend_from_slice(body);
    push_u32(out, total, big_endian);
}

/// A little-endian pcapng file whose one interface is `linktype`, with the
/// default microsecond timestamps: what `rayhunter-check -P` writes.
pub(crate) fn pcapng(records: &[Recorded], linktype: u32) -> Vec<u8> {
    pcapng_blocks(records, &[(linktype, None)], false, false)
}

/// The same file in a big-endian section, the byte order the real capture from
/// the Pi's toolchain happens to use.
pub(crate) fn pcapng_big_endian(records: &[Recorded], linktype: u32) -> Vec<u8> {
    pcapng_blocks(records, &[(linktype, None)], true, false)
}

/// A pcapng that declares nanosecond resolution with `if_tsresol`. The same
/// instants as [`pcapng`], in units a reader that ignored the option would
/// place 1000 away — which is precisely what `pcap-file` does, and why this
/// front-end reads the option itself.
pub(crate) fn pcapng_nanosecond(records: &[Recorded], linktype: u32) -> Vec<u8> {
    pcapng_blocks(records, &[(linktype, Some(9))], false, false)
}

/// A pcapng carrying several interfaces, so a packet's own interface decides
/// what its bytes mean.
pub(crate) fn pcapng_interfaces(records: &[Recorded], interfaces: &[(u32, Option<u8>)]) -> Vec<u8> {
    pcapng_blocks(records, interfaces, false, false)
}

/// A pcapng with a Name Resolution Block before every packet.
///
/// pcapng is a stream of blocks, not a stream of packets, and real files carry
/// name-resolution, statistics and comment blocks among their packets — the
/// difference is invisible until something counts wrong. A reader that took every
/// block for a packet reports a capture bigger than the file, and one that treated
/// a skipped block as end-of-file loses the rest of the signaling.
#[allow(dead_code)] // kept for a reader test that is not yet written
pub(crate) fn pcapng_with_other_blocks(records: &[Recorded], linktype: u32) -> Vec<u8> {
    pcapng_blocks(records, &[(linktype, None)], false, true)
}

/// The Internet checksum of RFC 1071, so the headers built here are valid
/// enough for any dissector to take them.
fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for pair in bytes.chunks_exact(2) {
        sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
    }
    if let Some(&last) = bytes.chunks_exact(2).remainder().first() {
        sum += u32::from(last) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The container's own declaration is what these builders are checked
    /// against: a magic that lies about its byte order or its timestamp
    /// resolution produces a capture that reads as a different file.
    #[test]
    fn pcap_magics_are_the_bytes_the_reader_matches() {
        let records = [recorded(1_700_000_000, 500_000, vec![0x45; 28])];

        // Little-endian microsecond: `d4 c3 b2 a1` on disk.
        let bytes = pcap(&records, 101);
        assert_eq!(&bytes[..4], &[0xd4, 0xc3, 0xb2, 0xa1]);
        // Big-endian microsecond: the same value the other way round.
        let bytes = pcap_big_endian(&records, 101);
        assert_eq!(&bytes[..4], &[0xa1, 0xb2, 0xc3, 0xd4]);
        // Little-endian nanosecond: `4d 3c b2 a1`.
        let bytes = pcap_nanosecond(&records, 101);
        assert_eq!(&bytes[..4], &[0x4d, 0x3c, 0xb2, 0xa1]);
    }

    #[test]
    fn a_record_is_header_then_the_packet_octets() {
        let packet = ip_udp(&gsmtap_frame(0x12, 0, &[0x07, 0x55, 0x01]), 4729);
        let bytes = pcap(&[recorded(7, 8, packet.clone())], 101);

        assert_eq!(bytes.len(), 24 + 16 + packet.len());
        assert_eq!(&bytes[24 + 16..], &packet[..]);
        // The link type is the last global-header field, little-endian.
        assert_eq!(&bytes[20..24], &[101, 0, 0, 0]);
        // Record header: secs, then the sub-second field in the container's own
        // units — microseconds here, nanoseconds in a nanosecond file.
        assert_eq!(subsec_field(&bytes), 8);
        assert_eq!(
            subsec_field(&pcap_nanosecond(&[recorded(7, 8, packet)], 101)),
            8_000
        );
    }

    /// The record's sub-second octets, at their offset in a little-endian file.
    fn subsec_field(bytes: &[u8]) -> u32 {
        u32::from_le_bytes(
            bytes[24 + 4..24 + 8]
                .try_into()
                .expect("a record header is 16 bytes"),
        )
    }

    #[test]
    fn ip_udp_is_a_valid_ipv4_udp_packet_on_port_4729() {
        let packet = ip_udp(&[0x02, 0x04, 0x12], 4729);

        assert_eq!(packet[0], 0x45);
        assert_eq!(
            usize::from(u16::from_be_bytes([packet[2], packet[3]])),
            packet.len(),
            "total length matches the bytes written"
        );
        assert_eq!(packet[9], 17);
        assert_eq!(u16::from_be_bytes([packet[22], packet[23]]), 4729);
        // A checksum that actually verifies: summing the header's 16-bit words
        // with the checksum included yields all-ones.
        assert_eq!(internet_checksum(&packet[..20]), 0);
        assert_eq!(packet[20..24], [0xd4, 0x31, 0x12, 0x79]);
        // And the TCP variant differs only in the protocol octet.
        assert_eq!(ip_tcp(&[], 4729)[9], 6);
    }
}
