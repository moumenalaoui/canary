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
}

pub(crate) fn recorded(secs: u32, micros: u32, packet: Vec<u8>) -> Recorded {
    Recorded {
        secs,
        micros,
        packet,
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
