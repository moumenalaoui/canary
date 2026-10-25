//! GSMTAP v2 framing: getting from a captured packet to a cellular payload.
//!
//! `rayhunter-check -P` writes a classic PCAP whose link type is raw IPv4 — no
//! Ethernet, no PPP. So each record is:
//!
//! ```text
//! IPv4 header -> UDP header (GSMTAP is UDP destination port 4729)
//!             -> GSMTAP v2 header -> the cellular message
//! ```
//!
//! Everything here is that fixed skeleton: no RRC, no NAS, no packet-parsing
//! framework — just byte slicing. The verdict type is deliberately shaped to
//! match the skip counters in [`crate::nas_stream`], because "why did this
//! capture yield no NAS events?" is the first question asked of it, and the
//! answer is a different counter per reason.
//!
//! Fields are read where the GSMTAP spec puts them, big-endian for the
//! multi-byte ones. Only the fields this layer needs are touched: `version`,
//! `hdr_len`, `type` and, for LTE NAS, `sub_type`. `arfcn`, signal level and
//! frame number are real and useful, but nothing downstream consumes them yet.

/// The GSMTAP header version this reads. Version 1 has no `hdr_len` field at
/// all, so a non-2 version is not a frame whose payload can be located.
pub const VERSION: u8 = 0x02;

/// GSMTAP's UDP destination port.
pub const UDP_PORT: u16 = 4729;

/// GSMTAP type `LTE_NAS` (NAS-EPS): the only type this task processes.
/// Confirmed against Wireshark's GSMTAP dissector, which decodes type 18
/// (`0x12`) as `NAS-EPS` and leaves `0x11` undecoded.
pub const LTE_NAS_TYPE: u8 = 0x12;

/// GSMTAP type `LTE_RRC`. Named only so that a capture full of RRC reads as
/// "RRC, a later task" rather than as an unrecognised numbering scheme.
pub const LTE_RRC_TYPE: u8 = 0x0d;

/// GSMTAP `sub_type` for LTE NAS: the payload is a plain NAS message.
pub const NAS_SUBTYPE_PLAIN: u8 = 0x00;

/// GSMTAP `sub_type` for LTE NAS: the payload is security protected.
pub const NAS_SUBTYPE_SECURE: u8 = 0x01;

/// Smallest GSMTAP header: the fields above, i.e. `hdr_len` of 4 words.
const MIN_HEADER_BYTES: usize = 16;

/// A 32-bit word: the unit GSMTAP measures its header length in.
const WORD: usize = 4;

/// Shortest legal IPv4 header (IHL 5).
const MIN_IP_HEADER_BYTES: usize = 20;

/// UDP header length. UDP has no header of variable size.
const UDP_HEADER_BYTES: usize = 8;

/// IPv4 protocol number for UDP.
const PROTO_UDP: u8 = 17;

/// What a captured packet turned out to be.
///
/// The cases map one-to-one onto what the streaming reader does with them: one
/// produces an event, one is a skip that says something about the capture's
/// format, and the two failure cases are kept apart on purpose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict<'a> {
    /// A valid GSMTAP frame of type [`LTE_NAS_TYPE`].
    Nas {
        /// The NAS message, starting at its own header octet. Empty when the
        /// capture cut the frame off; the classifier reports that as malformed.
        payload: &'a [u8],
        /// True when GSMTAP's `sub_type` flags the payload as secure. A frame
        /// can claim this while its payload still opens with a plain header;
        /// the claim wins, see [`crate::signaling`].
        secure: bool,
    },
    /// A well-formed GSMTAP frame of some other radio type — `0x0d` LTE RRC,
    /// GSM, UMTS, GNSS and so on. Skipped, but worth counting by type: that is
    /// how you notice a capture that numbers types differently than expected.
    OtherType { gsmtap_type: u8 },
    /// Not a container GSMTAP could live in: not IPv4, not UDP, not port 4729,
    /// or a fragment. Ordinary IP traffic in a capture that also has NAS.
    NotGsmtapContainer,
    /// Shaped like it should hold GSMTAP but structurally broken: truncated at
    /// the IPv4, UDP or GSMTAP header, a `hdr_len` pointing outside the frame,
    /// or an unreadable version.
    Malformed,
}

/// Locate the cellular payload in a captured packet, then read its GSMTAP frame.
pub fn dissect(packet: &[u8]) -> Verdict<'_> {
    match container(packet) {
        Container::Payload(payload) => dissect_gsmtap(payload),
        Container::NotGsmtap => Verdict::NotGsmtapContainer,
        Container::Truncated => Verdict::Malformed,
    }
}

/// Read a GSMTAP frame from the start of `frame`.
///
/// The payload begins at `hdr_len * 4`, not at a hard-coded 16: a sender that
/// appends fields puts them in front of the message, and honouring the declared
/// length is what lets such a frame parse at all.
pub fn dissect_gsmtap(frame: &[u8]) -> Verdict<'_> {
    if frame.len() < MIN_HEADER_BYTES {
        return Verdict::Malformed;
    }
    let (header, _) = frame.split_at(MIN_HEADER_BYTES);

    if header[0] != VERSION {
        return Verdict::Malformed;
    }

    // `hdr_len` counts 32-bit words, so 4 words is the 16-byte minimum. A
    // smaller value, or one that reaches past the end of the frame, cannot be
    // honoured.
    let Some(offset) = usize::from(header[1]).checked_mul(WORD) else {
        return Verdict::Malformed;
    };
    if offset < MIN_HEADER_BYTES || offset > frame.len() {
        return Verdict::Malformed;
    }

    let gsmtap_type = header[2];
    if gsmtap_type != LTE_NAS_TYPE {
        return Verdict::OtherType { gsmtap_type };
    }

    Verdict::Nas {
        payload: &frame[offset..],
        secure: header[12] == NAS_SUBTYPE_SECURE,
    }
}

/// The IPv4/UDP layer's opinion about where a GSMTAP frame could be.
enum Container<'a> {
    /// The UDP payload, i.e. a GSMTAP frame.
    Payload(&'a [u8]),
    /// Wrong version, wrong protocol, wrong port, or a fragment.
    NotGsmtap,
    /// Right shape, bytes missing.
    Truncated,
}

/// Walk IPv4 and UDP down to the GSMTAP frame.
///
/// The IPv4 header length is read from the packet rather than assumed to be
/// 20: options are legal, and hard-coding 20 would misplace every GSMTAP field
/// in such a capture. The IPv4 total-length and UDP length fields are *not*
/// used to size the payload — a capture truncated by its snaplen leaves those
/// declaring more than was written, and the bytes actually present are all
/// there is to work with.
fn container(packet: &[u8]) -> Container<'_> {
    let Some(first) = packet.first() else {
        return Container::NotGsmtap;
    };
    if first >> 4 != 4 {
        return Container::NotGsmtap;
    }

    let ihl = usize::from(first & 0x0f) * WORD;
    if ihl < MIN_IP_HEADER_BYTES {
        return Container::Truncated;
    }
    if packet.len() < ihl + UDP_HEADER_BYTES {
        return Container::Truncated;
    }
    let (ip, udp) = packet.split_at(ihl);

    // Fragments are out of scope, and both kinds have to be refused: a second
    // fragment has no UDP header where we would look for it, and a *first* one
    // has the header but only part of the payload, so honouring its declared
    // lengths would be reading a message we have only a piece of. Of the two
    // fragment octets: bit 15 is reserved, bit 14 is don't-fragment (harmless,
    // and set by our own builders), bit 13 is more-fragments, and the 13 bits
    // below that are the offset in 8-octet units. Anything but DF set is ours
    // to skip.
    if ip[6] & 0x3f != 0 || ip[7] != 0 {
        return Container::NotGsmtap;
    }
    if ip[9] != PROTO_UDP {
        return Container::NotGsmtap;
    }

    // UDP: source port 0..2, destination port 2..4, length 4..6, checksum 6..8.
    if u16::from_be_bytes([udp[2], udp[3]]) != UDP_PORT {
        return Container::NotGsmtap;
    }

    Container::Payload(&udp[UDP_HEADER_BYTES..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signaling::{IdentityType, SignalingKind};
    use crate::test_support;

    /// The NAS octets from the task's example: plain EMM Identity Request, IMSI.
    const IDENTITY_REQUEST_IMSI: [u8; 3] = [0x07, 0x55, 0x01];

    #[test]
    fn lte_nas_plain_frame_yields_its_nas_payload() {
        // The frame from the task, byte for byte: a 16-byte GSMTAP header whose
        // type octet is 0x12, then the three NAS octets.
        let mut bytes = vec![
            0x02, 0x04, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        bytes.extend_from_slice(&IDENTITY_REQUEST_IMSI);

        assert_eq!(
            dissect_gsmtap(&bytes),
            Verdict::Nas {
                payload: &IDENTITY_REQUEST_IMSI,
                secure: false,
            }
        );
        // And that payload reaches the signaling layer as an Identity Request.
        assert_eq!(
            SignalingKind::classify(&IDENTITY_REQUEST_IMSI, false),
            Some(SignalingKind::IdentityRequest {
                id_type: IdentityType::Imsi
            })
        );
    }

    #[test]
    fn authentication_request_frame_decodes_to_its_kind() {
        let payload = [0x07, 0x52, 0x00, 0x11, 0x22, 0x33];
        let bytes = test_support::gsmtap_frame(LTE_NAS_TYPE, NAS_SUBTYPE_PLAIN, &payload);

        assert_eq!(
            dissect_gsmtap(&bytes),
            Verdict::Nas {
                payload: &payload,
                secure: false,
            }
        );
        assert_eq!(
            SignalingKind::classify(&payload, false),
            Some(SignalingKind::AuthenticationRequest)
        );
    }

    #[test]
    fn secure_subtype_is_carried_out_without_reading_the_body() {
        // `sub_type` at offset 12 = 01 means secure. The body here opens with a
        // plain Identity Request header deliberately: the framing must report
        // the secure flag, and the classifier must not touch that body.
        let payload = IDENTITY_REQUEST_IMSI.to_vec();
        let bytes = test_support::gsmtap_frame(LTE_NAS_TYPE, NAS_SUBTYPE_SECURE, &payload);

        let Verdict::Nas { payload, secure } = dissect_gsmtap(&bytes) else {
            panic!("expected an LTE NAS frame: {:?}", dissect_gsmtap(&bytes));
        };
        assert!(secure, "sub_type 1 must read as secure");
        assert_eq!(payload, IDENTITY_REQUEST_IMSI);

        let kind = SignalingKind::classify(payload, secure).expect("classifiable");
        assert_eq!(
            kind,
            SignalingKind::ProtectedNas {
                security_header_type: 0
            }
        );
        assert_eq!(kind.emm_code(), None, "no inner message type is decoded");
    }

    #[test]
    fn an_rrc_frame_is_not_nas_but_keeps_its_type() {
        let bytes = test_support::gsmtap_frame(LTE_RRC_TYPE, 0x00, &[0x00, 0x01, 0x02]);

        assert_eq!(
            dissect_gsmtap(&bytes),
            Verdict::OtherType {
                gsmtap_type: LTE_RRC_TYPE
            }
        );
    }

    #[test]
    fn payload_offset_follows_hdr_len() {
        // `hdr_len` 5 = a 20-byte header: 4 extra bytes belong to GSMTAP, not
        // the NAS message, so the payload must start at offset 20. The sub_type
        // of a longer header still lives at offset 12.
        let mut bytes = test_support::gsmtap_frame(LTE_NAS_TYPE, NAS_SUBTYPE_SECURE, &[]);
        bytes[1] = 5;
        bytes.extend_from_slice(&[0x99, 0x88, 0x77, 0x66]);
        bytes.extend_from_slice(&IDENTITY_REQUEST_IMSI);

        assert_eq!(
            dissect_gsmtap(&bytes),
            Verdict::Nas {
                payload: &IDENTITY_REQUEST_IMSI,
                secure: true,
            }
        );
    }

    #[test]
    fn a_header_only_frame_is_nas_with_an_empty_payload() {
        let bytes = test_support::gsmtap_frame(LTE_NAS_TYPE, NAS_SUBTYPE_PLAIN, &[]);

        assert_eq!(
            dissect_gsmtap(&bytes),
            Verdict::Nas {
                payload: &[],
                secure: false,
            }
        );
        // Which is not a message: the reader counts it as malformed.
        assert_eq!(SignalingKind::classify(&[], false), None);
    }

    #[test]
    fn broken_gsmtap_headers_are_malformed() {
        let mut version_one = test_support::gsmtap_frame(LTE_NAS_TYPE, 0, &IDENTITY_REQUEST_IMSI);
        version_one[0] = 0x01;
        let mut version_three = version_one.clone();
        version_three[0] = 0x03;

        let hdr_len = |words: u8| {
            let mut bytes = test_support::gsmtap_frame(LTE_NAS_TYPE, 0, &IDENTITY_REQUEST_IMSI);
            bytes[1] = words;
            bytes
        };

        let cases = [
            ("empty", Vec::new()),
            ("shorter than a header", vec![0x02, 0x04, 0x12, 0x00]),
            ("version 1", version_one),
            ("version 3", version_three),
            ("hdr_len 0 words", hdr_len(0)),
            ("hdr_len 1 word", hdr_len(1)),
            ("hdr_len 3 words is under the minimum", hdr_len(3)),
            ("hdr_len 255 words is past the frame", hdr_len(255)),
        ];

        for (what, bytes) in cases {
            assert_eq!(dissect_gsmtap(&bytes), Verdict::Malformed, "{what}");
        }
    }

    #[test]
    fn plain_ipv4_udp_reaches_the_frame_and_other_containers_do_not() {
        let gsmtap =
            test_support::gsmtap_frame(LTE_NAS_TYPE, NAS_SUBTYPE_PLAIN, &IDENTITY_REQUEST_IMSI);

        assert_eq!(
            dissect(&test_support::ip_udp(&gsmtap, UDP_PORT)),
            Verdict::Nas {
                payload: &IDENTITY_REQUEST_IMSI,
                secure: false,
            }
        );

        // Not our port: GSMTAP is defined on 4729 and nothing else.
        assert_eq!(
            dissect(&test_support::ip_udp(&gsmtap, 4730)),
            Verdict::NotGsmtapContainer
        );
        // Not UDP: TCP carrying the same bytes.
        assert_eq!(
            dissect(&test_support::ip_tcp(&gsmtap, UDP_PORT)),
            Verdict::NotGsmtapContainer
        );
        // Not IPv4 at all: version nibble 6 is IPv6.
        assert_eq!(dissect(&[0x60; 64]), Verdict::NotGsmtapContainer);
        assert_eq!(dissect(&[]), Verdict::NotGsmtapContainer);
    }

    #[test]
    fn ipv4_options_do_not_move_the_udp_header() {
        // IHL 6 = a 24-byte IPv4 header, four option bytes in front of the UDP
        // header. Assuming 20 would read those options as port numbers.
        let gsmtap =
            test_support::gsmtap_frame(LTE_NAS_TYPE, NAS_SUBTYPE_PLAIN, &IDENTITY_REQUEST_IMSI);
        let mut packet = test_support::ip_udp(&gsmtap, UDP_PORT);
        packet.splice(20..20, [0x44, 0x00, 0x00, 0x00]);
        packet[0] = 0x46; // version 4, IHL 6

        assert_eq!(
            dissect(&packet),
            Verdict::Nas {
                payload: &IDENTITY_REQUEST_IMSI,
                secure: false,
            }
        );
    }

    #[test]
    fn fragments_are_not_ours_and_short_packets_are_malformed() {
        let gsmtap =
            test_support::gsmtap_frame(LTE_NAS_TYPE, NAS_SUBTYPE_PLAIN, &IDENTITY_REQUEST_IMSI);

        // Don't-fragment set is the ordinary case, not a fragment: every packet
        // this crate's own builder produces has bit 14 set, and refusing it
        // would refuse the whole capture.
        let ordinary = test_support::ip_udp(&gsmtap, UDP_PORT);
        assert_eq!(ordinary[6], 0x40);
        assert_eq!(
            dissect(&ordinary),
            Verdict::Nas {
                payload: &IDENTITY_REQUEST_IMSI,
                secure: false,
            }
        );

        // More-fragments set (bit 13 of the first frag octet): a first fragment,
        // whose payload is complete only once the rest arrives.
        let mut more_frags = ordinary.clone();
        more_frags[6] |= 0x20;
        assert_eq!(dissect(&more_frags), Verdict::NotGsmtapContainer);

        // A nonzero fragment offset, in either octet: not the first fragment.
        let mut offset = ordinary.clone();
        offset[7] = 0x01;
        assert_eq!(dissect(&offset), Verdict::NotGsmtapContainer);
        let mut high_offset = ordinary.clone();
        high_offset[6] |= 0x01; // top bit of the offset, in the flags' octet
        assert_eq!(dissect(&high_offset), Verdict::NotGsmtapContainer);

        let packet = ordinary;
        // Cut inside the IPv4 header, and cut inside the UDP header.
        assert_eq!(dissect(&packet[..10]), Verdict::Malformed);
        assert_eq!(dissect(&packet[..24]), Verdict::Malformed);
        // IHL claims 20 bytes in a 20-byte packet: no UDP header at all.
        assert_eq!(dissect(&packet[..20]), Verdict::Malformed);
        // An IHL below 5 is not a legal IPv4 header.
        let mut bogus_ihl = packet.clone();
        bogus_ihl[0] = 0x44; // version 4, IHL 4 = 16 bytes
        assert_eq!(dissect(&bogus_ihl), Verdict::Malformed);
    }

    #[test]
    fn udp_payload_shorter_than_a_gsmtap_header_is_malformed() {
        // Right container, frame truncated before the header ends.
        let mut short = test_support::gsmtap_frame(LTE_NAS_TYPE, 0, &IDENTITY_REQUEST_IMSI);
        short.truncate(10);
        assert_eq!(
            dissect(&test_support::ip_udp(&short, UDP_PORT)),
            Verdict::Malformed
        );
    }
}
