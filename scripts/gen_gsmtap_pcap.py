#!/usr/bin/env python3
"""Write synthetic GSMTAP-in-UDP-in-IPv4 captures, for the NAS front-end.

    scripts/gen_gsmtap_pcap.py [--outdir DIR]

CANARY's cellular front-end reads a PCAP of GSMTAP frames and reconstructs the
LTE NAS signaling sequence. Hand-built byte arrays in the crate's own tests
prove that front-end against its own assumptions, which is not evidence. These
captures come from a second implementation of the same formats, written against
the field offsets in the specs in a language the front-end shares no code with,
so a disagreement between the two is a fact about the format rather than about
a shared mistake — and every one of them is readable by tshark, which is the
third opinion (`scripts/oracle_compare.sh`).

Four captures, because the front-end has duties that must not be confused:

  nas.pcap     frames that must all become events: the EMM messages this model
               names, the codes no dissector names, identity requests and
               responses, a security-protected container, and a NAS PDU whose
               protocol discriminator is not EMM.
  skips.pcap   traffic that must be counted and skipped, with one real NAS frame
               among it — so that a front-end which skips *everything* is caught
               by the event count rather than by a table that looks plausible.
  nas_be.pcap  the NAS frames again in a big-endian container.
  nas_ns.pcap  the same frames with nanosecond timestamps.

The last two exist because a file's magic, not the reading host, decides both
byte order and timestamp resolution: a reader that copies the sub-second field
instead of scaling it reports 1.000000 seconds as 1000 seconds, and both files
here hold the same instants as `nas.pcap`.

Link type is 101 (RAW): the IPv4 packet starts at the first octet of the
record's data, which is what Rayhunter's cellular captures use.
"""

import argparse
import struct
from pathlib import Path

LINKTYPE_RAW = 101
UDP_PORT_GSMTAP = 4729

GSMTAP_LTE_RRC = 0x0D
GSMTAP_LTE_NAS = 0x12

# EMM message types, TS 24.301 table 9.9.2.4.
NAMED_EMM = {
    0x41: "Attach request",
    0x44: "Attach reject",
    0x45: "Detach request",
    0x48: "Tracking area update request",
    0x4B: "Tracking area update reject",
    0x52: "Authentication request",
    0x53: "Authentication response",
    0x54: "Authentication reject",
    0x55: "Identity request",
    0x56: "Identity response",
    0x5D: "Security mode command",
    0x5E: "Security mode complete",
}

# Codes a dissector's table has no name for. CANARY reports the raw octet for
# these, which is the honest answer and the one the oracle cannot contradict.
UNNAMED_EMM = [0x40, 0x47, 0x65, 0x7F, 0xF1]


def checksum(data):
    """The Internet checksum of RFC 1071, so the headers built here are valid."""
    if len(data) % 2:
        data += b"\x00"
    total = sum(int.from_bytes(data[i : i + 2], "big") for i in range(0, len(data), 2))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def octets(text):
    return bytes(int(part) for part in text.split("."))


def gsmtap(payload, gsmtap_type=GSMTAP_LTE_NAS, sub_type=0, hdr_len_words=4, timeslot=0):
    """A GSMTAP v2 header plus `payload`.

    Sixteen octets, written field by field: version, header length in 32-bit
    words, payload type, timeslot, ARFCN (16 bits, big-endian), signal level,
    SNR, frame number (32 bits), then the subtype — for LTE NAS the security
    header type, the one piece of NAS protection information outside the PDU.
    """
    header = bytearray(16)
    header[0] = 2
    header[1] = hdr_len_words
    header[2] = gsmtap_type
    header[3] = timeslot
    header[4:6] = struct.pack(">H", 100)  # ARFCN
    header[6] = 0x3C  # signal level, an i8: 60 dBm
    header[7] = 10  # SNR
    header[8:12] = struct.pack(">I", 5)  # frame number
    header[12] = sub_type
    return bytes(header) + payload


def udp(payload, dport=UDP_PORT_GSMTAP, sport=54321):
    """A UDP header whose checksum is zero: optional over IPv4, and unused."""
    return struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload


def ipv4(packet, protocol=17, flags=0x4000, options=b"", src="127.0.0.1", dst="127.0.0.1"):
    """An IPv4 header in front of `packet`, with a checksum that verifies."""
    ihl = 5 + len(options) // 4
    total = 20 + len(options) + len(packet)
    header = bytearray(
        struct.pack(
            ">BBHHHBBH4s4s",
            (4 << 4) | ihl,
            0,
            total,
            0x1234,
            flags,
            64,
            protocol,
            0,
            octets(src),
            octets(dst),
        )
    )
    header[10:12] = struct.pack(">H", checksum(bytes(header)))
    return bytes(header) + options + packet


def raw(packet):
    """A packet that is not IPv4 at all, for the containers that must be skipped."""
    return packet


def identity_request(code):
    """An Identity request whose identity-type nibble is `code`."""
    return bytes([0x07, 0x55, code, 0x00])


def mobile_identity(value, digits="0123456789"):
    """A Mobile Identity IE: length octet, then the type in its low three bits."""
    contents = bytes([value & 0x07]) + bytes.fromhex(digits)
    return bytes([len(contents)]) + contents


def identity_response(value):
    """An Identity response: its type is inside the Mobile Identity IE, not a
    fixed nibble, which is why the request's rule cannot be reused here."""
    return bytes([0x07, 0x56]) + mobile_identity(value)


def record(index, packet):
    """One PCAP record, a second apart with a millisecond step between them."""
    return (1_700_000_000 + index, index * 1_000, packet)


def pcap(records, linktype=LINKTYPE_RAW, nanoseconds=False, big_endian=False):
    """A classic libpcap file. The magic declares byte order *and* resolution."""
    endian = ">" if big_endian else "<"
    magic = 0xA1B2_3C4D if nanoseconds else 0xA1B2_C3D4
    out = bytearray(struct.pack(endian + "IHHIIII", magic, 2, 4, 0, 0, 65535, linktype))
    for secs, micros, packet in records:
        subsecs = micros * 1000 if nanoseconds else micros
        out += struct.pack(endian + "IIII", secs, subsecs, len(packet), len(packet))
        out += packet
    return bytes(out)


def nas_packets():
    """The LTE NAS frames, in a fixed order, as bare GSMTAP frames."""
    frames = []

    for code in sorted(NAMED_EMM):
        # A named EMM message: discriminator, message type, and two spare
        # octets standing in for a body this stage does not read.
        frames.append(gsmtap(bytes([0x07, code, 0x07, 0x00])))

    for code in UNNAMED_EMM:
        frames.append(gsmtap(bytes([0x07, code, 0x07, 0x00])))

    # Identity requests: every code the spec assigns and the ones it does not,
    # so an unknown label is pinned beside the known ones.
    for code in range(8):
        frames.append(gsmtap(identity_request(code)))

    # Identity responses, same eight codes, different rule for finding them.
    for code in range(8):
        frames.append(gsmtap(identity_response(code)))

    # A security-protected container whose payload begins with a plain-looking
    # NAS header. Opening it is the bug this case exists to catch: the message
    # type of a protected message is inside the encrypted part, so reporting
    # 0x55 for it would be inventing a fact about a message never read.
    frames.append(gsmtap(bytes([0x07, 0x55, 0x01, 0x00]) + b"\xa5" * 8, sub_type=1))
    # The other protected kind, with a payload that is not a NAS header at all.
    frames.append(gsmtap(bytes([0x07, 0x41]) + b"\x5a" * 12, sub_type=3))

    # Not EMM: discriminator 2 is the session-management messages, and 6 is
    # unassigned. Both are LTE NAS frames, so both are events; neither has an
    # EMM message type to tally.
    frames.append(gsmtap(bytes([0x02, 0xD1, 0x3E, 0x00, 0x00, 0x00])))
    frames.append(gsmtap(bytes([0x06, 0x00])))

    # A GSMTAP header with no NAS PDU: an event of zero message, which is what
    # a radio can emit.
    frames.append(gsmtap(b""))
    # And one octet, a discriminator with no message type after it.
    frames.append(gsmtap(bytes([0x07])))

    return frames


def skip_packets():
    """Containers and frames that must be skipped, each labelled with why."""
    nas = gsmtap(identity_request(1))
    rrc = gsmtap(bytes(range(33)), gsmtap_type=GSMTAP_LTE_RRC)

    return [
        # Valid GSMTAP, but not the LTE NAS payload type.
        ("GSMTAP LTE_RRC", ipv4(udp(rrc))),
        ("GSMTAP type 0x11", ipv4(udp(gsmtap(b"\x00\x01\x02\x03", gsmtap_type=0x11)))),
        # A NAS frame on the wrong UDP port: not the GSMTAP port.
        ("UDP/4730", ipv4(udp(nas, dport=4730))),
        # The same frame over TCP: GSMTAP is UDP, and the offsets are UDP's.
        ("TCP", ipv4(nas, protocol=6)),
        # IPv4 that is not v4.
        ("ARP", raw(b"\x00\x01\x08\x00" + bytes(24))),
        ("IPv6", raw(b"\x60\x00\x00\x00" + bytes(36))),
        # Shorter than an IPv4 header.
        ("4 octets", raw(b"\x00\x11\x22\x33")),
        # A GSMTAP frame whose version octet is not 2.
        ("gsmtap version 1", ipv4(udp(b"\x01\x04\x12" + bytes(13) + identity_request(1)))),
        # A header length below the 16 octets GSMTAP has always had.
        ("hdr_len 2 words", ipv4(udp(b"\x02\x02\x12" + bytes(13) + identity_request(1)))),
        # A header length that claims more octets than the frame holds.
        ("hdr_len past end", ipv4(udp(gsmtap(identity_request(1), hdr_len_words=8)[:20]))),
        # Three octets: cannot be a header.
        ("3 octets", ipv4(udp(nas[:3]))),
        # An empty UDP payload.
        ("empty payload", ipv4(udp(b""))),
        # A first fragment: the UDP header is there, the NAS PDU is not whole.
        ("more fragments", ipv4(udp(nas), flags=0x2000)),
        # A later fragment: no UDP header where one would be looked for.
        ("fragment offset", ipv4(udp(nas), flags=0x0001)),
        # IPv4 options: the UDP header moves, so a parser that assumes a
        # 20-octet header would read the option octets as a GSMTAP header.
        ("ipv4 options", ipv4(udp(nas), options=b"\x05\x03\x00\x00")),
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--outdir", default="captures", help="where to write the captures")
    args = parser.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    frames = nas_packets()
    nas_records = [record(i, ipv4(udp(frame))) for i, frame in enumerate(frames)]

    skips = skip_packets()
    skip_records = [record(i, packet) for i, (_why, packet) in enumerate(skips)]
    # And one real NAS frame, last: the skip path has to be seen beside a parse,
    # or a front-end that reads nothing at all would pass every skip test.
    skip_records.append(record(99, ipv4(udp(gsmtap(identity_request(1))))))

    written = []
    for name, data in [
        ("nas.pcap", pcap(nas_records)),
        ("skips.pcap", pcap(skip_records)),
        ("nas_be.pcap", pcap(nas_records, big_endian=True)),
        ("nas_ns.pcap", pcap(nas_records, nanoseconds=True)),
    ]:
        (outdir / name).write_bytes(data)
        written.append((name, len(data)))

    print(f"{'file':<14}{'bytes':>9}  contents")
    for name, size in written:
        print(f"{name:<14}{size:>9}  ", end="")
        if name.startswith("skips"):
            print(f"{len(skips)} frames to skip + 1 NAS event")
        elif name.endswith("_be.pcap"):
            print(f"{len(frames)} NAS frames, big-endian container")
        elif name.endswith("_ns.pcap"):
            print(f"{len(frames)} NAS frames, nanosecond timestamps")
        else:
            print(f"{len(frames)} NAS frames, all events")

    # What the front-end owes for `nas.pcap`, stated here so the comparison
    # script has one source for the expectation.
    protected = 2
    non_emm = 2
    short = 2  # the zero-length and one-octet NAS PDUs
    emm = len(NAMED_EMM) + len(UNNAMED_EMM) + 16  # named, unnamed, identity req/resp
    print(
        f"\nnas.pcap expectation: {len(frames)} events = "
        f"{emm} EMM + {protected} protected + {non_emm} non-EMM; "
        f"{short} of the EMM events carry no message type at all"
    )


if __name__ == "__main__":
    main()
