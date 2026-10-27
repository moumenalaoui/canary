# CANARY — Terminology Cheat Sheet

A plain-language reference for the terms that come up building CANARY. Organized
by area. "Why it matters" is written from CANARY's point of view, not the textbook.

---

## 1. The threat

**IMSI catcher** (aka **Stingray**, **cell-site simulator / CSS**, **fake base
station**, **rogue eNodeB**) — A device that pretends to be a legitimate cell
tower so nearby phones connect to it. Once connected, it can capture identifiers,
track location, force weaker encryption, or intercept traffic. CANARY exists to
detect these.

**Downgrade attack** — Forcing a phone from secure 4G/LTE down to weak 2G/GSM,
where interception is easy. A catcher does this by faking network messages. One
of CANARY's target signals (the "LTE→2G redirect").

**Null cipher (EEA0)** — "Encryption turned off." Legit networks almost never use
it; catchers do, because they lack the real keys. A detectable red flag.

---

## 2. Cellular identifiers (what a catcher wants)

**IMSI** (International Mobile Subscriber Identity) — Your SIM's *permanent*
identity. The crown jewel a catcher tries to grab. A tower demanding your IMSI
without authenticating is the classic catcher signature.

**IMEI** (International Mobile Equipment Identity) — The *device's* permanent
hardware ID (the phone, not the SIM).

**IMEISV** — IMEI plus a software-version field.

**TMSI / GUTI** — *Temporary* identities the network assigns so your permanent
IMSI isn't sent over the air constantly. Normal networks use these; a catcher
often can't, so it falls back to requesting the IMSI — which is the tell.

**PLMN** (Public Land Mobile Network) — A carrier's network ID (country code +
network code). Identifies which operator a tower claims to belong to.

---

## 3. Cellular protocol layers & messages

**eNodeB** — The technical name for a 4G/LTE base station (a cell tower's radio).

**Control plane vs. user plane** — Control plane = the *signaling* that sets up
and manages your connection (who you are, authentication, which tower to use).
User plane = your actual data (web traffic). CANARY's cellular layer watches the
**control plane** — that's where catchers reveal themselves.

**NAS** (Non-Access Stratum) — The signaling layer between your phone and the
core network (authentication, attach, identity requests). **This is what the
CANARY cellular parser reconstructs.** NAS is relatively simple (byte/TLV-based),
which is why we could hand-parse it.
  - **EMM** (EPS Mobility Management) — the NAS sub-protocol for mobility/identity
    (attach, identity request, authentication). The messages CANARY cares about.
  - **ESM** (EPS Session Management) — the NAS sub-protocol for data sessions.
    CANARY tags these as "Non-EMM" and largely ignores them.

**RRC** (Radio Resource Control) — The signaling layer between your phone and the
*tower* (radio setup, system info, connection release). Carries the SIB and
redirect messages. **RRC is ASN.1/UPER-encoded (hard to parse)** — deferred to a
later milestone.

**SIB** (System Information Block) — Broadcast messages a tower sends telling
phones how to use it. **SIB1** is the first/essential one.
  - **Incomplete SIB** — a real tower sends a full chain (SIB3, 5, etc.); a lazy
    catcher sends only SIB1 + one more. A CANARY detection signal.
  - **SIB6/7** — carry 2G/3G neighbor info; a catcher abuses these to lure phones
    into a downgrade.

**Identity Request chain** — CANARY's core cellular signature:
`phone connects → tower asks for IMSI/IMEI → authentication does NOT happen →
tower drops the connection`. Legit towers authenticate; a catcher grabs the
identity and bails.

**Authentication Request / Response** — The exchange where the network proves
it's legit. Its *absence* after an identity request is the suspicious part.

**Security Mode Command** — Where encryption gets turned on. A null cipher here
is a red flag.

---

## 4. Capture formats & tools

**QMDL** — Qualcomm's raw diagnostic log format. What the Orbic's baseband emits
and Rayhunter records. Proprietary and messy — CANARY does **not** parse this
directly.

**GSMTAP** — A standard (osmocom) format that wraps decoded cellular messages so
tools like Wireshark can read them. Rayhunter converts QMDL → GSMTAP. **This is
the layer CANARY parses.** (Despite the "network packet" look, GSMTAP carries
*cellular signaling*, not IP traffic.)

**pcap / pcapng** — Standard packet-capture file formats. `pcapng` is the newer
one. `rayhunter-check -P` outputs **pcapng**. CANARY reads both.

**DLT / linktype** — A number in a capture file saying what the packets are.
Rayhunter writes **"raw IPv4"** (linktype 228) — packets start directly with an
IP header, no Ethernet. CANARY has to know this to find where the data begins.

**ASN.1 / PER / UPER** — A way of describing and bit-packing message formats,
used by RRC. **UPER** (Unaligned Packed Encoding Rules) is bit-level and
schema-dependent — you can't read a field at a fixed offset. This is why RRC is
hard and NAS is easy.

**tshark / Wireshark** — The standard packet dissector. CANARY uses **tshark as
an independent oracle**: it decodes the same capture, and CANARY's output must
match it. This catches bugs that self-written tests miss.

**capinfos** — A small tool (ships with Wireshark) that reports a capture's
format, link type, and packet count.

---

## 5. The Rayhunter / CANARY ecosystem

**Rayhunter** — EFF's current open-source IMSI-catcher detector. Runs on a
modified Orbic hotspot, records the cellular control plane, flags suspicious
patterns. **GPLv3** — so CANARY consumes its *output*, never its code.

**rayhunter-check** — Rayhunter's desktop CLI. Analyzes a QMDL/pcap capture and
can convert QMDL → pcapng (`-P`) and emit a JSON report (`-j`). CANARY feeds on
its output.

**Crocodile Hunter** — Rayhunter's *predecessor* (2020, EFF). SDR-based, built on
srsLTE, hard to run, abandoned Dec 2022. The cautionary tale — its failures
(build pain, expensive hardware, external-DB dependence) are things CANARY's
design avoids.

**srsLTE** — An open-source software LTE stack (C++). What Crocodile Hunter used
to decode LTE from raw radio. Heavy and finicky — CANARY avoids it.

**Orbic RC400L** — The cheap hotspot Rayhunter runs on. Its Qualcomm baseband
diagnostic port can be opened, which is what makes it a cellular sensor.

**RTL-SDR** — A ~$30 software-defined radio (receive-only). Good for raw RF/
spectrum monitoring (CANARY's RF layer), **not** powerful enough to decode LTE
control-plane signaling (that's the Orbic's job).

**hampi / asn1-codecs** — A permissively-licensed (Apache/MIT) Rust toolkit that
can generate RRC decoders from the public 3GPP ASN.1 spec. The clean path to
RRC support later, without touching Rayhunter's GPL code.

---

## 6. CANARY's own concepts

**Sensor layers** — CANARY is designed to span three: **RF** (RTL-SDR),
**cellular control-plane** (Orbic + the software we're building), and **IP
network** (Raspberry Pi + Zeek/Suricata). The real value is *correlating* them.

**Baseline** — A model of "what normal looks like *at this fixed location*."
CANARY flags *deviations* from it, rather than relying on external tower
databases (which rot). Built from your own green captures.

**SignalingEvent** — CANARY's internal representation of one reconstructed NAS
message (type + timestamp). The parser turns a capture into a stream of these.

**Severity vs. Confidence** — Two *separate* axes, deliberately:
  - **Severity** (Informational / Low / Medium / High) — how alarming a signal
    is. Mirrors Rayhunter's scale, used when importing.
  - **Confidence** (Unconfirmed / Suspicious / Confirmed) — how sure CANARY is
    it's a *real* catcher. **Imported/field data is never auto-marked
    "Confirmed"** — forensic honesty: an anomaly is an observation, not a verdict.

---

## 7. The network layer (not built yet — bullet 2)

**Zeek** — A network-traffic analysis tool that turns raw IP traffic into
structured logs (connections, DNS, etc.).

**Suricata** — An intrusion-detection engine that flags suspicious network
patterns against rules.

**Resolver bypass** — A device sending DNS to something other than the configured
resolver — a sign of misconfiguration or evasion.

**Beaconing** — Regular, periodic outbound connections (like clockwork) — often
malware calling home, sometimes just vendor telemetry.

**First-seen destination** — A connection to somewhere never seen in the baseline
— worth a look.

---

## 8. Dev / build tooling

**Rust** — CANARY's main language. Memory-safe, which matters for parsing
untrusted capture data.

**crate** — A Rust package/library. CANARY has `canary-core`, `canary-cellular`,
`canary-network`.

**workspace** — A set of crates built together under one repo. CANARY is one
workspace with three member crates.

**cargo** — Rust's build tool. `cargo build` / `cargo test`.

**clippy** — Rust's linter. We run `cargo clippy -- -D warnings` as a hard gate —
the code isn't "done" until it's clean.

**GPLv3** — A copyleft license: if you link GPL code into your program, your
program must also be GPL. Why CANARY consumes Rayhunter's *output*, never links
its code — so CANARY stays free to license (and potentially commercialize).
