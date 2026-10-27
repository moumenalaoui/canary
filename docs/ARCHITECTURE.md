# CANARY — Architecture & Decision Log

The design of CANARY and the reasoning behind each major choice. If you are
picking this project up fresh (a new agent, or a new planning session), read
this top to bottom. The rules derived from it are in `/AGENTS.md`.

---

## What CANARY is

Low-cost, **fixed** passive sensors that detect anomalous cellular and network
activity around a site — most importantly, signs of a fake cell tower (IMSI
catcher / cell-site simulator). The long-term vision is a purpose-built static
sensor deployable in numbers across a facility, spanning three layers:

| Layer | Hardware | Senses | Status |
|---|---|---|---|
| **RF / physical** | RTL-SDR | Raw spectrum: rogue carriers, signal anomalies | Not started (exploratory) |
| **Cellular control-plane** | Orbic RC400L + Rayhunter | LTE signaling (NAS/RRC): identity requests, downgrades, SIBs | **In progress** |
| **IP / network** | Raspberry Pi + Zeek/Suricata | IP traffic: resolver bypass, beaconing, first-seen destinations | Not started |

The **differentiated value** is not any single layer — Rayhunter already does
cellular-only detection. It is (a) a **fixed-location baseline** ("what is normal
*here*"), (b) **cross-layer correlation** (a cellular anomaly *and* a network
anomaly at the same instant = far higher confidence), and (c) a **conservative
confidence model**. Those three are what make CANARY more than "Rayhunter
re-implemented." They are largely still ahead of us.

---

## The decisions (ADR-style)

**D1 — Consume Rayhunter's output, never its code.** Rayhunter is GPLv3. Linking
its code would force CANARY to be GPL too, killing the possibility of a private
core / commercial path. The GPL covers code, not the *data a program emits*, so
CANARY shells out to / reads the output of `rayhunter-check` (JSON reports, and
the pcap/pcapng it converts QMDL into) and parses that. This single constraint
dictates the whole architecture: link nothing, copy nothing, parse outputs.

**D2 — The Orbic IS the cellular sensor (for now).** A normal phone's modem sees
LTE signaling but locks it inside the baseband. The Orbic RC400L's Qualcomm diag
interface can be opened; Rayhunter logs that. It is a modem repurposed as a
control-plane sensor — and the control plane is where a catcher reveals itself
(asking for IMSI without auth, forcing 2G, incomplete SIBs). An RTL-SDR cannot
decode LTE control-plane signaling (that path is what killed Crocodile Hunter);
it serves the separate RF layer. The analysis software is hardware-independent
(consumes standard GSMTAP), so it survives swapping the Orbic for a future
purpose-built sensor.

**D3 — NAS first, RRC deferred.** The catcher signals split by encoding
difficulty. **NAS** (identity requests, authentication) is TLV/byte-structured —
hand-parseable, and that is what the cellular front-end does today. **RRC** (SIB
chains, LTE→2G redirects) is ASN.1 / UPER — bit-packed and schema-dependent, not
hand-rollable. A permissively-licensed path exists for RRC later: regenerate RRC
types from the public 3GPP ASN.1 spec using **hampi** (Apache/MIT) — NOT
Rayhunter's generated `telcom-parser` (GPL).

**D4 — tshark as an independent oracle.** Self-written tests encode the same
assumptions as the parser and stay green on wrong logic. tshark (Wireshark) is a
second, independent dissector that never saw our reasoning; the parser's output
must match it. This has repeatedly caught real bugs that unit tests missed (a
secure-subtype mislabel; a PD-before-SHT ordering bug) and even caught errors in
the task specs before code was written. Divergences from tshark are
*pre-declared* into legitimate classes (protected frames we won't decode,
RRC-carried NAS we can't see yet, truncated PDUs); anything outside those classes
is treated as a parser bug.

**D5 — Severity and Confidence are separate axes.** `Severity`
(Informational/Low/Medium/High) mirrors the upstream tool's "how alarming."
`Confidence` (Unconfirmed/Suspicious/Confirmed) is CANARY's own "how sure it's a
real catcher." Imported/field data is never auto-`Confirmed`. Forensic honesty:
an anomaly is an observation, not a verdict.

---

## The cellular pipeline (today)

```
QMDL capture ──(rayhunter-check -P, run by the user, offline)──▶ pcapng (raw IPv4)
                                                                     │
  CANARY canary-cellular:                                            ▼
  pcap/pcapng ─▶ IPv4 ─▶ UDP(4729) ─▶ GSMTAP ─▶ [type 0x12 = LTE NAS] ─▶ classify_nas
                                                                     │
                                                       stream of SignalingEvent
```

- Input is **pcapng, raw-IPv4 linktype (228)**, as `rayhunter-check -P` emits.
- Only GSMTAP **type 0x12 (LTE NAS)** is parsed. RRC (0x0d) is skipped (deferred).
- NAS decoding reads the message *type* only; protected (ciphered) bodies are not
  decoded. Reading depth stops where honesty does.
- A second front-end (`rayhunter_import`) ingests `rayhunter-check` JSON reports
  into the same `Anomaly`/`Report` model.

## Known limitations (deliberate, documented)

- **NAS carried inside RRC is invisible.** Much LTE NAS travels inside RRC
  messages; CANARY reads only standalone GSMTAP NAS frames. So NAS visibility is
  *partial* until RRC parsing lands — some identity requests may be RRC-carried.
  This is the strongest argument for prioritizing the RRC work.
- Protected/ciphered NAS bodies are not decoded.
- No baseline and no cross-layer correlation yet — the differentiated value is
  not yet built.
