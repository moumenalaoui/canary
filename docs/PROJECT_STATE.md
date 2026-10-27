# CANARY — Project State & Handoff

A living snapshot of where the project is, how we work, and what's next. **Keep
this updated as work lands.** If you are a fresh planning/architect session
picking CANARY up, this plus `ARCHITECTURE.md`, `AGENTS.md`, and the project
memory are your full context.

_Last updated: 2026-10-27_

---

## How we work

- **Roles.** A strong model plans and reviews (decomposition, task specs,
  judgment calls, architectural review). A cheaper proven model (DeepSeek V3.2)
  implements well-specified, bounded tasks. An independent reviewer step
  verifies the "done" gate. Strength goes to the low-token, high-judgment roles;
  the cheap model carries the implementation volume. Priority order:
  **code quality > cost > speed.**
- **The loop that works.** Decompose small → specify precisely (with acceptance
  criteria) → implement → validate against an independent oracle + cargo gates →
  review before merge. The complexity is managed by this *process*, not by model
  brilliance. Do not drop the specs or the review when parallelizing.
- **Git flow.** One feature = one worktree = one branch off `main`; PR to `main`;
  reviewer (not the author) clears the merge. `main` stays green and
  Pi-pullable. Foundational infra/docs may go straight to `main`; feature work
  is PR-only.
- **Hardware is offline.** No layer needs live hardware in the dev loop. Agents
  develop against recorded sample data in `data/` (gitignored); hardware
  produces that data separately (user plugs in the SDR / runs Rayhunter / runs
  Zeek on the Pi, drops a sample in `data/`).

---

## Done

- **canary-core** — shared model: `Severity`, `Confidence`, `Source`, `Anomaly`,
  `Report`. Imports never auto-`Confirmed`.
- **canary-cellular / rayhunter_import** — parses `rayhunter-check` JSON reports
  into the core model (conservative severity→confidence mapping).
- **canary-cellular / GSMTAP→NAS reconstruction** — streaming parser:
  pcap + pcapng (raw-IPv4), IPv4/UDP/GSMTAP framing, LTE NAS (EMM) message
  classification, identity-type extraction. Memory-safe (no panics in parse
  path). Validated against tshark on synthetic captures AND a real 60k-frame
  capture; two real bugs caught by the oracle and fixed. Merged to `main`.
- **Tooling** — `scripts/gen_gsmtap_pcap.py` (synthetic captures, stdlib-only),
  `scripts/oracle_compare.sh` (tshark oracle comparison).

## Next (in priority order)

1. **RRC parsing (cellular).** Regenerate RRC types from 3GPP ASN.1 via **hampi**
   (Apache/MIT), decode SIB1 + RRCConnectionRelease. Unlocks incomplete-SIB and
   LTE→2G-redirect detection AND closes the NAS-in-RRC visibility gap. Finicky
   (ASN.1 codegen integration) — spec to known-good hampi/spec versions; architect
   stays close. Serial on `canary-cellular`.
2. **Classifier (cellular).** Identity-request-without-auth detection on the
   reconstructed NAS/RRC sequence. Depends on #1 for complete NAS visibility.
   Serial on `canary-cellular`.
3. **Network layer (canary-network).** Zeek/Suricata log ingest → events →
   resolver bypass, beaconing, first-seen destinations. Separate crate, genuine
   parallel track. Needs a sample Zeek/Suricata log in `data/`.
4. **Baseline + cross-layer correlation.** The actual differentiator. After the
   layers produce events.
5. **RF layer (RTL-SDR).** Still exploratory — needs a design pass (what it
   detects, what sample IQ data, what "done") BEFORE it becomes an agent task.
   Architect work first, not an implementer task yet.

## Parallelization plan

- **Serial:** cellular track (RRC → classifier; both touch `canary-cellular`).
- **Parallel:** `canary-network` (separate crate, no overlap).
- **Coordinated:** any `canary-core` change (shared dep — never forked across
  worktrees).

## Open items / parking lot

- `rayhunter_import` errored on a **real** `report.json` (from rayhunter 0.13.0);
  the synthetic fixture passes. Likely the importer's strictness vs real schema.
  Not blocking; revisit before relying on the JSON import path.
- RF layer needs scoping (see Next #5).
- Branch protection on `main` to be enabled before the multi-agent fan-out.
