# AGENTS.md — rules for any agent working on CANARY

You are working on **CANARY**: low-cost, fixed passive sensors that detect
anomalous cellular and network activity around a site — above all, signs of a
fake cell tower (IMSI catcher). This file is the contract. Follow it exactly.
For *why* behind these rules, read `docs/ARCHITECTURE.md`; for where the project
stands and what's next, read `docs/PROJECT_STATE.md`; for unfamiliar terms, read
`docs/GLOSSARY.md`.

---

## Non-negotiable rules

1. **GPL boundary — never link or copy Rayhunter.** Rayhunter (EFForg/rayhunter)
   is GPLv3. CANARY consumes its *output* only (its JSON reports, and the
   pcap/pcapng it emits). NEVER add `rayhunter` or any EFF/Rayhunter crate as a
   dependency. NEVER copy, translate, or paste Rayhunter source. Re-implement
   ideas from public specs (3GPP, osmocom) and the prose of their docs, not from
   their code. This keeps CANARY independently licensable.

2. **Memory safety in parse paths.** CANARY parses untrusted capture data. In any
   code that touches captured bytes: NO `unwrap()`, `expect()`, `panic!`,
   `unreachable!`, or raw `slice[i]` indexing. Use `.get()`, length checks before
   slicing, and `checked_*` arithmetic. A malformed packet must never crash the
   stream — it is *skipped and counted*, not fatal.

3. **Stay in your crate / feature.** Work only in the crate your task names.
   `canary-core` is the shared vocabulary — changes to it are coordinated by the
   planner, never made unilaterally from a feature worktree (two worktrees
   editing core = merge conflicts at integration).

4. **Validation is external, not self-certified.** Self-written unit tests are
   necessary but NOT sufficient — they encode the same assumptions as the code
   and stay green on wrong logic. Every parser is validated against an
   **independent oracle** (for cellular: `tshark`). When the oracle disagrees,
   assume the parser is wrong until proven otherwise; never edit counts to match.

5. **Conservative classification.** An anomaly is an observation, not a verdict.
   Imported or field data is NEVER marked `Confidence::Confirmed` — that is
   reserved for multi-signal corroboration. Default to `Unconfirmed`.

6. **Captures never enter git.** Raw captures (`*.qmdl`, `*.pcap`, `*.pcapng`,
   `*.iq`, Zeek/Suricata logs) can carry other people's identifiers and reveal
   location/time. They live in `data/` (gitignored). Commit only derived,
   scrubbed summaries.

---

## Definition of "done" (the gate — a task is NOT done until ALL pass)

**Common floor (every task):**
- `cargo build` — clean
- `cargo clippy --all-targets -- -D warnings` — clean (fix warnings; do NOT `#[allow]` them)
- `cargo test` — green
- `cargo fmt` — applied to new code
- No Rayhunter/EFF dependency anywhere; no captures committed
- Scope respected (only the crate/feature the task named)
- No panics/unwraps/indexing in parse paths

**Per-task acceptance criteria:** defined in the task spec itself. The planner
writes them; the reviewer verifies them. If your task has no explicit acceptance
criteria beyond the floor, ask — do not invent them.

---

## Workflow

- **One feature = one worktree = one branch** off `main`. Never commit feature
  work directly to `main`.
- Open a **PR to `main`**; do not merge your own PR. Review is a separate step.
- **Conventional commits**: `feat(scope):`, `fix(scope):`, `chore(scope):`,
  `docs(scope):`. Each commit should build + clippy + test green, not just the
  final one.
- Before pushing, run the full gate above and paste its output in the PR.
- The PR description carries the **validation evidence** (e.g. the oracle table),
  not just a prose summary.

---

## Repo layout

```
crates/
  core/      (canary-core)     shared vocabulary: Severity, Confidence, Source, Anomaly, Report
  cellular/  (canary-cellular) capture → GSMTAP → NAS reconstruction; rayhunter JSON import
  network/   (canary-network)  IP-layer sensor (Zeek/Suricata) — early
scripts/     gen_gsmtap_pcap.py (stdlib-only), oracle_compare.sh (tshark oracle)
docs/        ARCHITECTURE.md, PROJECT_STATE.md, GLOSSARY.md
data/        gitignored — raw captures live here, never committed
```

Python tooling uses a local `.venv` (gitignored); scripts are stdlib-only today.
