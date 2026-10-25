## CANARY

Passive sensor tooling for detecting anomalous cellular and network activity around a site (fake cell towers - IMSI-catchers).

### Layout

- `crates/core` — shared event / baseline / anomaly model
- `crates/cellular` — LTE signaling reconstruction from Rayhunter (EFF Labs) captures
- `crates/network` — passive IP-layer sensor (Zeek / Suricata → events)
