//! CANARY's cellular side: LTE signaling observations, and the input
//! front-ends that feed them.
//!
//! Today the only front-end is [`rayhunter_import`], which reads the JSON
//! emitted by the external `rayhunter-check` CLI. Native reconstruction from
//! raw captures is not implemented yet.

pub mod rayhunter_import;
