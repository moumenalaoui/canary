//! CANARY's cellular side: LTE signaling observations, and the input
//! front-ends that feed them.
//!
//! [`signaling`] is the model: what a NAS message looks like once CANARY has
//! decided how deeply to read it. Two front-ends fill it, independently of each
//! other —
//!
//! - [`rayhunter_import`] reads the JSON emitted by the external
//!   `rayhunter-check` CLI, and reports that tool's findings in CANARY's
//!   vocabulary.
//! - `nas_stream` (next) reconstructs the signaling sequence itself, by
//!   streaming a PCAP capture off disk.

pub mod rayhunter_import;
pub mod signaling;
