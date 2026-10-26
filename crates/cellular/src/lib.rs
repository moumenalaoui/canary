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
//! - [`nas_stream`] reconstructs the signaling sequence itself, by streaming a
//!   PCAP capture off disk. It reaches the NAS message through [`gsmtap`],
//!   which knows only the container's fixed byte offsets.

pub mod gsmtap;
pub mod nas_stream;
pub mod rayhunter_import;
pub mod signaling;

#[cfg(test)]
mod test_support;
