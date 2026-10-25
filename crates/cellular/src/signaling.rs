//! CANARY's own model of LTE NAS signaling observed in a capture.
//!
//! This is the output vocabulary of the native PCAP front-end, the counterpart
//! of what [`crate::rayhunter_import`] produces from a third party's JSON. It
//! is deliberately *not* in `canary-core`: `core` holds the anomaly and report
//! types every front-end shares, while these types describe one radio
//! technology's signaling layer and mean nothing to the network side.
//!
//! ## Why decoding stops at the message type
//!
//! Each event records *which* NAS message occurred and *when* — nothing about
//! what the message contained. Two reasons, both deliberate:
//!
//! - **A protected NAS body cannot be read, so anything claimed about it would
//!   be fabricated.** When the security header type is non-zero — whether the
//!   NAS message says so itself or the container carrying it does — the body is
//!   integrity-protected and/or ciphered with keys we do not hold. The only
//!   honest output is [`SignalingKind::ProtectedNas`] carrying the type that
//!   told us so. We do not look past byte 0 of such a payload, not even when the
//!   following bytes happen to look like a plain header.
//! - **Reconstruction is all this stage needs.** Catcher behaviour shows up in
//!   the *sequence* of signaling messages — an IMSI request with no preceding
//!   authentication, repeated attach rejection — which the message types alone
//!   already expose. Per-message IE parsing is a separate, later concern.
//!
//! The one field extracted beyond the message type is the identity of a plain
//! Identity Request/Response, because a single octet there decides how alarming
//! the request is. It is never read from a protected message.

use chrono::{DateTime, FixedOffset};
use serde::{Deserialize, Serialize};

/// The identity a plain Identity Request asked for, or a plain Identity
/// Response supplied.
///
/// The three-bit codes behind this come from TS 24.301 and were verified
/// against Wireshark's NAS-EPS dissector: `1`, `2`, `3`, `4` decode as IMSI,
/// IMEI, IMEISV and TMSI in both the request and the response space, and every
/// other code decodes as unknown there.
///
/// There is intentionally no `GUTI` variant yet, so that no variant here is one
/// the parser can never produce:
///
/// - In a *request*, code 5 is the value TS 24.301 assigns to GUTI, but the
///   dissector we validate against prints it as unknown, and CANARY does not
///   name a code it cannot corroborate. It stays `Unknown(5)`.
/// - In a *response*, code 4 covers the whole TMSI/P-TMSI/GUTI family: telling
///   them apart needs a sub-field of the Mobile Identity IE that this task does
///   not parse, so the family is reported as [`IdentityType::Tmsi`]. A later
///   task that does that disambiguation adds the missing variants instead of
///   guessing them here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IdentityType {
    /// International Mobile Subscriber Identity.
    Imsi,
    /// International Mobile Equipment Identity.
    Imei,
    /// IMEI with software version number.
    Imeisv,
    /// Temporary Mobile Subscriber Identity. In an Identity Response this also
    /// covers P-TMSI and GUTI, which share code 4 and are not disambiguated
    /// here — see the type-level note.
    Tmsi,
    /// A code with no corroborated meaning, reported as the raw bits.
    Unknown(u8),
}

impl IdentityType {
    /// Map a three-bit identity code, ignoring the other bits of its octet.
    pub(crate) fn from_code(code: u8) -> Self {
        match code & 0x07 {
            1 => IdentityType::Imsi,
            2 => IdentityType::Imei,
            3 => IdentityType::Imeisv,
            4 => IdentityType::Tmsi,
            other => IdentityType::Unknown(other),
        }
    }

    /// Read the identity type out of a plain Identity Response's Mobile
    /// Identity IE.
    ///
    /// A response does not put the type where a request does: byte 2 is the
    /// *length* of the mobile identity and the type is in the low 3 bits of
    /// byte 3. Applying the request's rule here would read the length as a
    /// type, which is how a parser ends up calling every response
    /// `Unknown(8)` — a length of 8 octets is the ordinary IMSI case.
    ///
    /// A response truncated before the type octet yields `Unknown(0)`: code 0
    /// already means "no identity" in this space, and
    /// [`SignalingEvent::payload_len`] exposes the truncation.
    pub(crate) fn from_mobile_identity_ie(payload: &[u8]) -> Self {
        // `payload` is the whole NAS message: [PD+0][0x56][length][type][digits..]
        Self::from_code(payload.get(3).copied().unwrap_or(0))
    }
}

impl std::fmt::Display for IdentityType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IdentityType::Imsi => f.write_str("IMSI"),
            IdentityType::Imei => f.write_str("IMEI"),
            IdentityType::Imeisv => f.write_str("IMEISV"),
            IdentityType::Tmsi => f.write_str("TMSI"),
            IdentityType::Unknown(code) => write!(f, "Unknown({code})"),
        }
    }
}

/// Which LTE NAS message occurred.
///
/// The plain EMM variants are the message types CANARY cares about most. The
/// three catch-all variants mean "this was NAS traffic, and here is what could
/// be told about it without decoding further" — a real reconstruction outcome,
/// not a failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SignalingKind {
    /// 0x41
    AttachRequest,
    /// 0x44
    AttachReject,
    /// 0x45
    DetachRequest,
    /// 0x48
    TrackingAreaUpdateRequest,
    /// 0x4b — not 0x4c; 0x4c is Extended Service Request.
    TrackingAreaUpdateReject,
    /// 0x4c
    ExtendedServiceRequest,
    /// 0x4d
    ControlPlaneServiceRequest,
    /// 0x52
    AuthenticationRequest,
    /// 0x53
    AuthenticationResponse,
    /// 0x54
    AuthenticationReject,
    /// 0x55, with the identity that was requested.
    IdentityRequest { id_type: IdentityType },
    /// 0x56, with the identity that was supplied.
    IdentityResponse { id_type: IdentityType },
    /// 0x5d
    SecurityModeCommand,
    /// 0x5e
    SecurityModeComplete,
    /// Security-protected NAS: the body is ciphered or integrity-protected, so
    /// it was not decoded at all. See the module docs.
    ProtectedNas {
        /// The security header type: 1..=3, from GSMTAP's `sub_type` when the
        /// container claimed one and from the payload's own first octet
        /// otherwise. The container's claim wins, so this is never the 0 of a
        /// plain-looking header inside a frame that says it is protected — the
        /// octet there is ciphertext, not a header.
        security_header_type: u8,
    },
    /// NAS that is not EPS Mobility Management — typically EPS Session
    /// Management. Not decoded.
    NonEmm {
        /// Low nibble of the NAS header.
        protocol_discriminator: u8,
    },
    /// Plain EMM of a type not named above.
    OtherEmm {
        /// The EMM message type octet, exactly as it appeared on the wire. EMM
        /// has no transaction-marker sub-field to mask off: Wireshark confirms
        /// the dissector only recognises the full octet, so `0xc1` is not
        /// "Attach Request with a marker" but a type we do not know. Keeping
        /// the raw octet is also what makes our counts line up with
        /// `nas_eps.nas_msg_emm_type` one-for-one.
        message_type: u8,
    },
}

impl SignalingKind {
    /// The EMM message type octet this kind was decoded from, when it came from
    /// a plain EMM message.
    ///
    /// [`SignalingKind::ProtectedNas`] and [`SignalingKind::NonEmm`] have none:
    /// there is no decoded EMM type to report for them. The binary prints this
    /// per event and the oracle comparison groups by it, so the diff lands on
    /// message codes rather than on the wording of our labels.
    pub fn emm_code(&self) -> Option<u8> {
        match self {
            SignalingKind::AttachRequest => Some(0x41),
            SignalingKind::AttachReject => Some(0x44),
            SignalingKind::DetachRequest => Some(0x45),
            SignalingKind::TrackingAreaUpdateRequest => Some(0x48),
            SignalingKind::TrackingAreaUpdateReject => Some(0x4b),
            SignalingKind::ExtendedServiceRequest => Some(0x4c),
            SignalingKind::ControlPlaneServiceRequest => Some(0x4d),
            SignalingKind::AuthenticationRequest => Some(0x52),
            SignalingKind::AuthenticationResponse => Some(0x53),
            SignalingKind::AuthenticationReject => Some(0x54),
            SignalingKind::IdentityRequest { .. } => Some(0x55),
            SignalingKind::IdentityResponse { .. } => Some(0x56),
            SignalingKind::SecurityModeCommand => Some(0x5d),
            SignalingKind::SecurityModeComplete => Some(0x5e),
            SignalingKind::OtherEmm { message_type } => Some(*message_type),
            SignalingKind::ProtectedNas { .. } | SignalingKind::NonEmm { .. } => None,
        }
    }

    /// Classify the NAS payload of an LTE NAS frame, as far as [the module
    /// docs](self) allow.
    ///
    /// `frame_sub_type` is GSMTAP's `sub_type` octet: the container's own
    /// statement of the NAS security header type, made by whatever wrote the
    /// capture rather than by the message. Any value but plain asserts a
    /// protected payload, and that claim is honoured even when the payload's
    /// first octet looks plain — reading a ciphered body as a plain header
    /// produces a wrong event rather than a lucky one.
    ///
    /// Returns `None` only when the payload is too short to identify a message
    /// at all, which the caller counts as malformed. An unrecognised EMM type
    /// is [`SignalingKind::OtherEmm`], never an error: the type space is ours to
    /// name, not the network's to conform to.
    pub fn classify(payload: &[u8], frame_sub_type: u8) -> Option<Self> {
        let header = *payload.first()?;
        let security_header_type = header >> 4;
        let protocol_discriminator = header & 0x0f;

        // The container's number is the one reported when it made a claim: the
        // first octet of a protected payload is ciphertext as far as this stage
        // knows, so its nibble is not a security header type at all.
        if frame_sub_type != SECURITY_HEADER_TYPE_PLAIN {
            return Some(SignalingKind::ProtectedNas {
                security_header_type: frame_sub_type,
            });
        }
        if security_header_type != SECURITY_HEADER_TYPE_PLAIN {
            return Some(SignalingKind::ProtectedNas {
                security_header_type,
            });
        }

        if protocol_discriminator != EMM_PROTOCOL_DISCRIMINATOR {
            return Some(SignalingKind::NonEmm {
                protocol_discriminator,
            });
        }

        // A plain EMM message always carries its type in octet 1.
        let message_type = *payload.get(1)?;
        Some(classify_emm(message_type, payload))
    }
}

impl std::fmt::Display for SignalingKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignalingKind::AttachRequest => f.write_str("Attach Request"),
            SignalingKind::AttachReject => f.write_str("Attach Reject"),
            SignalingKind::DetachRequest => f.write_str("Detach Request"),
            SignalingKind::TrackingAreaUpdateRequest => f.write_str("Tracking Area Update Request"),
            SignalingKind::TrackingAreaUpdateReject => f.write_str("Tracking Area Update Reject"),
            SignalingKind::ExtendedServiceRequest => f.write_str("Extended Service Request"),
            SignalingKind::ControlPlaneServiceRequest => {
                f.write_str("Control Plane Service Request")
            }
            SignalingKind::AuthenticationRequest => f.write_str("Authentication Request"),
            SignalingKind::AuthenticationResponse => f.write_str("Authentication Response"),
            SignalingKind::AuthenticationReject => f.write_str("Authentication Reject"),
            SignalingKind::IdentityRequest { id_type } => {
                write!(f, "Identity Request ({id_type})")
            }
            SignalingKind::IdentityResponse { id_type } => {
                write!(f, "Identity Response ({id_type})")
            }
            SignalingKind::SecurityModeCommand => f.write_str("Security Mode Command"),
            SignalingKind::SecurityModeComplete => f.write_str("Security Mode Complete"),
            SignalingKind::ProtectedNas {
                security_header_type,
            } => write!(
                f,
                "Protected NAS (security header type {security_header_type})"
            ),
            SignalingKind::NonEmm {
                protocol_discriminator,
            } => write!(
                f,
                "Non-EMM NAS (protocol discriminator {protocol_discriminator:#04x})"
            ),
            SignalingKind::OtherEmm { message_type } => {
                write!(f, "Other EMM (message type {message_type:#04x})")
            }
        }
    }
}

/// One NAS message that occurred in a capture, in capture order.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignalingEvent {
    /// When the frame was captured, from the PCAP record timestamp. PCAP
    /// timestamps are UTC, so this carries a zero offset.
    pub timestamp: DateTime<FixedOffset>,
    /// What was observed.
    pub kind: SignalingKind,
    /// Length of the NAS payload — the GSMTAP frame's contents from the NAS
    /// header on. This is what separates a genuinely short message from a
    /// truncated one.
    pub payload_len: usize,
}

/// NAS messages whose protocol discriminator is 7 are EPS Mobility Management.
const EMM_PROTOCOL_DISCRIMINATOR: u8 = 0x07;

/// The NAS security header type that means "plain NAS message, not security
/// protected" (TS 24.301 §9.2). Every other value says the body is at least
/// integrity protected, and so is not ours to read.
const SECURITY_HEADER_TYPE_PLAIN: u8 = 0x00;

/// Map the message type octet of a plain EMM message, pulling the identity out
/// of the two Identity messages.
fn classify_emm(message_type: u8, payload: &[u8]) -> SignalingKind {
    match message_type {
        0x41 => SignalingKind::AttachRequest,
        0x44 => SignalingKind::AttachReject,
        0x45 => SignalingKind::DetachRequest,
        0x48 => SignalingKind::TrackingAreaUpdateRequest,
        0x4b => SignalingKind::TrackingAreaUpdateReject,
        0x4c => SignalingKind::ExtendedServiceRequest,
        0x4d => SignalingKind::ControlPlaneServiceRequest,
        0x52 => SignalingKind::AuthenticationRequest,
        0x53 => SignalingKind::AuthenticationResponse,
        0x54 => SignalingKind::AuthenticationReject,
        0x55 => SignalingKind::IdentityRequest {
            // Requested identity: low 3 bits of octet 2.
            id_type: IdentityType::from_code(payload.get(2).copied().unwrap_or(0)),
        },
        0x56 => SignalingKind::IdentityResponse {
            id_type: IdentityType::from_mobile_identity_ie(payload),
        },
        0x5d => SignalingKind::SecurityModeCommand,
        0x5e => SignalingKind::SecurityModeComplete,
        other => SignalingKind::OtherEmm {
            message_type: other,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `07` is plain (SHT 0) + EMM (PD 7); `27` is ciphered + integrity.
    const PLAIN_EMM: u8 = 0x07;

    fn plain(message_type: u8) -> Vec<u8> {
        vec![PLAIN_EMM, message_type]
    }

    #[test]
    fn plain_emm_message_types_map_to_their_kinds() {
        // The table, pinned: this is the mapping the oracle comparison rests
        // on, including the 0x4b/0x4c correction.
        let expected = [
            (0x41u8, SignalingKind::AttachRequest),
            (0x44, SignalingKind::AttachReject),
            (0x45, SignalingKind::DetachRequest),
            (0x48, SignalingKind::TrackingAreaUpdateRequest),
            (0x4b, SignalingKind::TrackingAreaUpdateReject),
            (0x4c, SignalingKind::ExtendedServiceRequest),
            (0x4d, SignalingKind::ControlPlaneServiceRequest),
            (0x52, SignalingKind::AuthenticationRequest),
            (0x53, SignalingKind::AuthenticationResponse),
            (0x54, SignalingKind::AuthenticationReject),
            (0x5d, SignalingKind::SecurityModeCommand),
            (0x5e, SignalingKind::SecurityModeComplete),
        ];

        for (message_type, kind) in expected {
            let payload = plain(message_type);
            assert_eq!(
                SignalingKind::classify(&payload, 0),
                Some(kind),
                "octet {message_type:#04x}"
            );
            // And the code we report for the kind is the octet it came from.
            assert_eq!(kind.emm_code(), Some(message_type));
        }
    }

    #[test]
    fn identity_request_reads_the_three_bit_type_from_octet_2() {
        let cases = [
            (1u8, IdentityType::Imsi),
            (2, IdentityType::Imei),
            (3, IdentityType::Imeisv),
            (4, IdentityType::Tmsi),
            // Corroborated as unknown by the dissector, including code 5 which
            // TS 24.301 calls GUTI: we report the raw bits instead.
            (0, IdentityType::Unknown(0)),
            (5, IdentityType::Unknown(5)),
            (6, IdentityType::Unknown(6)),
            (7, IdentityType::Unknown(7)),
        ];

        for (code, id_type) in cases {
            let payload = vec![PLAIN_EMM, 0x55, code];
            assert_eq!(
                SignalingKind::classify(&payload, 0),
                Some(SignalingKind::IdentityRequest { id_type }),
                "request code {code}"
            );
        }

        // Only the low 3 bits are the type; the rest of the octet is spare.
        let payload = vec![PLAIN_EMM, 0x55, 0xf1];
        assert_eq!(
            SignalingKind::classify(&payload, 0),
            Some(SignalingKind::IdentityRequest {
                id_type: IdentityType::Imsi,
            })
        );
    }

    #[test]
    fn identity_response_reads_the_type_past_the_length_octet() {
        // [PD+0][0x56][IE length = 8][0x19: type 1 = IMSI in low 3 bits][digits]
        // A parser that used the request's rule would report Unknown(0) here,
        // because the length 8 masks to 0 — the trap this test exists for.
        let response = vec![
            PLAIN_EMM, 0x56, 0x08, 0x19, 0x21, 0x43, 0x65, 0x87, 0x09, 0x21,
        ];
        assert_eq!(
            SignalingKind::classify(&response, 0),
            Some(SignalingKind::IdentityResponse {
                id_type: IdentityType::Imsi,
            })
        );

        // The code space matches the request's, with code 4 standing for the
        // whole TMSI/P-TMSI/GUTI family.
        for (type_octet, id_type) in [
            (0x01u8, IdentityType::Imsi),
            (0x02, IdentityType::Imei),
            (0x03, IdentityType::Imeisv),
            (0x04, IdentityType::Tmsi),
            (0x05, IdentityType::Unknown(5)),
        ] {
            let response = vec![PLAIN_EMM, 0x56, 0x08, type_octet, 0x21];
            assert_eq!(
                SignalingKind::classify(&response, 0),
                Some(SignalingKind::IdentityResponse { id_type }),
                "response type octet {type_octet:#04x}"
            );
        }

        // Truncated before the type octet: no identity to report, but the
        // message itself is still an Identity Response.
        let full = [PLAIN_EMM, 0x56, 0x08, 0x19, 0x21];
        for len in 2..4 {
            let response = full[..len].to_vec();
            assert_eq!(
                SignalingKind::classify(&response, 0),
                Some(SignalingKind::IdentityResponse {
                    id_type: IdentityType::Unknown(0),
                }),
                "truncated response of {len} octets"
            );
        }
    }

    #[test]
    fn every_security_protected_message_stops_at_the_header() {
        // SHT is the *high* nibble, PD the low one: `0x17` is integrity
        // protected EMM, not "PD 1".
        for sht in 1..=3u8 {
            let payload = vec![sht << 4 | PLAIN_EMM, 0x41, 0x00];
            let kind = SignalingKind::classify(&payload, 0).expect("classified");
            assert_eq!(
                kind,
                SignalingKind::ProtectedNas {
                    security_header_type: sht
                }
            );
            assert_eq!(kind.emm_code(), None, "protected NAS has no EMM type");
            assert_eq!(
                kind.to_string(),
                format!("Protected NAS (security header type {sht})")
            );
        }
    }

    #[test]
    fn a_secure_container_is_not_opened_even_when_the_body_looks_plain() {
        // The case GSMTAP actually produces: sub_type says protected, yet the
        // payload starts with a plain EMM header. Reading `0x41` out of it
        // would be guessing that a ciphered body happens to spell a header, so
        // the container's claim wins and no inner type is attempted. The type
        // reported is the one the container claimed, not the 0 that the
        // ciphertext's first nibble happens to spell: a label of "security
        // header type 0" here would read as plain where the frame is not.
        let payload = vec![PLAIN_EMM, 0x41, 0x00];
        let kind = SignalingKind::classify(&payload, 1).expect("classified");

        assert_eq!(
            kind,
            SignalingKind::ProtectedNas {
                security_header_type: 1,
            }
        );
        assert_eq!(kind.emm_code(), None);
        assert!(!matches!(
            kind,
            SignalingKind::AttachRequest | SignalingKind::OtherEmm { .. }
        ));
    }

    #[test]
    fn non_emm_protocol_discriminators_are_kept_unnamed() {
        // PD 0x2 is EPS Session Management: NAS, but not the layer we decode.
        for pd in [0x02u8, 0x00, 0x0a] {
            let payload = vec![pd, 0x41, 0x00];
            let kind = SignalingKind::classify(&payload, 0).expect("classified");
            assert_eq!(
                kind,
                SignalingKind::NonEmm {
                    protocol_discriminator: pd
                },
                "PD {pd:#04x}"
            );
            assert_eq!(kind.emm_code(), None);
        }

        // The security header type still wins over the discriminator: a
        // ciphered ESM frame is Protected, because its PD octet may be fake.
        assert_eq!(
            SignalingKind::classify(&[0x22, 0x01], 0),
            Some(SignalingKind::ProtectedNas {
                security_header_type: 2
            })
        );
    }

    #[test]
    fn unknown_emm_types_are_other_emm_not_errors() {
        for message_type in [0x40u8, 0x47, 0x57, 0x65, 0xc1] {
            let payload = plain(message_type);
            assert_eq!(
                SignalingKind::classify(&payload, 0),
                Some(SignalingKind::OtherEmm { message_type }),
                "octet {message_type:#04x}"
            );
        }

        // 0xc1 is not "0x41 with a transaction marker": EMM has no such
        // sub-field to mask, so it stays an unknown type rather than folding
        // into Attach Request.
        assert_ne!(
            SignalingKind::classify(&plain(0xc1), 0),
            Some(SignalingKind::AttachRequest)
        );
    }

    #[test]
    fn payloads_too_short_to_identify_are_not_classified() {
        assert_eq!(SignalingKind::classify(&[], 0), None);
        // One octet tells us PD and SHT, but nothing about the message: EMM
        // needs octet 1 to be identifiable at all.
        assert_eq!(SignalingKind::classify(&[PLAIN_EMM], 0), None);
        // A protected message is fully identified by its header octet.
        assert_eq!(
            SignalingKind::classify(&[0x27], 0),
            Some(SignalingKind::ProtectedNas {
                security_header_type: 2
            })
        );
        assert_eq!(
            SignalingKind::classify(&[0x02], 0),
            Some(SignalingKind::NonEmm {
                protocol_discriminator: 2
            })
        );
    }

    #[test]
    fn labels_are_human_readable_and_distinguish_raw_codes() {
        assert_eq!(SignalingKind::AttachRequest.to_string(), "Attach Request");
        assert_eq!(
            SignalingKind::IdentityRequest {
                id_type: IdentityType::Imsi
            }
            .to_string(),
            "Identity Request (IMSI)"
        );
        assert_eq!(
            SignalingKind::OtherEmm { message_type: 0x61 }.to_string(),
            "Other EMM (message type 0x61)"
        );
        assert_eq!(
            SignalingKind::NonEmm {
                protocol_discriminator: 0x02
            }
            .to_string(),
            "Non-EMM NAS (protocol discriminator 0x02)"
        );
        assert_eq!(IdentityType::Unknown(5).to_string(), "Unknown(5)");
    }

    #[test]
    fn events_round_trip_through_serde() {
        let event = SignalingEvent {
            timestamp: DateTime::from_timestamp(1_700_000_000, 0)
                .expect("valid epoch second")
                .into(),
            kind: SignalingKind::IdentityRequest {
                id_type: IdentityType::Imsi,
            },
            payload_len: 3,
        };

        let json = serde_json::to_string(&event).expect("event serialises");
        let parsed: SignalingEvent = serde_json::from_str(&json).expect("event deserialises");

        assert_eq!(parsed, event);
        assert!(json.contains("\"IdentityRequest\""));
        assert!(json.contains("\"Imsi\""));
    }
}
