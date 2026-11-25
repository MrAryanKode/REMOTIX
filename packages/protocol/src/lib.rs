use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const PROTOCOL_VERSION: u16 = 3;
pub const MAX_FIELD_LENGTH: usize = 16_384;
pub const CHALLENGE_SIZE: usize = 32;
pub const SIGNATURE_SIZE: usize = 64;
pub const PUBLIC_KEY_SIZE: usize = 32;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignalEnvelope {
    pub version: u16,
    pub request_id: Uuid,
    pub message: SignalMessage,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeviceRole {
    Host,
    Controller,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PairingStatus {
    Pending,
    Approved,
    Rejected,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload", rename_all = "snake_case")]
pub enum SignalMessage {
    // Development registration.
    Register {
        role: DeviceRole,
        device_id: Uuid,
    },

    // Remote desktop session signalling.
    CreateSession {
        session_id: Uuid,
    },
    JoinSession {
        session_id: Uuid,
    },
    Offer {
        session_id: Uuid,
        sdp: String,
    },
    Answer {
        session_id: Uuid,
        sdp: String,
    },
    IceCandidate {
        session_id: Uuid,
        candidate: String,
    },
    EndSession {
        session_id: Uuid,
    },

    // Host pairing.
    CreatePairing {
        host_device_id: Uuid,
    },
    PairingCreated {
        pairing_id: Uuid,
        pairing_code: String,
        expires_at_unix: u64,
    },

    // Controller requests pairing.
    RequestPairing {
        pairing_id: Uuid,
        pairing_code: String,
        controller_device_id: Uuid,
        controller_public_key: [u8; PUBLIC_KEY_SIZE],
    },

    // Server challenges the controller.
    PairingChallenge {
        pairing_id: Uuid,
        challenge_id: Uuid,
        nonce: [u8; CHALLENGE_SIZE],
        expires_at_unix: u64,
    },

    // Controller proves ownership of its private key.
    ProvePairing {
        pairing_id: Uuid,
        controller_device_id: Uuid,
        challenge_id: Uuid,
        signature: Vec<u8>,
    },

    // Server notifies the host after proof verification.
    PairingRequested {
        pairing_id: Uuid,
        controller_device_id: Uuid,
        controller_public_key: [u8; PUBLIC_KEY_SIZE],
    },

    // Host makes the final decision.
    ApprovePairing {
        pairing_id: Uuid,
        controller_device_id: Uuid,
    },
    RejectPairing {
        pairing_id: Uuid,
        controller_device_id: Uuid,
    },
    PairingResult {
        pairing_id: Uuid,
        status: PairingStatus,
    },

    // Host-bound reconnection authentication.
    BeginAuthentication {
        host_device_id: Uuid,
        controller_device_id: Uuid,
    },

    // Server sends a challenge bound to both devices.
    AuthenticationChallenge {
        host_device_id: Uuid,
        controller_device_id: Uuid,
        challenge_id: Uuid,
        nonce: [u8; CHALLENGE_SIZE],
        expires_at_unix: u64,
    },

    // Controller signs the host-bound challenge.
    Authenticate {
        host_device_id: Uuid,
        controller_device_id: Uuid,
        challenge_id: Uuid,
        signature: Vec<u8>,
    },

    // Server confirms successful authentication.
    Authenticated {
        host_device_id: Uuid,
        controller_device_id: Uuid,
        role: DeviceRole,
    },

    // Server errors.
    Error {
        code: String,
        message: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    UnsupportedVersion(u16),
    EmptyField(&'static str),
    FieldTooLong(&'static str),
    InvalidLength(&'static str),
}

impl SignalEnvelope {
    pub fn new(message: SignalMessage) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            request_id: Uuid::new_v4(),
            message,
        }
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.version != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(self.version));
        }

        let check = |value: &str, field: &'static str| {
            if value.is_empty() {
                return Err(ProtocolError::EmptyField(field));
            }

            if value.len() > MAX_FIELD_LENGTH {
                return Err(ProtocolError::FieldTooLong(field));
            }

            Ok(())
        };

        match &self.message {
            SignalMessage::Offer { sdp, .. } | SignalMessage::Answer { sdp, .. } => {
                check(sdp, "sdp")
            }

            SignalMessage::IceCandidate { candidate, .. } => check(candidate, "candidate"),

            SignalMessage::PairingCreated { pairing_code, .. }
            | SignalMessage::RequestPairing { pairing_code, .. } => {
                check(pairing_code, "pairing_code")
            }

            SignalMessage::ProvePairing { signature, .. }
            | SignalMessage::Authenticate { signature, .. } => {
                if signature.len() != SIGNATURE_SIZE {
                    return Err(ProtocolError::InvalidLength("signature"));
                }

                Ok(())
            }

            SignalMessage::Error { code, message } => {
                check(code, "code")?;
                check(message, "message")
            }

            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_valid_envelope() {
        let envelope = SignalEnvelope::new(SignalMessage::CreateSession {
            session_id: Uuid::new_v4(),
        });

        assert_eq!(envelope.version, PROTOCOL_VERSION);
        assert!(envelope.validate().is_ok());
    }

    #[test]
    fn uses_protocol_version_three() {
        assert_eq!(PROTOCOL_VERSION, 3);
    }

    #[test]
    fn rejects_unsupported_protocol_version() {
        let mut envelope = SignalEnvelope::new(SignalMessage::EndSession {
            session_id: Uuid::new_v4(),
        });

        envelope.version = 99;

        assert_eq!(
            envelope.validate(),
            Err(ProtocolError::UnsupportedVersion(99))
        );
    }

    #[test]
    fn rejects_empty_sdp() {
        let envelope = SignalEnvelope::new(SignalMessage::Offer {
            session_id: Uuid::new_v4(),
            sdp: String::new(),
        });

        assert_eq!(envelope.validate(), Err(ProtocolError::EmptyField("sdp")));
    }

    #[test]
    fn serializes_and_deserializes_session_messages() {
        let original = SignalEnvelope::new(SignalMessage::JoinSession {
            session_id: Uuid::new_v4(),
        });

        let json = serde_json::to_string(&original).unwrap();
        let decoded: SignalEnvelope = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.version, original.version);
        assert_eq!(decoded.request_id, original.request_id);
        assert!(decoded.validate().is_ok());
    }

    #[test]
    fn serializes_pairing_creation() {
        let original = SignalEnvelope::new(SignalMessage::CreatePairing {
            host_device_id: Uuid::new_v4(),
        });

        let json = serde_json::to_string(&original).unwrap();
        let decoded: SignalEnvelope = serde_json::from_str(&json).unwrap();

        assert!(matches!(
            decoded.message,
            SignalMessage::CreatePairing { .. }
        ));
    }

    #[test]
    fn serializes_pairing_challenge() {
        let original = SignalEnvelope::new(SignalMessage::PairingChallenge {
            pairing_id: Uuid::new_v4(),
            challenge_id: Uuid::new_v4(),
            nonce: [9u8; CHALLENGE_SIZE],
            expires_at_unix: 1_800_000_000,
        });

        let json = serde_json::to_string(&original).unwrap();
        let decoded: SignalEnvelope = serde_json::from_str(&json).unwrap();

        assert!(matches!(
            decoded.message,
            SignalMessage::PairingChallenge {
                nonce,
                ..
            } if nonce == [9u8; CHALLENGE_SIZE]
        ));
    }

    #[test]
    fn rejects_empty_pairing_code() {
        let envelope = SignalEnvelope::new(SignalMessage::RequestPairing {
            pairing_id: Uuid::new_v4(),
            pairing_code: String::new(),
            controller_device_id: Uuid::new_v4(),
            controller_public_key: [1u8; PUBLIC_KEY_SIZE],
        });

        assert_eq!(
            envelope.validate(),
            Err(ProtocolError::EmptyField("pairing_code"))
        );
    }

    #[test]
    fn accepts_exactly_64_byte_authentication_signature() {
        let envelope = SignalEnvelope::new(SignalMessage::Authenticate {
            host_device_id: Uuid::new_v4(),
            controller_device_id: Uuid::new_v4(),
            challenge_id: Uuid::new_v4(),
            signature: vec![1u8; SIGNATURE_SIZE],
        });

        assert!(envelope.validate().is_ok());
    }

    #[test]
    fn rejects_short_authentication_signature() {
        let envelope = SignalEnvelope::new(SignalMessage::Authenticate {
            host_device_id: Uuid::new_v4(),
            controller_device_id: Uuid::new_v4(),
            challenge_id: Uuid::new_v4(),
            signature: vec![1u8; 10],
        });

        assert_eq!(
            envelope.validate(),
            Err(ProtocolError::InvalidLength("signature"))
        );
    }

    #[test]
    fn rejects_invalid_pairing_proof_signature_length() {
        let envelope = SignalEnvelope::new(SignalMessage::ProvePairing {
            pairing_id: Uuid::new_v4(),
            controller_device_id: Uuid::new_v4(),
            challenge_id: Uuid::new_v4(),
            signature: vec![1u8; 10],
        });

        assert_eq!(
            envelope.validate(),
            Err(ProtocolError::InvalidLength("signature"))
        );
    }

    #[test]
    fn rejects_unknown_json_fields() {
        let json = format!(
            r#"{{"version":{},"request_id":"{}","unexpected":true,"message":{{"type":"end_session","payload":{{"session_id":"{}"}}}}}}"#,
            PROTOCOL_VERSION,
            Uuid::new_v4(),
            Uuid::new_v4(),
        );

        assert!(serde_json::from_str::<SignalEnvelope>(&json).is_err());
    }

    #[test]
    fn serializes_host_bound_authentication_request() {
        let host_id = Uuid::new_v4();
        let controller_id = Uuid::new_v4();

        let original = SignalEnvelope::new(SignalMessage::BeginAuthentication {
            host_device_id: host_id,
            controller_device_id: controller_id,
        });

        let json = serde_json::to_string(&original).unwrap();
        let decoded: SignalEnvelope = serde_json::from_str(&json).unwrap();

        assert!(matches!(
            decoded.message,
            SignalMessage::BeginAuthentication {
                host_device_id,
                controller_device_id,
            } if host_device_id == host_id
                && controller_device_id == controller_id
        ));
    }

    #[test]
    fn serializes_host_bound_authentication_challenge() {
        let host_id = Uuid::new_v4();
        let controller_id = Uuid::new_v4();

        let original = SignalEnvelope::new(SignalMessage::AuthenticationChallenge {
            host_device_id: host_id,
            controller_device_id: controller_id,
            challenge_id: Uuid::new_v4(),
            nonce: [7u8; CHALLENGE_SIZE],
            expires_at_unix: 1_800_000_000,
        });

        let json = serde_json::to_string(&original).unwrap();
        let decoded: SignalEnvelope = serde_json::from_str(&json).unwrap();

        assert!(matches!(
            decoded.message,
            SignalMessage::AuthenticationChallenge {
                host_device_id,
                controller_device_id,
                nonce,
                ..
            } if host_device_id == host_id
                && controller_device_id == controller_id
                && nonce == [7u8; CHALLENGE_SIZE]
        ));
    }

    #[test]
    fn rejects_unknown_json_fields_in_envelope() {
        let json = format!(
            r#"{{"version":{},"request_id":"{}","unexpected":true,"message":{{"type":"end_session","payload":{{"session_id":"{}"}}}}}}"#,
            PROTOCOL_VERSION,
            Uuid::new_v4(),
            Uuid::new_v4(),
        );

        assert!(serde_json::from_str::<SignalEnvelope>(&json).is_err());
    }
}
