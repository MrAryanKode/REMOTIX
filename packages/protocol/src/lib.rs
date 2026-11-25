use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_FIELD_LENGTH: usize = 16_384;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload", rename_all = "snake_case")]
pub enum SignalMessage {
    Register { role: DeviceRole, device_id: Uuid },
    CreateSession { session_id: Uuid },
    JoinSession { session_id: Uuid },
    Offer { session_id: Uuid, sdp: String },
    Answer { session_id: Uuid, sdp: String },
    IceCandidate { session_id: Uuid, candidate: String },
    EndSession { session_id: Uuid },
    Error { code: String, message: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    UnsupportedVersion(u16),
    EmptyField(&'static str),
    FieldTooLong(&'static str),
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
    fn serializes_and_deserializes_messages() {
        let original = SignalEnvelope::new(SignalMessage::JoinSession {
            session_id: Uuid::new_v4(),
        });

        let json = serde_json::to_string(&original).unwrap();
        let decoded: SignalEnvelope = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.version, original.version);
        assert_eq!(decoded.request_id, original.request_id);
        assert!(decoded.validate().is_ok());
    }
}
