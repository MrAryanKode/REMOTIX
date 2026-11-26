use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

const CHALLENGE_DOMAIN: &[u8] = b"REMOTIX_AUTH_V2";
const HOST_AUTH_DOMAIN: &[u8] = b"REMOTIX_HOST_AUTH_V1";
const SERVER_HOST_AUTH_DOMAIN: &[u8] = b"REMOTIX_SERVER_HOST_AUTH_V1";
const PROTOCOL_VERSION: u16 = 1;

pub const CHALLENGE_SIZE: usize = 32;
pub const SIGNATURE_SIZE: usize = 64;
pub const DEVICE_ID_SIZE: usize = 16;
pub const CHALLENGE_ID_SIZE: usize = 16;

#[derive(Debug, PartialEq, Eq)]
pub enum IdentityError {
    InvalidPublicKey,
    InvalidSignature,
    InvalidChallenge,
}

pub struct DeviceIdentity {
    signing_key: SigningKey,
}

impl DeviceIdentity {
    pub fn generate() -> Self {
        Self {
            signing_key: SigningKey::generate(&mut OsRng),
        }
    }

    pub fn from_secret_bytes(secret: [u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&secret),
        }
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Exports the secret key bytes for protected local persistence.
    ///
    /// Callers must protect the returned copy and clear it after use.
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    pub fn fingerprint(&self) -> String {
        let hash = Sha256::digest(self.public_key());

        hash.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// Signs a challenge bound to a device ID.
    ///
    /// Retained for existing authentication compatibility.
    pub fn sign_authentication(
        &self,
        device_id: &[u8; DEVICE_ID_SIZE],
        challenge_id: &[u8; CHALLENGE_ID_SIZE],
        nonce: &[u8],
    ) -> Result<[u8; SIGNATURE_SIZE], IdentityError> {
        let transcript = build_authentication_transcript(device_id, challenge_id, nonce)?;

        Ok(self.signing_key.sign(&transcript).to_bytes())
    }

    /// Signs a challenge bound to both the host and controller.
    ///
    /// This is the preferred API for REMOTIX trusted-device authentication.
    pub fn sign_host_authentication(
        &self,
        host_device_id: &[u8; DEVICE_ID_SIZE],
        controller_device_id: &[u8; DEVICE_ID_SIZE],
        challenge_id: &[u8; CHALLENGE_ID_SIZE],
        nonce: &[u8],
    ) -> Result<[u8; SIGNATURE_SIZE], IdentityError> {
        let transcript = build_host_authentication_transcript(
            host_device_id,
            controller_device_id,
            challenge_id,
            nonce,
        )?;

        Ok(self.signing_key.sign(&transcript).to_bytes())
    }

    /// Signs a server-issued challenge proving this host's identity.
    ///
    /// The signature is bound to the host ID, challenge ID, nonce,
    /// protocol version, and a dedicated domain separator.
    pub fn sign_server_host_challenge(
        &self,
        host_device_id: &[u8; DEVICE_ID_SIZE],
        challenge_id: &[u8; CHALLENGE_ID_SIZE],
        nonce: &[u8],
    ) -> Result<[u8; SIGNATURE_SIZE], IdentityError> {
        let transcript =
            build_server_host_authentication_transcript(host_device_id, challenge_id, nonce)?;

        Ok(self.signing_key.sign(&transcript).to_bytes())
    }

    // Retained for compatibility with the original identity API.
    pub fn sign_challenge(&self, challenge: &[u8]) -> Result<[u8; SIGNATURE_SIZE], IdentityError> {
        if challenge.len() != CHALLENGE_SIZE {
            return Err(IdentityError::InvalidChallenge);
        }

        let mut message = Vec::with_capacity(CHALLENGE_DOMAIN.len() + challenge.len());

        message.extend_from_slice(CHALLENGE_DOMAIN);
        message.extend_from_slice(challenge);

        Ok(self.signing_key.sign(&message).to_bytes())
    }
}

fn build_authentication_transcript(
    device_id: &[u8; DEVICE_ID_SIZE],
    challenge_id: &[u8; CHALLENGE_ID_SIZE],
    nonce: &[u8],
) -> Result<Vec<u8>, IdentityError> {
    if nonce.len() != CHALLENGE_SIZE {
        return Err(IdentityError::InvalidChallenge);
    }

    let mut transcript = Vec::with_capacity(
        CHALLENGE_DOMAIN.len() + 2 + DEVICE_ID_SIZE + CHALLENGE_ID_SIZE + CHALLENGE_SIZE,
    );

    transcript.extend_from_slice(CHALLENGE_DOMAIN);
    transcript.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    transcript.extend_from_slice(device_id);
    transcript.extend_from_slice(challenge_id);
    transcript.extend_from_slice(nonce);

    Ok(transcript)
}

fn build_host_authentication_transcript(
    host_device_id: &[u8; DEVICE_ID_SIZE],
    controller_device_id: &[u8; DEVICE_ID_SIZE],
    challenge_id: &[u8; CHALLENGE_ID_SIZE],
    nonce: &[u8],
) -> Result<Vec<u8>, IdentityError> {
    if nonce.len() != CHALLENGE_SIZE {
        return Err(IdentityError::InvalidChallenge);
    }

    let mut transcript = Vec::with_capacity(
        HOST_AUTH_DOMAIN.len() + 2 + DEVICE_ID_SIZE * 2 + CHALLENGE_ID_SIZE + CHALLENGE_SIZE,
    );

    transcript.extend_from_slice(HOST_AUTH_DOMAIN);
    transcript.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    transcript.extend_from_slice(host_device_id);
    transcript.extend_from_slice(controller_device_id);
    transcript.extend_from_slice(challenge_id);
    transcript.extend_from_slice(nonce);

    Ok(transcript)
}

fn build_server_host_authentication_transcript(
    host_device_id: &[u8; DEVICE_ID_SIZE],
    challenge_id: &[u8; CHALLENGE_ID_SIZE],
    nonce: &[u8],
) -> Result<Vec<u8>, IdentityError> {
    if nonce.len() != CHALLENGE_SIZE {
        return Err(IdentityError::InvalidChallenge);
    }

    let mut transcript = Vec::with_capacity(
        SERVER_HOST_AUTH_DOMAIN.len() + 2 + DEVICE_ID_SIZE + CHALLENGE_ID_SIZE + CHALLENGE_SIZE,
    );

    transcript.extend_from_slice(SERVER_HOST_AUTH_DOMAIN);
    transcript.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    transcript.extend_from_slice(host_device_id);
    transcript.extend_from_slice(challenge_id);
    transcript.extend_from_slice(nonce);

    Ok(transcript)
}

/// Verifies a host's proof of possession of its enrolled private key.
pub fn verify_server_host_challenge(
    public_key: &[u8; 32],
    host_device_id: &[u8; DEVICE_ID_SIZE],
    challenge_id: &[u8; CHALLENGE_ID_SIZE],
    nonce: &[u8],
    signature: &[u8; SIGNATURE_SIZE],
) -> Result<(), IdentityError> {
    let transcript =
        build_server_host_authentication_transcript(host_device_id, challenge_id, nonce)?;

    let verifying_key =
        VerifyingKey::from_bytes(public_key).map_err(|_| IdentityError::InvalidPublicKey)?;

    let signature = Signature::from_bytes(signature);

    verifying_key
        .verify_strict(&transcript, &signature)
        .map_err(|_| IdentityError::InvalidSignature)
}

pub fn verify_authentication(
    public_key: &[u8; 32],
    device_id: &[u8; DEVICE_ID_SIZE],
    challenge_id: &[u8; CHALLENGE_ID_SIZE],
    nonce: &[u8],
    signature: &[u8; SIGNATURE_SIZE],
) -> Result<(), IdentityError> {
    let transcript = build_authentication_transcript(device_id, challenge_id, nonce)?;

    let verifying_key =
        VerifyingKey::from_bytes(public_key).map_err(|_| IdentityError::InvalidPublicKey)?;

    let signature = Signature::from_bytes(signature);

    verifying_key
        .verify_strict(&transcript, &signature)
        .map_err(|_| IdentityError::InvalidSignature)
}

/// Verifies authentication bound to a specific host and controller.
pub fn verify_host_authentication(
    public_key: &[u8; 32],
    host_device_id: &[u8; DEVICE_ID_SIZE],
    controller_device_id: &[u8; DEVICE_ID_SIZE],
    challenge_id: &[u8; CHALLENGE_ID_SIZE],
    nonce: &[u8],
    signature: &[u8; SIGNATURE_SIZE],
) -> Result<(), IdentityError> {
    let transcript = build_host_authentication_transcript(
        host_device_id,
        controller_device_id,
        challenge_id,
        nonce,
    )?;

    let verifying_key =
        VerifyingKey::from_bytes(public_key).map_err(|_| IdentityError::InvalidPublicKey)?;

    let signature = Signature::from_bytes(signature);

    verifying_key
        .verify_strict(&transcript, &signature)
        .map_err(|_| IdentityError::InvalidSignature)
}

pub fn verify_challenge(
    public_key: &[u8; 32],
    challenge: &[u8],
    signature: &[u8; SIGNATURE_SIZE],
) -> Result<(), IdentityError> {
    if challenge.len() != CHALLENGE_SIZE {
        return Err(IdentityError::InvalidChallenge);
    }

    let verifying_key =
        VerifyingKey::from_bytes(public_key).map_err(|_| IdentityError::InvalidPublicKey)?;

    let mut message = Vec::with_capacity(CHALLENGE_DOMAIN.len() + challenge.len());

    message.extend_from_slice(CHALLENGE_DOMAIN);
    message.extend_from_slice(challenge);

    let signature = Signature::from_bytes(signature);

    verifying_key
        .verify_strict(&message, &signature)
        .map_err(|_| IdentityError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_unique_device_identities() {
        let first = DeviceIdentity::generate();
        let second = DeviceIdentity::generate();

        assert_ne!(first.public_key(), second.public_key());
        assert_ne!(first.fingerprint(), second.fingerprint());
    }

    #[test]
    fn fingerprint_is_stable() {
        let identity = DeviceIdentity::generate();

        assert_eq!(identity.fingerprint().len(), 64);
        assert_eq!(identity.fingerprint(), identity.fingerprint());
    }

    #[test]
    fn verifies_valid_challenge_signature() {
        let identity = DeviceIdentity::generate();
        let challenge = [7u8; CHALLENGE_SIZE];

        let signature = identity.sign_challenge(&challenge).unwrap();

        assert!(verify_challenge(&identity.public_key(), &challenge, &signature).is_ok());
    }

    #[test]
    fn rejects_modified_challenge() {
        let identity = DeviceIdentity::generate();

        let signature = identity.sign_challenge(&[1u8; CHALLENGE_SIZE]).unwrap();

        assert_eq!(
            verify_challenge(&identity.public_key(), &[2u8; CHALLENGE_SIZE], &signature,),
            Err(IdentityError::InvalidSignature)
        );
    }

    #[test]
    fn rejects_signature_from_another_device() {
        let first = DeviceIdentity::generate();
        let second = DeviceIdentity::generate();

        let challenge = [9u8; CHALLENGE_SIZE];
        let signature = first.sign_challenge(&challenge).unwrap();

        assert_eq!(
            verify_challenge(&second.public_key(), &challenge, &signature,),
            Err(IdentityError::InvalidSignature)
        );
    }

    #[test]
    fn rejects_wrong_challenge_length() {
        let identity = DeviceIdentity::generate();

        assert_eq!(
            identity.sign_challenge(b"short"),
            Err(IdentityError::InvalidChallenge)
        );
    }

    #[test]
    fn rejects_wrong_length_during_verification() {
        let identity = DeviceIdentity::generate();
        let signature = [0u8; SIGNATURE_SIZE];

        assert_eq!(
            verify_challenge(&identity.public_key(), b"short", &signature,),
            Err(IdentityError::InvalidChallenge)
        );
    }

    #[test]
    fn restores_identity_from_secret_bytes() {
        let original = DeviceIdentity::generate();
        let secret = original.signing_key.to_bytes();

        let restored = DeviceIdentity::from_secret_bytes(secret);

        assert_eq!(original.public_key(), restored.public_key());
        assert_eq!(original.fingerprint(), restored.fingerprint());
    }

    #[test]
    fn verifies_context_bound_authentication() {
        let identity = DeviceIdentity::generate();

        let device_id = [1u8; DEVICE_ID_SIZE];
        let challenge_id = [2u8; CHALLENGE_ID_SIZE];
        let nonce = [3u8; CHALLENGE_SIZE];

        let signature = identity
            .sign_authentication(&device_id, &challenge_id, &nonce)
            .unwrap();

        assert!(
            verify_authentication(
                &identity.public_key(),
                &device_id,
                &challenge_id,
                &nonce,
                &signature,
            )
            .is_ok()
        );
    }

    #[test]
    fn rejects_authentication_for_another_device() {
        let identity = DeviceIdentity::generate();

        let device_id = [1u8; DEVICE_ID_SIZE];
        let challenge_id = [2u8; CHALLENGE_ID_SIZE];
        let nonce = [3u8; CHALLENGE_SIZE];

        let signature = identity
            .sign_authentication(&device_id, &challenge_id, &nonce)
            .unwrap();

        assert_eq!(
            verify_authentication(
                &identity.public_key(),
                &[9u8; DEVICE_ID_SIZE],
                &challenge_id,
                &nonce,
                &signature,
            ),
            Err(IdentityError::InvalidSignature)
        );
    }

    #[test]
    fn rejects_replayed_authentication_challenge_id() {
        let identity = DeviceIdentity::generate();

        let device_id = [1u8; DEVICE_ID_SIZE];
        let challenge_id = [2u8; CHALLENGE_ID_SIZE];
        let nonce = [3u8; CHALLENGE_SIZE];

        let signature = identity
            .sign_authentication(&device_id, &challenge_id, &nonce)
            .unwrap();

        assert_eq!(
            verify_authentication(
                &identity.public_key(),
                &device_id,
                &[8u8; CHALLENGE_ID_SIZE],
                &nonce,
                &signature,
            ),
            Err(IdentityError::InvalidSignature)
        );
    }

    #[test]
    fn rejects_modified_authentication_nonce() {
        let identity = DeviceIdentity::generate();

        let device_id = [1u8; DEVICE_ID_SIZE];
        let challenge_id = [2u8; CHALLENGE_ID_SIZE];
        let nonce = [3u8; CHALLENGE_SIZE];

        let signature = identity
            .sign_authentication(&device_id, &challenge_id, &nonce)
            .unwrap();

        assert_eq!(
            verify_authentication(
                &identity.public_key(),
                &device_id,
                &challenge_id,
                &[4u8; CHALLENGE_SIZE],
                &signature,
            ),
            Err(IdentityError::InvalidSignature)
        );
    }

    #[test]
    fn rejects_invalid_authentication_nonce_length() {
        let identity = DeviceIdentity::generate();

        assert_eq!(
            identity.sign_authentication(
                &[1u8; DEVICE_ID_SIZE],
                &[2u8; CHALLENGE_ID_SIZE],
                b"short",
            ),
            Err(IdentityError::InvalidChallenge)
        );
    }

    #[test]
    fn verifies_host_bound_authentication() {
        let identity = DeviceIdentity::generate();

        let host_id = [1u8; DEVICE_ID_SIZE];
        let controller_id = [2u8; DEVICE_ID_SIZE];
        let challenge_id = [3u8; CHALLENGE_ID_SIZE];
        let nonce = [4u8; CHALLENGE_SIZE];

        let signature = identity
            .sign_host_authentication(&host_id, &controller_id, &challenge_id, &nonce)
            .unwrap();

        assert!(
            verify_host_authentication(
                &identity.public_key(),
                &host_id,
                &controller_id,
                &challenge_id,
                &nonce,
                &signature,
            )
            .is_ok()
        );
    }

    #[test]
    fn rejects_host_bound_authentication_for_another_host() {
        let identity = DeviceIdentity::generate();

        let host_id = [1u8; DEVICE_ID_SIZE];
        let controller_id = [2u8; DEVICE_ID_SIZE];
        let challenge_id = [3u8; CHALLENGE_ID_SIZE];
        let nonce = [4u8; CHALLENGE_SIZE];

        let signature = identity
            .sign_host_authentication(&host_id, &controller_id, &challenge_id, &nonce)
            .unwrap();

        assert_eq!(
            verify_host_authentication(
                &identity.public_key(),
                &[9u8; DEVICE_ID_SIZE],
                &controller_id,
                &challenge_id,
                &nonce,
                &signature,
            ),
            Err(IdentityError::InvalidSignature)
        );
    }

    #[test]
    fn rejects_host_bound_authentication_for_another_controller() {
        let identity = DeviceIdentity::generate();

        let host_id = [1u8; DEVICE_ID_SIZE];
        let controller_id = [2u8; DEVICE_ID_SIZE];
        let challenge_id = [3u8; CHALLENGE_ID_SIZE];
        let nonce = [4u8; CHALLENGE_SIZE];

        let signature = identity
            .sign_host_authentication(&host_id, &controller_id, &challenge_id, &nonce)
            .unwrap();

        assert_eq!(
            verify_host_authentication(
                &identity.public_key(),
                &host_id,
                &[9u8; DEVICE_ID_SIZE],
                &challenge_id,
                &nonce,
                &signature,
            ),
            Err(IdentityError::InvalidSignature)
        );
    }

    #[test]
    fn rejects_host_bound_authentication_with_modified_nonce() {
        let identity = DeviceIdentity::generate();

        let host_id = [1u8; DEVICE_ID_SIZE];
        let controller_id = [2u8; DEVICE_ID_SIZE];
        let challenge_id = [3u8; CHALLENGE_ID_SIZE];
        let nonce = [4u8; CHALLENGE_SIZE];

        let signature = identity
            .sign_host_authentication(&host_id, &controller_id, &challenge_id, &nonce)
            .unwrap();

        assert_eq!(
            verify_host_authentication(
                &identity.public_key(),
                &host_id,
                &controller_id,
                &challenge_id,
                &[8u8; CHALLENGE_SIZE],
                &signature,
            ),
            Err(IdentityError::InvalidSignature)
        );
    }

    #[test]
    fn rejects_invalid_host_bound_nonce_length() {
        let identity = DeviceIdentity::generate();

        assert_eq!(
            identity.sign_host_authentication(
                &[1u8; DEVICE_ID_SIZE],
                &[2u8; DEVICE_ID_SIZE],
                &[3u8; CHALLENGE_ID_SIZE],
                b"short",
            ),
            Err(IdentityError::InvalidChallenge)
        );
    }
}

#[cfg(test)]
mod server_host_auth_tests {
    use super::*;

    #[test]
    fn verifies_valid_server_host_challenge() {
        let identity = DeviceIdentity::generate();
        let host_id = [1u8; DEVICE_ID_SIZE];
        let challenge_id = [2u8; CHALLENGE_ID_SIZE];
        let nonce = [3u8; CHALLENGE_SIZE];

        let signature = identity
            .sign_server_host_challenge(&host_id, &challenge_id, &nonce)
            .unwrap();

        assert!(
            verify_server_host_challenge(
                &identity.public_key(),
                &host_id,
                &challenge_id,
                &nonce,
                &signature,
            )
            .is_ok()
        );
    }

    #[test]
    fn rejects_wrong_host_id() {
        let identity = DeviceIdentity::generate();
        let host_id = [1u8; DEVICE_ID_SIZE];
        let challenge_id = [2u8; CHALLENGE_ID_SIZE];
        let nonce = [3u8; CHALLENGE_SIZE];

        let signature = identity
            .sign_server_host_challenge(&host_id, &challenge_id, &nonce)
            .unwrap();

        assert_eq!(
            verify_server_host_challenge(
                &identity.public_key(),
                &[9u8; DEVICE_ID_SIZE],
                &challenge_id,
                &nonce,
                &signature,
            ),
            Err(IdentityError::InvalidSignature),
        );
    }

    #[test]
    fn rejects_wrong_challenge_id() {
        let identity = DeviceIdentity::generate();
        let host_id = [1u8; DEVICE_ID_SIZE];
        let challenge_id = [2u8; CHALLENGE_ID_SIZE];
        let nonce = [3u8; CHALLENGE_SIZE];

        let signature = identity
            .sign_server_host_challenge(&host_id, &challenge_id, &nonce)
            .unwrap();

        assert_eq!(
            verify_server_host_challenge(
                &identity.public_key(),
                &host_id,
                &[8u8; CHALLENGE_ID_SIZE],
                &nonce,
                &signature,
            ),
            Err(IdentityError::InvalidSignature),
        );
    }

    #[test]
    fn rejects_modified_nonce() {
        let identity = DeviceIdentity::generate();
        let host_id = [1u8; DEVICE_ID_SIZE];
        let challenge_id = [2u8; CHALLENGE_ID_SIZE];
        let nonce = [3u8; CHALLENGE_SIZE];

        let signature = identity
            .sign_server_host_challenge(&host_id, &challenge_id, &nonce)
            .unwrap();

        assert_eq!(
            verify_server_host_challenge(
                &identity.public_key(),
                &host_id,
                &challenge_id,
                &[4u8; CHALLENGE_SIZE],
                &signature,
            ),
            Err(IdentityError::InvalidSignature),
        );
    }

    #[test]
    fn rejects_another_identity_key() {
        let identity = DeviceIdentity::generate();
        let other_identity = DeviceIdentity::generate();
        let host_id = [1u8; DEVICE_ID_SIZE];
        let challenge_id = [2u8; CHALLENGE_ID_SIZE];
        let nonce = [3u8; CHALLENGE_SIZE];

        let signature = identity
            .sign_server_host_challenge(&host_id, &challenge_id, &nonce)
            .unwrap();

        assert_eq!(
            verify_server_host_challenge(
                &other_identity.public_key(),
                &host_id,
                &challenge_id,
                &nonce,
                &signature,
            ),
            Err(IdentityError::InvalidSignature),
        );
    }

    #[test]
    fn rejects_invalid_nonce_length() {
        let identity = DeviceIdentity::generate();

        assert_eq!(
            identity.sign_server_host_challenge(
                &[1u8; DEVICE_ID_SIZE],
                &[2u8; CHALLENGE_ID_SIZE],
                &[3u8; 12],
            ),
            Err(IdentityError::InvalidChallenge),
        );
    }
}
