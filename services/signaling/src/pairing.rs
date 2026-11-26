use rand::{RngCore, rngs::OsRng};
use remotix_device_identity::{
    CHALLENGE_ID_SIZE, CHALLENGE_SIZE, DEVICE_ID_SIZE, SIGNATURE_SIZE, verify_authentication,
    verify_host_authentication,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use uuid::Uuid;

const PAIRING_TTL_SECONDS: u64 = 300;
const CHALLENGE_TTL_SECONDS: u64 = 60;
const MAX_PENDING_PAIRINGS: usize = 100;
const MAX_FAILED_PROOFS: u8 = 3;
const MAX_FAILED_AUTHENTICATIONS: u8 = 3;

#[derive(Debug, Clone)]
pub struct PairingCreated {
    pub pairing_id: Uuid,
    pub pairing_code: String,
    pub expires_at_unix: u64,
}

#[derive(Debug, Clone)]
pub struct PairingChallenge {
    pub pairing_id: Uuid,
    pub challenge_id: Uuid,
    pub nonce: Vec<u8>,
    pub expires_at_unix: u64,
}

#[derive(Debug, Clone)]
pub struct AuthenticationChallenge {
    pub host_device_id: Uuid,
    pub controller_device_id: Uuid,
    pub challenge_id: Uuid,
    pub nonce: Vec<u8>,
    pub expires_at_unix: u64,
}

#[derive(Debug, Clone)]
pub struct PairingRequest {
    pub pairing_id: Uuid,
    pub host_connection_id: Uuid,
    pub host_device_id: Uuid,
    pub controller_connection_id: Uuid,
    pub controller_device_id: Uuid,
    pub controller_public_key: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct TrustedDevice {
    pub device_id: Uuid,
    pub public_key: Vec<u8>,
    pub approved_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairingError {
    CapacityReached,
    PairingNotFound,
    InvalidCode,
    InvalidPublicKey,
    InvalidProof,
    Expired,
    AlreadyRequested,
    RequestNotFound,
    UnauthorizedHost,
    UnauthorizedController,
    TooManyFailedAttempts,
    AuthenticationNotFound,
    AuthenticationAlreadyPending,
}

#[derive(Debug, Clone)]
struct PendingChallenge {
    challenge_id: Uuid,
    nonce: [u8; CHALLENGE_SIZE],
    expires_at_unix: u64,
    controller_connection_id: Uuid,
    controller_device_id: Uuid,
    controller_public_key: [u8; 32],
}

#[derive(Debug, Clone)]
struct PendingAuthentication {
    host_device_id: Uuid,
    controller_device_id: Uuid,
    controller_connection_id: Uuid,
    challenge_id: Uuid,
    nonce: [u8; CHALLENGE_SIZE],
    expires_at_unix: u64,
}

#[derive(Debug, Clone)]
struct PendingPairing {
    host_connection_id: Uuid,
    host_device_id: Uuid,
    code_hash: [u8; 32],
    expires_at_unix: u64,
    challenge: Option<PendingChallenge>,
    request: Option<PairingRequest>,
    failed_proofs: u8,
}

#[derive(Debug, Clone)]
struct TrustedRecord {
    host_device_id: Uuid,
    trusted_device: TrustedDevice,
}

/// In-memory pairing and authentication state.
///
/// Pairings, authentication challenges, and trusted-device records are
/// lost when the server restarts. Persistent storage is a future stage.
#[derive(Debug, Default)]
pub struct PairingManager {
    pending: HashMap<Uuid, PendingPairing>,
    trusted: HashMap<(Uuid, Uuid), TrustedRecord>,
    pending_authentication: HashMap<Uuid, PendingAuthentication>,
    failed_authentications: HashMap<Uuid, u8>,
}

impl PairingManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn create_pairing(
        &mut self,
        host_connection_id: Uuid,
        host_device_id: Uuid,
        now_unix: u64,
    ) -> Result<PairingCreated, PairingError> {
        self.remove_expired(now_unix);

        if self.pending.len() >= MAX_PENDING_PAIRINGS {
            return Err(PairingError::CapacityReached);
        }

        let pairing_id = Uuid::new_v4();
        let mut random_code = [0u8; 32];
        OsRng.fill_bytes(&mut random_code);

        let pairing_code = encode_hex(&random_code);
        let code_hash = hash_code(&pairing_code);
        let expires_at_unix = now_unix.saturating_add(PAIRING_TTL_SECONDS);

        self.pending.insert(
            pairing_id,
            PendingPairing {
                host_connection_id,
                host_device_id,
                code_hash,
                expires_at_unix,
                challenge: None,
                request: None,
                failed_proofs: 0,
            },
        );

        Ok(PairingCreated {
            pairing_id,
            pairing_code,
            expires_at_unix,
        })
    }

    pub fn begin_pairing_request(
        &mut self,
        pairing_id: Uuid,
        pairing_code: &str,
        controller_connection_id: Uuid,
        controller_device_id: Uuid,
        controller_public_key: &[u8],
        now_unix: u64,
    ) -> Result<PairingChallenge, PairingError> {
        self.remove_expired(now_unix);

        if controller_public_key.len() != 32 {
            return Err(PairingError::InvalidPublicKey);
        }

        let pairing = self
            .pending
            .get_mut(&pairing_id)
            .ok_or(PairingError::PairingNotFound)?;

        if now_unix >= pairing.expires_at_unix {
            return Err(PairingError::Expired);
        }

        if pairing.request.is_some() || pairing.challenge.is_some() {
            return Err(PairingError::AlreadyRequested);
        }

        let supplied_hash = hash_code(pairing_code);

        if !constant_time_equal(&pairing.code_hash, &supplied_hash) {
            return Err(PairingError::InvalidCode);
        }

        let public_key: [u8; 32] = controller_public_key
            .try_into()
            .map_err(|_| PairingError::InvalidPublicKey)?;

        let mut nonce = [0u8; CHALLENGE_SIZE];
        OsRng.fill_bytes(&mut nonce);

        let challenge_id = Uuid::new_v4();
        let expires_at_unix = now_unix.saturating_add(CHALLENGE_TTL_SECONDS);

        pairing.challenge = Some(PendingChallenge {
            challenge_id,
            nonce,
            expires_at_unix,
            controller_connection_id,
            controller_device_id,
            controller_public_key: public_key,
        });

        Ok(PairingChallenge {
            pairing_id,
            challenge_id,
            nonce: nonce.to_vec(),
            expires_at_unix,
        })
    }

    pub fn complete_pairing_proof(
        &mut self,
        pairing_id: Uuid,
        controller_connection_id: Uuid,
        controller_device_id: Uuid,
        challenge_id: Uuid,
        signature: &[u8],
        now_unix: u64,
    ) -> Result<PairingRequest, PairingError> {
        if signature.len() != SIGNATURE_SIZE {
            return Err(PairingError::InvalidProof);
        }

        let signature_bytes: [u8; SIGNATURE_SIZE] = signature
            .try_into()
            .map_err(|_| PairingError::InvalidProof)?;

        let pairing = self
            .pending
            .get_mut(&pairing_id)
            .ok_or(PairingError::PairingNotFound)?;

        if now_unix >= pairing.expires_at_unix {
            return Err(PairingError::Expired);
        }

        if pairing.request.is_some() {
            return Err(PairingError::AlreadyRequested);
        }

        // Verify ownership before consuming the challenge.
        let challenge = pairing
            .challenge
            .as_ref()
            .ok_or(PairingError::RequestNotFound)?;

        if challenge.controller_connection_id != controller_connection_id
            || challenge.controller_device_id != controller_device_id
        {
            return Err(PairingError::UnauthorizedController);
        }

        if challenge.challenge_id != challenge_id {
            return Err(PairingError::InvalidProof);
        }

        if now_unix >= challenge.expires_at_unix {
            pairing.challenge = None;
            return Err(PairingError::Expired);
        }

        let nonce = challenge.nonce;
        let public_key = challenge.controller_public_key;

        let device_id_bytes: [u8; DEVICE_ID_SIZE] = *controller_device_id.as_bytes();
        let challenge_id_bytes: [u8; CHALLENGE_ID_SIZE] = *challenge_id.as_bytes();

        let proof_valid = verify_authentication(
            &public_key,
            &device_id_bytes,
            &challenge_id_bytes,
            &nonce,
            &signature_bytes,
        )
        .is_ok();

        // A correctly bound challenge is one-time,
        // even when the proof is invalid.
        pairing.challenge = None;

        if !proof_valid {
            pairing.failed_proofs = pairing.failed_proofs.saturating_add(1);

            if pairing.failed_proofs >= MAX_FAILED_PROOFS {
                self.pending.remove(&pairing_id);
                return Err(PairingError::TooManyFailedAttempts);
            }

            return Err(PairingError::InvalidProof);
        }

        let request = PairingRequest {
            pairing_id,
            host_connection_id: pairing.host_connection_id,
            host_device_id: pairing.host_device_id,
            controller_connection_id,
            controller_device_id,
            controller_public_key: public_key.to_vec(),
        };

        pairing.request = Some(request.clone());

        Ok(request)
    }

    pub fn approve_pairing(
        &mut self,
        pairing_id: Uuid,
        host_connection_id: Uuid,
        controller_device_id: Uuid,
        now_unix: u64,
    ) -> Result<PairingRequest, PairingError> {
        let pairing = self
            .pending
            .get(&pairing_id)
            .ok_or(PairingError::PairingNotFound)?;

        if pairing.host_connection_id != host_connection_id {
            return Err(PairingError::UnauthorizedHost);
        }

        if now_unix >= pairing.expires_at_unix {
            self.pending.remove(&pairing_id);
            return Err(PairingError::Expired);
        }

        let request = pairing
            .request
            .as_ref()
            .ok_or(PairingError::RequestNotFound)?;

        if request.controller_device_id != controller_device_id {
            return Err(PairingError::UnauthorizedController);
        }

        let request = request.clone();

        self.trusted.insert(
            (request.host_device_id, request.controller_device_id),
            TrustedRecord {
                host_device_id: request.host_device_id,
                trusted_device: TrustedDevice {
                    device_id: request.controller_device_id,
                    public_key: request.controller_public_key.clone(),
                    approved_at_unix: now_unix,
                },
            },
        );

        self.pending.remove(&pairing_id);

        Ok(request)
    }

    pub fn reject_pairing(
        &mut self,
        pairing_id: Uuid,
        host_connection_id: Uuid,
        controller_device_id: Uuid,
        now_unix: u64,
    ) -> Result<PairingRequest, PairingError> {
        let pairing = self
            .pending
            .get(&pairing_id)
            .ok_or(PairingError::PairingNotFound)?;

        if pairing.host_connection_id != host_connection_id {
            return Err(PairingError::UnauthorizedHost);
        }

        if now_unix >= pairing.expires_at_unix {
            self.pending.remove(&pairing_id);
            return Err(PairingError::Expired);
        }

        let request = pairing
            .request
            .as_ref()
            .ok_or(PairingError::RequestNotFound)?;

        if request.controller_device_id != controller_device_id {
            return Err(PairingError::UnauthorizedController);
        }

        let request = request.clone();

        self.pending.remove(&pairing_id);

        Ok(request)
    }

    /// Starts a fresh authentication challenge for a previously trusted
    /// controller connecting to a particular host.
    ///
    /// The controller's public key is obtained from the trusted-device
    /// record, never accepted from this authentication request.
    pub fn begin_authentication(
        &mut self,
        host_device_id: Uuid,
        controller_device_id: Uuid,
        controller_connection_id: Uuid,
        now_unix: u64,
    ) -> Result<AuthenticationChallenge, PairingError> {
        self.remove_expired(now_unix);

        if self
            .failed_authentications
            .get(&controller_connection_id)
            .copied()
            .unwrap_or(0)
            >= MAX_FAILED_AUTHENTICATIONS
        {
            return Err(PairingError::TooManyFailedAttempts);
        }

        if self
            .pending_authentication
            .contains_key(&controller_connection_id)
        {
            return Err(PairingError::AuthenticationAlreadyPending);
        }

        let record = self
            .trusted
            .get(&(host_device_id, controller_device_id))
            .ok_or(PairingError::UnauthorizedController)?;

        if record.host_device_id != host_device_id
            || record.trusted_device.device_id != controller_device_id
            || record.trusted_device.public_key.len() != 32
        {
            return Err(PairingError::UnauthorizedController);
        }

        let mut nonce = [0u8; CHALLENGE_SIZE];
        OsRng.fill_bytes(&mut nonce);

        let challenge_id = Uuid::new_v4();
        let expires_at_unix = now_unix.saturating_add(CHALLENGE_TTL_SECONDS);

        self.pending_authentication.insert(
            controller_connection_id,
            PendingAuthentication {
                host_device_id,
                controller_device_id,
                controller_connection_id,
                challenge_id,
                nonce,
                expires_at_unix,
            },
        );

        Ok(AuthenticationChallenge {
            host_device_id,
            controller_device_id,
            challenge_id,
            nonce: nonce.to_vec(),
            expires_at_unix,
        })
    }

    /// Verifies a host-bound authentication proof.
    ///
    /// A correctly bound challenge is consumed whether its signature is
    /// valid or invalid. Successful authentication returns the trusted
    /// device record so the caller can establish the authenticated identity.
    pub fn complete_authentication(
        &mut self,
        host_device_id: Uuid,
        controller_device_id: Uuid,
        controller_connection_id: Uuid,
        challenge_id: Uuid,
        signature: &[u8],
        now_unix: u64,
    ) -> Result<TrustedDevice, PairingError> {
        if signature.len() != SIGNATURE_SIZE {
            return Err(PairingError::InvalidProof);
        }

        let signature_bytes: [u8; SIGNATURE_SIZE] = signature
            .try_into()
            .map_err(|_| PairingError::InvalidProof)?;

        let challenge = self
            .pending_authentication
            .get(&controller_connection_id)
            .cloned()
            .ok_or(PairingError::AuthenticationNotFound)?;

        // Do not consume another connection's challenge.
        if challenge.controller_connection_id != controller_connection_id
            || challenge.host_device_id != host_device_id
            || challenge.controller_device_id != controller_device_id
        {
            return Err(PairingError::UnauthorizedController);
        }

        if challenge.challenge_id != challenge_id {
            return Err(PairingError::InvalidProof);
        }

        if now_unix >= challenge.expires_at_unix {
            self.pending_authentication
                .remove(&controller_connection_id);
            return Err(PairingError::Expired);
        }

        let trusted_device = self
            .trusted
            .get(&(host_device_id, controller_device_id))
            .filter(|record| {
                record.host_device_id == host_device_id
                    && record.trusted_device.device_id == controller_device_id
            })
            .map(|record| record.trusted_device.clone())
            .ok_or(PairingError::UnauthorizedController)?;

        if trusted_device.public_key.len() != 32 {
            self.pending_authentication
                .remove(&controller_connection_id);
            return Err(PairingError::InvalidPublicKey);
        }

        let public_key: [u8; 32] = trusted_device
            .public_key
            .as_slice()
            .try_into()
            .map_err(|_| PairingError::InvalidPublicKey)?;

        let proof_valid = verify_host_authentication(
            &public_key,
            host_device_id.as_bytes(),
            controller_device_id.as_bytes(),
            challenge.challenge_id.as_bytes(),
            &challenge.nonce,
            &signature_bytes,
        )
        .is_ok();

        // Consume the challenge before returning, including on bad proof.
        self.pending_authentication
            .remove(&controller_connection_id);

        if !proof_valid {
            let failures = self
                .failed_authentications
                .entry(controller_connection_id)
                .or_insert(0);

            *failures = failures.saturating_add(1);

            if *failures >= MAX_FAILED_AUTHENTICATIONS {
                // Keep the counter at the threshold so this connection
                // remains blocked from starting another authentication.
                return Err(PairingError::TooManyFailedAttempts);
            }

            return Err(PairingError::InvalidProof);
        }

        self.failed_authentications
            .remove(&controller_connection_id);

        Ok(trusted_device)
    }

    /// Checks whether a public key is trusted for this exact host/controller
    /// device pair.
    pub fn is_trusted(
        &self,
        host_device_id: Uuid,
        controller_device_id: Uuid,
        controller_public_key: &[u8],
    ) -> bool {
        let Some(record) = self.trusted.get(&(host_device_id, controller_device_id)) else {
            return false;
        };

        record.host_device_id == host_device_id
            && record.trusted_device.device_id == controller_device_id
            && constant_time_equal(&record.trusted_device.public_key, controller_public_key)
    }

    pub fn remove_expired(&mut self, now_unix: u64) {
        self.pending
            .retain(|_, pairing| now_unix < pairing.expires_at_unix);

        for pairing in self.pending.values_mut() {
            let expired = pairing
                .challenge
                .as_ref()
                .is_some_and(|challenge| now_unix >= challenge.expires_at_unix);

            if expired {
                pairing.challenge = None;
            }
        }

        self.pending_authentication
            .retain(|_, challenge| now_unix < challenge.expires_at_unix);
    }
}

fn hash_code(code: &str) -> [u8; 32] {
    Sha256::digest(code.as_bytes()).into()
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    let mut difference = 0u8;

    for (a, b) in left.iter().zip(right.iter()) {
        difference |= a ^ b;
    }

    difference == 0
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut output = String::with_capacity(bytes.len() * 2);

    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use remotix_device_identity::DeviceIdentity;

    fn sign_pairing_challenge(
        identity: &DeviceIdentity,
        device_id: Uuid,
        challenge: &PairingChallenge,
    ) -> [u8; SIGNATURE_SIZE] {
        identity
            .sign_authentication(
                device_id.as_bytes(),
                challenge.challenge_id.as_bytes(),
                &challenge.nonce,
            )
            .unwrap()
    }

    fn sign_auth_challenge(
        identity: &DeviceIdentity,
        challenge: &AuthenticationChallenge,
    ) -> [u8; SIGNATURE_SIZE] {
        identity
            .sign_host_authentication(
                challenge.host_device_id.as_bytes(),
                challenge.controller_device_id.as_bytes(),
                challenge.challenge_id.as_bytes(),
                &challenge.nonce,
            )
            .unwrap()
    }

    fn setup() -> (
        PairingManager,
        PairingCreated,
        Uuid,
        Uuid,
        Uuid,
        Uuid,
        DeviceIdentity,
    ) {
        let host_connection = Uuid::new_v4();
        let host_device = Uuid::new_v4();
        let controller_connection = Uuid::new_v4();
        let controller_device = Uuid::new_v4();

        let identity = DeviceIdentity::generate();

        let mut manager = PairingManager::new();

        let created = manager
            .create_pairing(host_connection, host_device, 100)
            .unwrap();

        (
            manager,
            created,
            host_connection,
            host_device,
            controller_connection,
            controller_device,
            identity,
        )
    }

    fn approve_test_device(
        manager: &mut PairingManager,
        created: &PairingCreated,
        host_connection: Uuid,
        controller_connection: Uuid,
        controller_device: Uuid,
        identity: &DeviceIdentity,
    ) {
        let challenge = manager
            .begin_pairing_request(
                created.pairing_id,
                &created.pairing_code,
                controller_connection,
                controller_device,
                &identity.public_key(),
                101,
            )
            .unwrap();

        let signature = sign_pairing_challenge(identity, controller_device, &challenge);

        manager
            .complete_pairing_proof(
                created.pairing_id,
                controller_connection,
                controller_device,
                challenge.challenge_id,
                &signature,
                102,
            )
            .unwrap();

        manager
            .approve_pairing(created.pairing_id, host_connection, controller_device, 103)
            .unwrap();
    }

    #[test]
    fn creates_random_pairing_code() {
        let (manager, created, _, _, _, _, _) = setup();

        assert_eq!(created.pairing_code.len(), 64);
        assert_eq!(created.expires_at_unix, 400);
        assert_eq!(manager.pending.len(), 1);
    }

    #[test]
    fn rejects_wrong_code() {
        let (mut manager, created, _, _, connection, device, identity) = setup();

        let result = manager.begin_pairing_request(
            created.pairing_id,
            "wrong-code",
            connection,
            device,
            &identity.public_key(),
            101,
        );

        assert_eq!(result.unwrap_err(), PairingError::InvalidCode);
    }

    #[test]
    fn rejects_invalid_public_key_length() {
        let (mut manager, created, _, _, connection, device, _) = setup();

        let result = manager.begin_pairing_request(
            created.pairing_id,
            &created.pairing_code,
            connection,
            device,
            &[1, 2, 3],
            101,
        );

        assert_eq!(result.unwrap_err(), PairingError::InvalidPublicKey);
    }

    #[test]
    fn verifies_proof_and_approves_device() {
        let (
            mut manager,
            created,
            host_connection,
            host_device,
            controller_connection,
            controller_device,
            identity,
        ) = setup();

        let public_key = identity.public_key();

        let challenge = manager
            .begin_pairing_request(
                created.pairing_id,
                &created.pairing_code,
                controller_connection,
                controller_device,
                &public_key,
                101,
            )
            .unwrap();

        let signature = sign_pairing_challenge(&identity, controller_device, &challenge);

        manager
            .complete_pairing_proof(
                created.pairing_id,
                controller_connection,
                controller_device,
                challenge.challenge_id,
                &signature,
                102,
            )
            .unwrap();

        manager
            .approve_pairing(created.pairing_id, host_connection, controller_device, 103)
            .unwrap();

        assert!(manager.is_trusted(host_device, controller_device, &public_key));
        assert!(!manager.is_trusted(host_device, controller_device, &[0u8; 32]));
    }

    #[test]
    fn rejects_replayed_challenge() {
        let (mut manager, created, _, _, connection, device, identity) = setup();

        let challenge = manager
            .begin_pairing_request(
                created.pairing_id,
                &created.pairing_code,
                connection,
                device,
                &identity.public_key(),
                101,
            )
            .unwrap();

        let signature = sign_pairing_challenge(&identity, device, &challenge);

        manager
            .complete_pairing_proof(
                created.pairing_id,
                connection,
                device,
                challenge.challenge_id,
                &signature,
                102,
            )
            .unwrap();

        let replay = manager.complete_pairing_proof(
            created.pairing_id,
            connection,
            device,
            challenge.challenge_id,
            &signature,
            103,
        );

        assert_eq!(replay.unwrap_err(), PairingError::AlreadyRequested);
    }

    #[test]
    fn wrong_connection_cannot_consume_challenge() {
        let (mut manager, created, _, _, connection, device, identity) = setup();

        let challenge = manager
            .begin_pairing_request(
                created.pairing_id,
                &created.pairing_code,
                connection,
                device,
                &identity.public_key(),
                101,
            )
            .unwrap();

        let wrong_connection = Uuid::new_v4();

        let wrong_attempt = manager.complete_pairing_proof(
            created.pairing_id,
            wrong_connection,
            device,
            challenge.challenge_id,
            &[0u8; SIGNATURE_SIZE],
            102,
        );

        assert_eq!(
            wrong_attempt.unwrap_err(),
            PairingError::UnauthorizedController
        );

        let signature = sign_pairing_challenge(&identity, device, &challenge);

        assert!(
            manager
                .complete_pairing_proof(
                    created.pairing_id,
                    connection,
                    device,
                    challenge.challenge_id,
                    &signature,
                    103,
                )
                .is_ok()
        );
    }

    #[test]
    fn limits_failed_pairing_proofs() {
        let (mut manager, created, _, _, connection, device, identity) = setup();

        for attempt in 0..MAX_FAILED_PROOFS {
            let challenge = manager
                .begin_pairing_request(
                    created.pairing_id,
                    &created.pairing_code,
                    connection,
                    device,
                    &identity.public_key(),
                    101 + u64::from(attempt),
                )
                .unwrap();

            let result = manager.complete_pairing_proof(
                created.pairing_id,
                connection,
                device,
                challenge.challenge_id,
                &[0u8; SIGNATURE_SIZE],
                102 + u64::from(attempt),
            );

            if attempt + 1 == MAX_FAILED_PROOFS {
                assert_eq!(result.unwrap_err(), PairingError::TooManyFailedAttempts);
            } else {
                assert_eq!(result.unwrap_err(), PairingError::InvalidProof);
            }
        }

        assert!(!manager.pending.contains_key(&created.pairing_id));
    }

    #[test]
    fn rejects_approval_from_wrong_host() {
        let (mut manager, created, _, _, connection, device, identity) = setup();

        let challenge = manager
            .begin_pairing_request(
                created.pairing_id,
                &created.pairing_code,
                connection,
                device,
                &identity.public_key(),
                101,
            )
            .unwrap();

        let signature = sign_pairing_challenge(&identity, device, &challenge);

        manager
            .complete_pairing_proof(
                created.pairing_id,
                connection,
                device,
                challenge.challenge_id,
                &signature,
                102,
            )
            .unwrap();

        let result = manager.approve_pairing(created.pairing_id, Uuid::new_v4(), device, 103);

        assert_eq!(result.unwrap_err(), PairingError::UnauthorizedHost);
    }

    #[test]
    fn expires_pairing_and_challenge() {
        let (mut manager, created, _, _, connection, device, identity) = setup();

        manager.remove_expired(400);

        assert!(!manager.pending.contains_key(&created.pairing_id));

        let second = manager
            .create_pairing(Uuid::new_v4(), Uuid::new_v4(), 500)
            .unwrap();

        let challenge = manager
            .begin_pairing_request(
                second.pairing_id,
                &second.pairing_code,
                connection,
                device,
                &identity.public_key(),
                501,
            )
            .unwrap();

        manager.remove_expired(561);

        assert!(manager.pending[&second.pairing_id].challenge.is_none());
        assert_eq!(challenge.expires_at_unix, 561);
    }

    #[test]
    fn begins_and_completes_host_bound_authentication() {
        let (
            mut manager,
            created,
            host_connection,
            host_device,
            controller_connection,
            controller_device,
            identity,
        ) = setup();

        approve_test_device(
            &mut manager,
            &created,
            host_connection,
            controller_connection,
            controller_device,
            &identity,
        );

        let challenge = manager
            .begin_authentication(host_device, controller_device, controller_connection, 200)
            .unwrap();

        assert_eq!(challenge.host_device_id, host_device);
        assert_eq!(challenge.controller_device_id, controller_device);
        assert_eq!(challenge.nonce.len(), CHALLENGE_SIZE);
        assert_eq!(challenge.expires_at_unix, 260);

        let signature = sign_auth_challenge(&identity, &challenge);

        let trusted = manager
            .complete_authentication(
                host_device,
                controller_device,
                controller_connection,
                challenge.challenge_id,
                &signature,
                201,
            )
            .unwrap();

        assert_eq!(trusted.device_id, controller_device);
        assert_eq!(trusted.public_key, identity.public_key());
    }

    #[test]
    fn rejects_authentication_for_untrusted_host() {
        let (
            mut manager,
            _created,
            _host_connection,
            host_device,
            controller_connection,
            controller_device,
            _identity,
        ) = setup();

        let result = manager.begin_authentication(
            host_device,
            controller_device,
            controller_connection,
            200,
        );

        assert_eq!(result.unwrap_err(), PairingError::UnauthorizedController);
    }

    #[test]
    fn rejects_host_bound_proof_for_wrong_host() {
        let (
            mut manager,
            created,
            host_connection,
            host_device,
            controller_connection,
            controller_device,
            identity,
        ) = setup();

        approve_test_device(
            &mut manager,
            &created,
            host_connection,
            controller_connection,
            controller_device,
            &identity,
        );

        let challenge = manager
            .begin_authentication(host_device, controller_device, controller_connection, 200)
            .unwrap();

        // Sign the challenge using a different host ID.
        let wrong_host = Uuid::new_v4();

        let wrong_signature = identity
            .sign_host_authentication(
                wrong_host.as_bytes(),
                controller_device.as_bytes(),
                challenge.challenge_id.as_bytes(),
                &challenge.nonce,
            )
            .unwrap();

        let result = manager.complete_authentication(
            host_device,
            controller_device,
            controller_connection,
            challenge.challenge_id,
            &wrong_signature,
            201,
        );

        assert_eq!(result.unwrap_err(), PairingError::InvalidProof);
    }

    #[test]
    fn rejects_replayed_authentication_challenge() {
        let (
            mut manager,
            created,
            host_connection,
            host_device,
            controller_connection,
            controller_device,
            identity,
        ) = setup();

        approve_test_device(
            &mut manager,
            &created,
            host_connection,
            controller_connection,
            controller_device,
            &identity,
        );

        let challenge = manager
            .begin_authentication(host_device, controller_device, controller_connection, 200)
            .unwrap();

        let signature = sign_auth_challenge(&identity, &challenge);

        manager
            .complete_authentication(
                host_device,
                controller_device,
                controller_connection,
                challenge.challenge_id,
                &signature,
                201,
            )
            .unwrap();

        let replay = manager.complete_authentication(
            host_device,
            controller_device,
            controller_connection,
            challenge.challenge_id,
            &signature,
            202,
        );

        assert_eq!(replay.unwrap_err(), PairingError::AuthenticationNotFound);
    }

    #[test]
    fn rejects_expired_authentication_challenge() {
        let (
            mut manager,
            created,
            host_connection,
            host_device,
            controller_connection,
            controller_device,
            identity,
        ) = setup();

        approve_test_device(
            &mut manager,
            &created,
            host_connection,
            controller_connection,
            controller_device,
            &identity,
        );

        let challenge = manager
            .begin_authentication(host_device, controller_device, controller_connection, 200)
            .unwrap();

        let signature = sign_auth_challenge(&identity, &challenge);

        let result = manager.complete_authentication(
            host_device,
            controller_device,
            controller_connection,
            challenge.challenge_id,
            &signature,
            260,
        );

        assert_eq!(result.unwrap_err(), PairingError::Expired);
    }

    #[test]
    fn rejects_authentication_from_another_connection() {
        let (
            mut manager,
            created,
            host_connection,
            host_device,
            controller_connection,
            controller_device,
            identity,
        ) = setup();

        approve_test_device(
            &mut manager,
            &created,
            host_connection,
            controller_connection,
            controller_device,
            &identity,
        );

        let challenge = manager
            .begin_authentication(host_device, controller_device, controller_connection, 200)
            .unwrap();

        let signature = sign_auth_challenge(&identity, &challenge);
        let wrong_connection = Uuid::new_v4();

        let result = manager.complete_authentication(
            host_device,
            controller_device,
            wrong_connection,
            challenge.challenge_id,
            &signature,
            201,
        );

        assert_eq!(result.unwrap_err(), PairingError::AuthenticationNotFound);

        // The original connection's challenge remains usable.
        assert!(
            manager
                .complete_authentication(
                    host_device,
                    controller_device,
                    controller_connection,
                    challenge.challenge_id,
                    &signature,
                    202,
                )
                .is_ok()
        );

        let _ = host_connection;
    }

    #[test]
    fn limits_failed_authentication_attempts() {
        let (
            mut manager,
            created,
            host_connection,
            host_device,
            controller_connection,
            controller_device,
            identity,
        ) = setup();

        approve_test_device(
            &mut manager,
            &created,
            host_connection,
            controller_connection,
            controller_device,
            &identity,
        );

        for attempt in 0..MAX_FAILED_AUTHENTICATIONS {
            let challenge = manager
                .begin_authentication(
                    host_device,
                    controller_device,
                    controller_connection,
                    200 + u64::from(attempt) * 2,
                )
                .unwrap();

            let result = manager.complete_authentication(
                host_device,
                controller_device,
                controller_connection,
                challenge.challenge_id,
                &[0u8; SIGNATURE_SIZE],
                201 + u64::from(attempt) * 2,
            );

            if attempt + 1 == MAX_FAILED_AUTHENTICATIONS {
                assert_eq!(result.unwrap_err(), PairingError::TooManyFailedAttempts);
            } else {
                assert_eq!(result.unwrap_err(), PairingError::InvalidProof);
            }
        }

        let blocked = manager.begin_authentication(
            host_device,
            controller_device,
            controller_connection,
            300,
        );

        assert_eq!(blocked.unwrap_err(), PairingError::TooManyFailedAttempts);
    }

    #[test]
    fn prevents_multiple_pending_authentication_challenges_on_one_connection() {
        let (
            mut manager,
            created,
            host_connection,
            host_device,
            controller_connection,
            controller_device,
            identity,
        ) = setup();

        approve_test_device(
            &mut manager,
            &created,
            host_connection,
            controller_connection,
            controller_device,
            &identity,
        );

        manager
            .begin_authentication(host_device, controller_device, controller_connection, 200)
            .unwrap();

        let second = manager.begin_authentication(
            host_device,
            controller_device,
            controller_connection,
            201,
        );

        assert_eq!(
            second.unwrap_err(),
            PairingError::AuthenticationAlreadyPending
        );
    }
}
