mod pairing;

use axum::{
    Router,
    extract::{
        State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::Response,
    routing::get,
};
use futures_util::{SinkExt, StreamExt};
use pairing::{PairingError, PairingManager};
use remotix_protocol::{DeviceRole, PairingStatus, ProtocolError, SignalEnvelope, SignalMessage};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::{Mutex, mpsc, watch};
use tracing::{info, warn};
use uuid::Uuid;

const OUTGOING_QUEUE_CAPACITY: usize = 32;
const MAX_WS_MESSAGE_SIZE: usize = 64 * 1024;
const MAX_WS_FRAME_SIZE: usize = 64 * 1024;

#[derive(Clone)]
struct AppState {
    expected_token: String,
    sessions: Arc<Mutex<HashMap<Uuid, Session>>>,
    pairings: Arc<Mutex<PairingManager>>,
    connections: Arc<Mutex<HashMap<Uuid, Peer>>>,
}

#[derive(Clone)]
struct Peer {
    connection_id: Uuid,
    outgoing: mpsc::Sender<Message>,
    disconnect: watch::Sender<bool>,
}

struct Session {
    host_device_id: Uuid,
    host: Option<Peer>,
    controller: Option<Peer>,
}

fn current_unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

async fn health() -> &'static str {
    "REMOTIX signalling online"
}

async fn websocket_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Result<Response, StatusCode> {
    let supplied_token = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));

    if supplied_token != Some(state.expected_token.as_str()) {
        warn!("Rejected WebSocket connection: invalid or missing token");
        return Err(StatusCode::UNAUTHORIZED);
    }

    info!("Authenticated development WebSocket connection accepted");

    Ok(ws
        .max_message_size(MAX_WS_MESSAGE_SIZE)
        .max_frame_size(MAX_WS_FRAME_SIZE)
        .on_upgrade(move |socket| {
            handle_socket(
                socket,
                state.sessions.clone(),
                state.pairings.clone(),
                state.connections.clone(),
            )
        }))
}

fn send_envelope(outgoing: &mpsc::Sender<Message>, envelope: &SignalEnvelope) -> bool {
    let json = match serde_json::to_string(envelope) {
        Ok(json) => json,
        Err(error) => {
            warn!("Could not serialize signalling message: {error}");
            return false;
        }
    };

    match outgoing.try_send(Message::Text(json.into())) {
        Ok(()) => true,
        Err(error) => {
            warn!("Could not queue outgoing WebSocket message: {error}");
            false
        }
    }
}

fn send_to_peer(peer: &Peer, envelope: &SignalEnvelope) -> bool {
    if send_envelope(&peer.outgoing, envelope) {
        return true;
    }

    warn!(
        "Disconnecting slow or unavailable client: {}",
        peer.connection_id
    );

    let _ = peer.disconnect.send(true);
    false
}

fn send_error(outgoing: &mpsc::Sender<Message>, code: &str, description: &str) -> bool {
    let envelope = SignalEnvelope::new(SignalMessage::Error {
        code: code.to_string(),
        message: description.to_string(),
    });

    send_envelope(outgoing, &envelope)
}

fn pairing_error_response(error: PairingError) -> (&'static str, &'static str) {
    match error {
        PairingError::CapacityReached => (
            "pairing_capacity",
            "The server has reached its pairing capacity",
        ),
        PairingError::PairingNotFound => ("pairing_not_found", "The pairing does not exist"),
        PairingError::InvalidCode => (
            "invalid_pairing_code",
            "The supplied pairing code is invalid",
        ),
        PairingError::InvalidPublicKey => {
            ("invalid_public_key", "The controller public key is invalid")
        }
        PairingError::InvalidProof => (
            "invalid_pairing_proof",
            "The cryptographic pairing proof is invalid",
        ),
        PairingError::Expired => ("pairing_expired", "The pairing or challenge has expired"),
        PairingError::AlreadyRequested => (
            "pairing_already_requested",
            "A pairing request already exists",
        ),
        PairingError::RequestNotFound => (
            "pairing_request_not_found",
            "No verified pairing request exists",
        ),
        PairingError::UnauthorizedHost => (
            "unauthorized_host",
            "This connection does not own the pairing",
        ),
        PairingError::UnauthorizedController => (
            "unauthorized_controller",
            "This connection does not own the request",
        ),
        PairingError::TooManyFailedAttempts => {
            ("too_many_failed_proofs", "Too many invalid pairing proofs")
        }
        PairingError::AuthenticationNotFound => (
            "authentication_not_found",
            "No pending authentication challenge exists for this connection",
        ),
        PairingError::AuthenticationAlreadyPending => (
            "authentication_already_pending",
            "This connection already has a pending authentication challenge",
        ),
    }
}

async fn route_message(
    envelope: SignalEnvelope,
    connection_id: Uuid,
    role: &mut Option<DeviceRole>,
    device_id: &mut Option<Uuid>,
    authenticated_host_id: &mut Option<Uuid>,
    outgoing: &mpsc::Sender<Message>,
    disconnect: &watch::Sender<bool>,
    sessions: &Arc<Mutex<HashMap<Uuid, Session>>>,
    pairings: &Arc<Mutex<PairingManager>>,
    connections: &Arc<Mutex<HashMap<Uuid, Peer>>>,
) -> Result<(), (&'static str, &'static str)> {
    match &envelope.message {
        SignalMessage::Register {
            role: requested_role,
            device_id: requested_device_id,
        } => {
            if role.is_some() {
                return Err(("already_registered", "Connection is already registered"));
            }

            *role = Some(requested_role.clone());
            *device_id = Some(*requested_device_id);

            info!(
                "Device registered: role={:?}, device_id={}",
                requested_role, requested_device_id
            );

            if !send_envelope(outgoing, &envelope) {
                let _ = disconnect.send(true);
            }
        }

        // ---------------------------------------------------------
        // HOST PAIRING CREATION
        // ---------------------------------------------------------
        SignalMessage::CreatePairing { host_device_id } => {
            if role.as_ref() != Some(&DeviceRole::Host) {
                return Err(("forbidden", "Only registered hosts can create pairings"));
            }

            if *device_id != Some(*host_device_id) {
                return Err((
                    "device_mismatch",
                    "Pairing device ID does not match the registered host",
                ));
            }

            let created = {
                let mut manager = pairings.lock().await;

                manager
                    .create_pairing(connection_id, *host_device_id, current_unix_time())
                    .map_err(pairing_error_response)?
            };

            let response = SignalEnvelope::new(SignalMessage::PairingCreated {
                pairing_id: created.pairing_id,
                pairing_code: created.pairing_code,
                expires_at_unix: created.expires_at_unix,
            });

            if !send_envelope(outgoing, &response) {
                let _ = disconnect.send(true);
            }

            info!("Pairing created for host device: {host_device_id}");
        }

        // ---------------------------------------------------------
        // CONTROLLER REQUESTS PAIRING
        // ---------------------------------------------------------
        SignalMessage::RequestPairing {
            pairing_id,
            pairing_code,
            controller_device_id,
            controller_public_key,
        } => {
            if role.as_ref() == Some(&DeviceRole::Host) {
                return Err(("forbidden", "A host cannot request controller pairing"));
            }

            if let Some(registered_device) = device_id {
                if registered_device != controller_device_id {
                    return Err((
                        "device_mismatch",
                        "Controller device ID does not match this connection",
                    ));
                }
            }

            let challenge = {
                let mut manager = pairings.lock().await;

                manager
                    .begin_pairing_request(
                        *pairing_id,
                        pairing_code,
                        connection_id,
                        *controller_device_id,
                        controller_public_key,
                        current_unix_time(),
                    )
                    .map_err(pairing_error_response)?
            };

            let nonce: [u8; 32] = challenge
                .nonce
                .as_slice()
                .try_into()
                .map_err(|_| ("invalid_challenge", "Server generated an invalid challenge"))?;

            let response = SignalEnvelope::new(SignalMessage::PairingChallenge {
                pairing_id: challenge.pairing_id,
                challenge_id: challenge.challenge_id,
                nonce,
                expires_at_unix: challenge.expires_at_unix,
            });

            if !send_envelope(outgoing, &response) {
                let _ = disconnect.send(true);
            }

            info!("Pairing challenge issued: {}", challenge.pairing_id);
        }

        // ---------------------------------------------------------
        // CONTROLLER PROVES OWNERSHIP OF PRIVATE KEY
        // ---------------------------------------------------------
        SignalMessage::ProvePairing {
            pairing_id,
            controller_device_id,
            challenge_id,
            signature,
        } => {
            if role.as_ref() == Some(&DeviceRole::Host) {
                return Err((
                    "forbidden",
                    "A host cannot submit a controller pairing proof",
                ));
            }

            if let Some(registered_device) = device_id {
                if registered_device != controller_device_id {
                    return Err((
                        "device_mismatch",
                        "Controller device ID does not match this connection",
                    ));
                }
            }

            let request = {
                let mut manager = pairings.lock().await;

                manager
                    .complete_pairing_proof(
                        *pairing_id,
                        connection_id,
                        *controller_device_id,
                        *challenge_id,
                        signature,
                        current_unix_time(),
                    )
                    .map_err(pairing_error_response)?
            };

            // Locate the host connection that created this pairing.
            let host_peer = {
                let connected = connections.lock().await;
                connected.get(&request.host_connection_id).cloned()
            };

            let host_peer = host_peer.ok_or((
                "host_unavailable",
                "The host disconnected before pairing approval",
            ))?;

            let public_key: [u8; 32] = request
                .controller_public_key
                .as_slice()
                .try_into()
                .map_err(|_| {
                    (
                        "invalid_public_key",
                        "Stored public key has an invalid length",
                    )
                })?;

            let host_notification = SignalEnvelope::new(SignalMessage::PairingRequested {
                pairing_id: request.pairing_id,
                controller_device_id: request.controller_device_id,
                controller_public_key: public_key,
            });

            if !send_to_peer(&host_peer, &host_notification) {
                return Err((
                    "delivery_failed",
                    "Could not notify the host about the pairing request",
                ));
            }

            let controller_response = SignalEnvelope::new(SignalMessage::PairingResult {
                pairing_id: request.pairing_id,
                status: PairingStatus::Pending,
            });

            if !send_envelope(outgoing, &controller_response) {
                let _ = disconnect.send(true);
            }

            info!(
                "Verified pairing request from controller {}",
                request.controller_device_id
            );
        }

        // ---------------------------------------------------------
        // HOST APPROVES A CONTROLLER
        // ---------------------------------------------------------
        SignalMessage::ApprovePairing {
            pairing_id,
            controller_device_id,
        } => {
            if role.as_ref() != Some(&DeviceRole::Host) {
                return Err(("forbidden", "Only a registered host can approve pairing"));
            }

            let request = {
                let mut manager = pairings.lock().await;

                manager
                    .approve_pairing(
                        *pairing_id,
                        connection_id,
                        *controller_device_id,
                        current_unix_time(),
                    )
                    .map_err(pairing_error_response)?
            };

            let controller_peer = {
                let connected = connections.lock().await;
                connected.get(&request.controller_connection_id).cloned()
            };

            let result = SignalEnvelope::new(SignalMessage::PairingResult {
                pairing_id: request.pairing_id,
                status: PairingStatus::Approved,
            });

            if let Some(peer) = controller_peer {
                send_to_peer(&peer, &result);
            }

            if !send_envelope(outgoing, &result) {
                let _ = disconnect.send(true);
            }

            info!(
                "Host approved controller device: {}",
                request.controller_device_id
            );
        }

        // ---------------------------------------------------------
        // HOST REJECTS A CONTROLLER
        // ---------------------------------------------------------
        SignalMessage::RejectPairing {
            pairing_id,
            controller_device_id,
        } => {
            if role.as_ref() != Some(&DeviceRole::Host) {
                return Err(("forbidden", "Only a registered host can reject pairing"));
            }

            let request = {
                let mut manager = pairings.lock().await;

                manager
                    .reject_pairing(
                        *pairing_id,
                        connection_id,
                        *controller_device_id,
                        current_unix_time(),
                    )
                    .map_err(pairing_error_response)?
            };

            let controller_peer = {
                let connected = connections.lock().await;
                connected.get(&request.controller_connection_id).cloned()
            };

            let result = SignalEnvelope::new(SignalMessage::PairingResult {
                pairing_id: request.pairing_id,
                status: PairingStatus::Rejected,
            });

            if let Some(peer) = controller_peer {
                send_to_peer(&peer, &result);
            }

            if !send_envelope(outgoing, &result) {
                let _ = disconnect.send(true);
            }

            info!(
                "Host rejected controller device: {}",
                request.controller_device_id
            );
        }

        // ---------------------------------------------------------
        // CONTROLLER BEGINS HOST-BOUND AUTHENTICATION
        // ---------------------------------------------------------
        SignalMessage::BeginAuthentication {
            host_device_id,
            controller_device_id,
        } => {
            if role.as_ref() == Some(&DeviceRole::Host) {
                return Err(("forbidden", "Hosts cannot authenticate as controllers"));
            }

            if let Some(registered_device) = device_id {
                if registered_device != controller_device_id {
                    return Err((
                        "device_mismatch",
                        "Controller device ID does not match this connection",
                    ));
                }
            }

            if authenticated_host_id.is_some() {
                return Err((
                    "already_authenticated",
                    "This connection has already authenticated for a host",
                ));
            }

            let challenge = {
                let mut manager = pairings.lock().await;
                manager
                    .begin_authentication(
                        *host_device_id,
                        *controller_device_id,
                        connection_id,
                        current_unix_time(),
                    )
                    .map_err(pairing_error_response)?
            };

            let nonce: [u8; 32] = challenge
                .nonce
                .as_slice()
                .try_into()
                .map_err(|_| ("invalid_challenge", "Server generated an invalid challenge"))?;

            let response = SignalEnvelope::new(SignalMessage::AuthenticationChallenge {
                host_device_id: challenge.host_device_id,
                controller_device_id: challenge.controller_device_id,
                challenge_id: challenge.challenge_id,
                nonce,
                expires_at_unix: challenge.expires_at_unix,
            });

            if !send_envelope(outgoing, &response) {
                let _ = disconnect.send(true);
            }
        }

        // ---------------------------------------------------------
        // CONTROLLER PROVES HOST-BOUND DEVICE IDENTITY
        // ---------------------------------------------------------
        SignalMessage::Authenticate {
            host_device_id,
            controller_device_id,
            challenge_id,
            signature,
        } => {
            if role.as_ref() == Some(&DeviceRole::Host) {
                return Err(("forbidden", "Hosts cannot authenticate as controllers"));
            }

            if let Some(registered_device) = device_id {
                if registered_device != controller_device_id {
                    return Err((
                        "device_mismatch",
                        "Controller device ID does not match this connection",
                    ));
                }
            }

            if authenticated_host_id.is_some() {
                return Err((
                    "already_authenticated",
                    "This connection has already authenticated for a host",
                ));
            }

            let trusted_device = {
                let mut manager = pairings.lock().await;
                manager
                    .complete_authentication(
                        *host_device_id,
                        *controller_device_id,
                        connection_id,
                        *challenge_id,
                        signature,
                        current_unix_time(),
                    )
                    .map_err(pairing_error_response)?
            };

            if trusted_device.device_id != *controller_device_id {
                return Err((
                    "unauthorized_controller",
                    "Authenticated device identity does not match the request",
                ));
            }

            *role = Some(DeviceRole::Controller);
            *device_id = Some(trusted_device.device_id);
            *authenticated_host_id = Some(*host_device_id);

            let response = SignalEnvelope::new(SignalMessage::Authenticated {
                host_device_id: *host_device_id,
                controller_device_id: trusted_device.device_id,
                role: DeviceRole::Controller,
            });

            if !send_envelope(outgoing, &response) {
                let _ = disconnect.send(true);
            }

            info!(
                "Controller authenticated for host {}: {}",
                host_device_id, trusted_device.device_id
            );
        }

        // ---------------------------------------------------------
        // SESSION CREATION
        // ---------------------------------------------------------
        SignalMessage::CreateSession { session_id } => {
            if role.as_ref() != Some(&DeviceRole::Host) {
                return Err(("forbidden", "Only registered hosts can create sessions"));
            }

            let host_device_id =
                (*device_id).ok_or(("not_registered", "Host device identity is missing"))?;

            let mut sessions = sessions.lock().await;

            if sessions.contains_key(session_id) {
                return Err(("session_exists", "Session ID is already in use"));
            }

            sessions.insert(
                *session_id,
                Session {
                    host_device_id,
                    host: Some(Peer {
                        connection_id,
                        outgoing: outgoing.clone(),
                        disconnect: disconnect.clone(),
                    }),
                    controller: None,
                },
            );

            info!("Session created: {session_id}");

            if !send_envelope(outgoing, &envelope) {
                let _ = disconnect.send(true);
            }
        }

        // ---------------------------------------------------------
        // SESSION JOIN
        // ---------------------------------------------------------
        SignalMessage::JoinSession { session_id } => {
            if role.as_ref() != Some(&DeviceRole::Controller) {
                return Err(("forbidden", "Only registered controllers can join sessions"));
            }

            {
                let mut sessions = sessions.lock().await;

                let session = sessions
                    .get_mut(session_id)
                    .ok_or(("session_not_found", "Requested session does not exist"))?;

                if *authenticated_host_id != Some(session.host_device_id) {
                    return Err((
                        "host_authentication_required",
                        "Authenticate for this session's host before joining",
                    ));
                }

                if *device_id == None {
                    return Err(("not_authenticated", "Controller device identity is missing"));
                }

                if session.controller.is_some() {
                    return Err(("session_full", "This session already has a controller"));
                }

                let host = session
                    .host
                    .as_ref()
                    .ok_or(("host_unavailable", "Session host is unavailable"))?;

                let host_peer = host.clone();

                if !send_to_peer(&host_peer, &envelope) {
                    return Err(("delivery_failed", "Could not notify the session host"));
                }

                session.controller = Some(Peer {
                    connection_id,
                    outgoing: outgoing.clone(),
                    disconnect: disconnect.clone(),
                });
            }

            info!("Controller joined session: {session_id}");

            if !send_envelope(outgoing, &envelope) {
                let _ = disconnect.send(true);
            }
        }

        // ---------------------------------------------------------
        // WEBRTC OFFER
        // ---------------------------------------------------------
        SignalMessage::Offer { session_id, .. } => {
            if role.as_ref() != Some(&DeviceRole::Host) {
                return Err(("forbidden", "Only the host can send an offer"));
            }

            let controller = {
                let sessions = sessions.lock().await;

                let session = sessions
                    .get(session_id)
                    .ok_or(("session_not_found", "Session does not exist"))?;

                let host = session
                    .host
                    .as_ref()
                    .ok_or(("host_unavailable", "Session host is unavailable"))?;

                if host.connection_id != connection_id {
                    return Err(("forbidden", "Connection is not this session's host"));
                }

                session
                    .controller
                    .clone()
                    .ok_or(("controller_not_ready", "Controller has not joined yet"))?
            };

            if !send_to_peer(&controller, &envelope) {
                return Err(("delivery_failed", "Could not deliver offer"));
            }
        }

        // ---------------------------------------------------------
        // WEBRTC ANSWER
        // ---------------------------------------------------------
        SignalMessage::Answer { session_id, .. } => {
            if role.as_ref() != Some(&DeviceRole::Controller) {
                return Err(("forbidden", "Only the controller can send an answer"));
            }

            let host = {
                let sessions = sessions.lock().await;

                let session = sessions
                    .get(session_id)
                    .ok_or(("session_not_found", "Session does not exist"))?;

                let controller = session
                    .controller
                    .as_ref()
                    .ok_or(("controller_unavailable", "Controller is unavailable"))?;

                if controller.connection_id != connection_id {
                    return Err(("forbidden", "Connection is not this session's controller"));
                }

                session
                    .host
                    .clone()
                    .ok_or(("host_unavailable", "Session host is unavailable"))?
            };

            if !send_to_peer(&host, &envelope) {
                return Err(("delivery_failed", "Could not deliver answer"));
            }
        }

        // ---------------------------------------------------------
        // WEBRTC ICE CANDIDATE
        // ---------------------------------------------------------
        SignalMessage::IceCandidate { session_id, .. } => {
            let peer = {
                let sessions = sessions.lock().await;

                let session = sessions
                    .get(session_id)
                    .ok_or(("session_not_found", "Session does not exist"))?;

                let host_id = session.host.as_ref().map(|peer| peer.connection_id);
                let controller_id = session.controller.as_ref().map(|peer| peer.connection_id);

                if host_id == Some(connection_id) {
                    session.controller.clone()
                } else if controller_id == Some(connection_id) {
                    session.host.clone()
                } else {
                    return Err(("forbidden", "Connection is not part of this session"));
                }
                .ok_or(("peer_unavailable", "The other participant is unavailable"))?
            };

            if !send_to_peer(&peer, &envelope) {
                return Err(("delivery_failed", "Could not deliver ICE candidate"));
            }
        }

        // ---------------------------------------------------------
        // SESSION END
        // ---------------------------------------------------------
        SignalMessage::EndSession { session_id } => {
            let peer = {
                let mut sessions = sessions.lock().await;

                let session = sessions
                    .get(session_id)
                    .ok_or(("session_not_found", "Session does not exist"))?;

                let host_id = session.host.as_ref().map(|peer| peer.connection_id);
                let controller_id = session.controller.as_ref().map(|peer| peer.connection_id);

                let peer = if host_id == Some(connection_id) {
                    session.controller.clone()
                } else if controller_id == Some(connection_id) {
                    session.host.clone()
                } else {
                    return Err(("forbidden", "Connection is not part of this session"));
                };

                sessions.remove(session_id);

                peer
            };

            if let Some(peer) = peer {
                send_to_peer(&peer, &envelope);
            }

            info!("Session ended: {session_id}");

            if !send_envelope(outgoing, &envelope) {
                let _ = disconnect.send(true);
            }
        }

        // ---------------------------------------------------------
        // SERVER-ONLY MESSAGES
        // ---------------------------------------------------------
        SignalMessage::PairingCreated { .. }
        | SignalMessage::PairingChallenge { .. }
        | SignalMessage::PairingRequested { .. }
        | SignalMessage::PairingResult { .. }
        | SignalMessage::AuthenticationChallenge { .. }
        | SignalMessage::Authenticated { .. } => {
            return Err((
                "invalid_message",
                "Clients cannot send server-generated messages",
            ));
        }

        SignalMessage::Error { .. } => {
            return Err((
                "invalid_message",
                "Clients cannot send server error messages",
            ));
        }
    }

    Ok(())
}

async fn cleanup_connection(connection_id: Uuid, sessions: &Arc<Mutex<HashMap<Uuid, Session>>>) {
    let mut sessions = sessions.lock().await;

    let affected_ids: Vec<Uuid> = sessions
        .iter()
        .filter_map(|(session_id, session)| {
            let is_host = session
                .host
                .as_ref()
                .is_some_and(|peer| peer.connection_id == connection_id);

            let is_controller = session
                .controller
                .as_ref()
                .is_some_and(|peer| peer.connection_id == connection_id);

            (is_host || is_controller).then_some(*session_id)
        })
        .collect();

    for session_id in affected_ids {
        if let Some(session) = sessions.remove(&session_id) {
            let peer = session
                .host
                .filter(|peer| peer.connection_id != connection_id)
                .or_else(|| {
                    session
                        .controller
                        .filter(|peer| peer.connection_id != connection_id)
                });

            if let Some(peer) = peer {
                let ended = SignalEnvelope::new(SignalMessage::EndSession { session_id });
                send_to_peer(&peer, &ended);
            }

            info!("Session cleaned up after disconnect: {session_id}");
        }
    }
}

async fn handle_socket(
    socket: WebSocket,
    sessions: Arc<Mutex<HashMap<Uuid, Session>>>,
    pairings: Arc<Mutex<PairingManager>>,
    connections: Arc<Mutex<HashMap<Uuid, Peer>>>,
) {
    let connection_id = Uuid::new_v4();

    let (mut socket_sender, mut socket_receiver) = socket.split();

    let (outgoing, mut outgoing_receiver) = mpsc::channel::<Message>(OUTGOING_QUEUE_CAPACITY);

    let (disconnect, mut disconnect_receiver) = watch::channel(false);

    let peer = Peer {
        connection_id,
        outgoing: outgoing.clone(),
        disconnect: disconnect.clone(),
    };

    connections.lock().await.insert(connection_id, peer);

    let writer = tokio::spawn(async move {
        while let Some(message) = outgoing_receiver.recv().await {
            if socket_sender.send(message).await.is_err() {
                break;
            }
        }
    });

    let mut role: Option<DeviceRole> = None;
    let mut device_id: Option<Uuid> = None;
    let mut authenticated_host_id: Option<Uuid> = None;

    info!("WebSocket client connected: {connection_id}");

    loop {
        tokio::select! {
            biased;

            disconnect_result = disconnect_receiver.changed() => {
                if disconnect_result.is_err() || *disconnect_receiver.borrow() {
                    warn!("Disconnecting slow or unavailable client: {connection_id}");
                    break;
                }
            }

            result = socket_receiver.next() => {
                let message = match result {
                    Some(Ok(message)) => message,
                    Some(Err(error)) => {
                        warn!("WebSocket receive error: {error}");
                        break;
                    }
                    None => break,
                };

                match message {
                    Message::Text(text) => {
                        let envelope: SignalEnvelope =
                            match serde_json::from_str(text.as_str()) {
                                Ok(envelope) => envelope,
                                Err(error) => {
                                    warn!("Invalid JSON protocol message: {error}");

                                    if !send_error(
                                        &outgoing,
                                        "invalid_json",
                                        "A valid REMOTIX JSON envelope is required",
                                    ) {
                                        let _ = disconnect.send(true);
                                        break;
                                    }

                                    continue;
                                }
                            };

                        if let Err(error) = envelope.validate() {
                            let (code, description) = match error {
                                ProtocolError::UnsupportedVersion(_) => (
                                    "unsupported_version",
                                    "Unsupported REMOTIX protocol version",
                                ),
                                ProtocolError::EmptyField(_) => (
                                    "empty_field",
                                    "A required message field is empty",
                                ),
                                ProtocolError::FieldTooLong(_) => (
                                    "field_too_long",
                                    "A message field exceeds the permitted length",
                                ),
                                ProtocolError::InvalidLength(_) => (
                                    "invalid_length",
                                    "A message field has an invalid length",
                                ),
                            };

                            if !send_error(&outgoing, code, description) {
                                let _ = disconnect.send(true);
                                break;
                            }

                            continue;
                        }

                        // Pairing requests are permitted before registration.
                        // This allows a new controller to prove ownership of
                        // its key before it is registered as a controller.
                        let pairing_message = matches!(
                            &envelope.message,
                            SignalMessage::RequestPairing { .. }
                                | SignalMessage::ProvePairing { .. }
                        );

                        let authentication_message = matches!(
                            &envelope.message,
                            SignalMessage::BeginAuthentication { .. }
                                | SignalMessage::Authenticate { .. }
                        );

                        if role.is_none()
                            && !pairing_message
                            && !authentication_message
                            && !matches!(
                                &envelope.message,
                                SignalMessage::Register { .. }
                            )
                        {
                            if !send_error(
                                &outgoing,
                                "not_registered",
                                "Register this device before sending session messages",
                            ) {
                                let _ = disconnect.send(true);
                                break;
                            }

                            continue;
                        }

                        if let Err((code, description)) = route_message(
                            envelope,
                            connection_id,
                            &mut role,
                            &mut device_id,
                            &mut authenticated_host_id,
                            &outgoing,
                            &disconnect,
                            &sessions,
                            &pairings,
                            &connections,
                        )
                        .await
                        {
                            if !send_error(&outgoing, code, description) {
                                let _ = disconnect.send(true);
                                break;
                            }
                        }
                    }

                    Message::Ping(payload) => {
                        if outgoing.try_send(Message::Pong(payload)).is_err() {
                            warn!(
                                "Outgoing queue full while responding to ping: {connection_id}"
                            );
                            let _ = disconnect.send(true);
                            break;
                        }
                    }

                    Message::Pong(_) => {}

                    Message::Close(_) => {
                        info!("WebSocket client requested disconnect");
                        break;
                    }

                    Message::Binary(_) => {
                        if !send_error(
                            &outgoing,
                            "unsupported_frame",
                            "Binary frames are not supported yet",
                        ) {
                            let _ = disconnect.send(true);
                            break;
                        }
                    }
                }
            }
        }
    }

    cleanup_connection(connection_id, &sessions).await;

    // Remove the disconnected connection from the live peer registry.
    connections.lock().await.remove(&connection_id);

    drop(outgoing);
    let _ = writer.await;

    info!("WebSocket client disconnected: {connection_id}");
}

pub fn build_app(token: String) -> Router {
    let state = AppState {
        expected_token: token,
        sessions: Arc::new(Mutex::new(HashMap::new())),
        pairings: Arc::new(Mutex::new(PairingManager::new())),
        connections: Arc::new(Mutex::new(HashMap::new())),
    };

    Router::new()
        .route("/health", get(health))
        .route("/ws", get(websocket_handler))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn full_peer_queue_triggers_disconnect() {
        let (outgoing, mut _receiver) = mpsc::channel::<Message>(OUTGOING_QUEUE_CAPACITY);

        let (disconnect, mut disconnect_receiver) = watch::channel(false);

        for _ in 0..OUTGOING_QUEUE_CAPACITY {
            outgoing
                .try_send(Message::Text("queued".into()))
                .expect("Queue should accept messages until full");
        }

        let peer = Peer {
            connection_id: Uuid::new_v4(),
            outgoing,
            disconnect,
        };

        let envelope = SignalEnvelope::new(SignalMessage::Error {
            code: "test".to_string(),
            message: "queue saturation test".to_string(),
        });

        assert!(!send_to_peer(&peer, &envelope));
        assert!(*disconnect_receiver.borrow_and_update());
    }

    #[tokio::test]
    async fn healthy_peer_queue_delivers_message() {
        let (outgoing, mut receiver) = mpsc::channel::<Message>(OUTGOING_QUEUE_CAPACITY);

        let (disconnect, mut disconnect_receiver) = watch::channel(false);

        let peer = Peer {
            connection_id: Uuid::new_v4(),
            outgoing,
            disconnect,
        };

        let envelope = SignalEnvelope::new(SignalMessage::Error {
            code: "test".to_string(),
            message: "healthy queue test".to_string(),
        });

        assert!(send_to_peer(&peer, &envelope));
        assert!(!*disconnect_receiver.borrow_and_update());

        let message = receiver.try_recv().unwrap();

        match message {
            Message::Text(text) => {
                let received: SignalEnvelope = serde_json::from_str(text.as_str()).unwrap();

                assert!(matches!(
                    received.message,
                    SignalMessage::Error { ref code, .. } if code == "test"
                ));
            }
            other => panic!("Expected text message, received: {other:?}"),
        }
    }
}
