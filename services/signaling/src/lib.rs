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
use remotix_protocol::{DeviceRole, ProtocolError, SignalEnvelope, SignalMessage};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{Mutex, mpsc, watch};
use tracing::{info, warn};
use uuid::Uuid;

// WebSocket resource limits.
const OUTGOING_QUEUE_CAPACITY: usize = 32;
const MAX_WS_MESSAGE_SIZE: usize = 64 * 1024;
const MAX_WS_FRAME_SIZE: usize = 64 * 1024;

#[derive(Clone)]
struct AppState {
    expected_token: String,
    sessions: Arc<Mutex<HashMap<Uuid, Session>>>,
}

#[derive(Clone)]
struct Peer {
    connection_id: Uuid,
    outgoing: mpsc::Sender<Message>,
    disconnect: watch::Sender<bool>,
}

struct Session {
    host: Option<Peer>,
    controller: Option<Peer>,
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
        .on_upgrade(move |socket| handle_socket(socket, state.sessions.clone())))
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

async fn route_message(
    envelope: SignalEnvelope,
    connection_id: Uuid,
    role: &mut Option<DeviceRole>,
    device_id: &mut Option<Uuid>,
    outgoing: &mpsc::Sender<Message>,
    disconnect: &watch::Sender<bool>,
    sessions: &Arc<Mutex<HashMap<Uuid, Session>>>,
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

        SignalMessage::CreateSession { session_id } => {
            if role.as_ref() != Some(&DeviceRole::Host) {
                return Err(("forbidden", "Only registered hosts can create sessions"));
            }

            let mut sessions = sessions.lock().await;

            if sessions.contains_key(session_id) {
                return Err(("session_exists", "Session ID is already in use"));
            }

            sessions.insert(
                *session_id,
                Session {
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

        SignalMessage::JoinSession { session_id } => {
            if role.as_ref() != Some(&DeviceRole::Controller) {
                return Err(("forbidden", "Only registered controllers can join sessions"));
            }

            {
                let mut sessions = sessions.lock().await;

                let session = sessions
                    .get_mut(session_id)
                    .ok_or(("session_not_found", "Requested session does not exist"))?;

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

async fn handle_socket(socket: WebSocket, sessions: Arc<Mutex<HashMap<Uuid, Session>>>) {
    let connection_id = Uuid::new_v4();

    let (mut socket_sender, mut socket_receiver) = socket.split();

    let (outgoing, mut outgoing_receiver) = mpsc::channel::<Message>(OUTGOING_QUEUE_CAPACITY);

    let (disconnect, mut disconnect_receiver) = watch::channel(false);

    let writer = tokio::spawn(async move {
        while let Some(message) = outgoing_receiver.recv().await {
            if socket_sender.send(message).await.is_err() {
                break;
            }
        }
    });

    let mut role: Option<DeviceRole> = None;
    let mut device_id: Option<Uuid> = None;

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
                            };

                            if !send_error(&outgoing, code, description) {
                                let _ = disconnect.send(true);
                                break;
                            }

                            continue;
                        }

                        if role.is_none()
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
                            &outgoing,
                            &disconnect,
                            &sessions,
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

    drop(outgoing);

    let _ = writer.await;

    info!("WebSocket client disconnected: {connection_id}");
}

pub fn build_app(token: String) -> Router {
    let state = AppState {
        expected_token: token,
        sessions: Arc::new(Mutex::new(HashMap::new())),
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

        // Fill the outgoing queue completely.
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

        // A full queue must reject delivery and request disconnection.
        assert!(!send_to_peer(&peer, &envelope));

        assert!(
            *disconnect_receiver.borrow_and_update(),
            "Slow client should receive a disconnect notification"
        );
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

        assert!(
            send_to_peer(&peer, &envelope),
            "Healthy queue should accept the message"
        );

        assert!(
            !*disconnect_receiver.borrow_and_update(),
            "Healthy client must not be disconnected"
        );

        let message = receiver
            .try_recv()
            .expect("Expected a message in the outgoing queue");

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
