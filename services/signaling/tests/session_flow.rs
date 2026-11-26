use futures_util::{SinkExt, StreamExt};
use remotix_device_identity::DeviceIdentity;
use remotix_protocol::{DeviceRole, PairingStatus, SignalEnvelope, SignalMessage};
use remotix_signaling::build_app;
use tokio::{
    net::{TcpListener, TcpStream},
    time::{Duration, timeout},
};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{Message, client::IntoClientRequest, http::header::AUTHORIZATION},
};

const TEST_TOKEN: &str = "remotix-integration-test-token-0123456789";
const MAX_WS_MESSAGE_SIZE: usize = 64 * 1024;

type Client = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>;

async fn start_test_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Could not bind test server");

    let address = listener.local_addr().unwrap();
    let app = build_app(TEST_TOKEN.to_string());

    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("Test server failed");
    });

    format!("ws://{address}/ws")
}

async fn connect_client(url: &str, token: &str) -> Client {
    let mut request = url
        .into_client_request()
        .expect("Could not create WebSocket request");

    request
        .headers_mut()
        .insert(AUTHORIZATION, format!("Bearer {token}").parse().unwrap());

    let (socket, _) = connect_async(request)
        .await
        .expect("WebSocket connection failed");

    socket
}

async fn send_envelope(socket: &mut Client, envelope: SignalEnvelope) {
    let json = serde_json::to_string(&envelope).expect("Could not serialize signalling envelope");

    socket
        .send(Message::Text(json.into()))
        .await
        .expect("Could not send WebSocket message");
}

async fn receive_envelope(socket: &mut Client) -> SignalEnvelope {
    let frame = timeout(Duration::from_secs(3), socket.next())
        .await
        .expect("Timed out waiting for WebSocket message")
        .expect("WebSocket stream ended")
        .expect("WebSocket receive failed");

    match frame {
        Message::Text(text) => {
            serde_json::from_str(text.as_str()).expect("Server returned invalid signalling JSON")
        }
        other => panic!("Expected a text frame, received: {other:?}"),
    }
}

async fn register_client(socket: &mut Client, role: DeviceRole) -> uuid::Uuid {
    let device_id = uuid::Uuid::new_v4();

    send_envelope(
        socket,
        SignalEnvelope::new(SignalMessage::Register { role, device_id }),
    )
    .await;

    let response = receive_envelope(socket).await;

    assert!(matches!(
        response.message,
        SignalMessage::Register { device_id: id, .. } if id == device_id
    ));

    device_id
}

async fn create_session(socket: &mut Client, session_id: uuid::Uuid) {
    send_envelope(
        socket,
        SignalEnvelope::new(SignalMessage::CreateSession { session_id }),
    )
    .await;

    let response = receive_envelope(socket).await;

    assert!(matches!(
        response.message,
        SignalMessage::CreateSession { session_id: id } if id == session_id
    ));
}

async fn pair_and_authenticate(
    host: &mut Client,
    controller: &mut Client,
    host_device_id: uuid::Uuid,
    controller_device_id: uuid::Uuid,
    identity: &DeviceIdentity,
) {
    // Host creates a temporary pairing invitation.
    send_envelope(
        host,
        SignalEnvelope::new(SignalMessage::CreatePairing { host_device_id }),
    )
    .await;

    let (pairing_id, pairing_code) = match receive_envelope(host).await.message {
        SignalMessage::PairingCreated {
            pairing_id,
            pairing_code,
            ..
        } => (pairing_id, pairing_code),
        other => panic!("Expected PairingCreated, received: {other:?}"),
    };

    // Controller requests pairing using its public key.
    send_envelope(
        controller,
        SignalEnvelope::new(SignalMessage::RequestPairing {
            pairing_id,
            pairing_code,
            controller_device_id,
            controller_public_key: identity.public_key(),
        }),
    )
    .await;

    let (pairing_challenge_id, pairing_nonce) = match receive_envelope(controller).await.message {
        SignalMessage::PairingChallenge {
            pairing_id: received_pairing_id,
            challenge_id,
            nonce,
            ..
        } => {
            assert_eq!(received_pairing_id, pairing_id);
            (challenge_id, nonce)
        }
        other => panic!("Expected PairingChallenge, received: {other:?}"),
    };

    // Prove possession of the controller's private key.
    let pairing_signature = identity
        .sign_authentication(
            controller_device_id.as_bytes(),
            pairing_challenge_id.as_bytes(),
            &pairing_nonce,
        )
        .expect("Could not sign pairing challenge");

    send_envelope(
        controller,
        SignalEnvelope::new(SignalMessage::ProvePairing {
            pairing_id,
            controller_device_id,
            challenge_id: pairing_challenge_id,
            signature: pairing_signature.to_vec(),
        }),
    )
    .await;

    // Host receives the verified request.
    match receive_envelope(host).await.message {
        SignalMessage::PairingRequested {
            pairing_id: received_pairing_id,
            controller_device_id: received_controller_id,
            ..
        } => {
            assert_eq!(received_pairing_id, pairing_id);
            assert_eq!(received_controller_id, controller_device_id);
        }
        other => panic!("Expected PairingRequested, received: {other:?}"),
    }

    match receive_envelope(controller).await.message {
        SignalMessage::PairingResult {
            pairing_id: received_pairing_id,
            status: PairingStatus::Pending,
        } => assert_eq!(received_pairing_id, pairing_id),
        other => panic!("Expected pending PairingResult, received: {other:?}"),
    }

    // Host explicitly approves the controller.
    send_envelope(
        host,
        SignalEnvelope::new(SignalMessage::ApprovePairing {
            pairing_id,
            controller_device_id,
        }),
    )
    .await;

    match receive_envelope(host).await.message {
        SignalMessage::PairingResult {
            pairing_id: received_pairing_id,
            status: PairingStatus::Approved,
        } => assert_eq!(received_pairing_id, pairing_id),
        other => panic!("Expected host approval result, received: {other:?}"),
    }

    match receive_envelope(controller).await.message {
        SignalMessage::PairingResult {
            pairing_id: received_pairing_id,
            status: PairingStatus::Approved,
        } => assert_eq!(received_pairing_id, pairing_id),
        other => panic!("Expected controller approval result, received: {other:?}"),
    }

    // Controller starts a fresh host-bound authentication exchange.
    send_envelope(
        controller,
        SignalEnvelope::new(SignalMessage::BeginAuthentication {
            host_device_id,
            controller_device_id,
        }),
    )
    .await;

    let (challenge_id, nonce) = match receive_envelope(controller).await.message {
        SignalMessage::AuthenticationChallenge {
            host_device_id: received_host_id,
            controller_device_id: received_controller_id,
            challenge_id,
            nonce,
            ..
        } => {
            assert_eq!(received_host_id, host_device_id);
            assert_eq!(received_controller_id, controller_device_id);
            (challenge_id, nonce)
        }
        other => panic!("Expected AuthenticationChallenge, received: {other:?}"),
    };

    let signature = identity
        .sign_host_authentication(
            host_device_id.as_bytes(),
            controller_device_id.as_bytes(),
            challenge_id.as_bytes(),
            &nonce,
        )
        .expect("Could not sign host-bound authentication challenge");

    send_envelope(
        controller,
        SignalEnvelope::new(SignalMessage::Authenticate {
            host_device_id,
            controller_device_id,
            challenge_id,
            signature: signature.to_vec(),
        }),
    )
    .await;

    match receive_envelope(controller).await.message {
        SignalMessage::Authenticated {
            host_device_id: received_host_id,
            controller_device_id: received_controller_id,
            role: DeviceRole::Controller,
        } => {
            assert_eq!(received_host_id, host_device_id);
            assert_eq!(received_controller_id, controller_device_id);
        }
        other => panic!("Expected Authenticated confirmation, received: {other:?}"),
    }
}

async fn join_session(host: &mut Client, controller: &mut Client, session_id: uuid::Uuid) {
    send_envelope(
        controller,
        SignalEnvelope::new(SignalMessage::JoinSession { session_id }),
    )
    .await;

    let host_response = receive_envelope(host).await;

    assert!(matches!(
        host_response.message,
        SignalMessage::JoinSession { session_id: id } if id == session_id
    ));

    let controller_response = receive_envelope(controller).await;

    assert!(matches!(
        controller_response.message,
        SignalMessage::JoinSession { session_id: id } if id == session_id
    ));
}

async fn expect_error(socket: &mut Client, expected_code: &str) {
    let response = receive_envelope(socket).await;

    match response.message {
        SignalMessage::Error { code, .. } => assert_eq!(code, expected_code),
        other => panic!("Expected error '{expected_code}', received: {other:?}"),
    }
}

#[tokio::test]
async fn test_authenticated_websocket_connection() {
    let url = start_test_server().await;
    let socket = connect_client(&url, TEST_TOKEN).await;

    assert!(socket.get_ref().get_ref().peer_addr().is_ok());
    drop(socket);
}

#[tokio::test]
async fn test_rejects_invalid_authentication_token() {
    let url = start_test_server().await;

    let mut request = url
        .into_client_request()
        .expect("Could not create WebSocket request");

    request
        .headers_mut()
        .insert(AUTHORIZATION, "Bearer invalid-token".parse().unwrap());

    let result = connect_async(request).await;

    assert!(
        result.is_err(),
        "Server should reject an invalid authentication token"
    );
}

#[tokio::test]
async fn test_complete_host_controller_session_flow() {
    let url = start_test_server().await;

    let mut host = connect_client(&url, TEST_TOKEN).await;
    let mut controller = connect_client(&url, TEST_TOKEN).await;

    let session_id = uuid::Uuid::new_v4();
    let host_id = register_client(&mut host, DeviceRole::Host).await;
    let controller_id = register_client(&mut controller, DeviceRole::Controller).await;
    let identity = DeviceIdentity::generate();

    pair_and_authenticate(
        &mut host,
        &mut controller,
        host_id,
        controller_id,
        &identity,
    )
    .await;

    create_session(&mut host, session_id).await;
    join_session(&mut host, &mut controller, session_id).await;

    send_envelope(
        &mut host,
        SignalEnvelope::new(SignalMessage::Offer {
            session_id,
            sdp: "test-webrtc-offer".to_string(),
        }),
    )
    .await;

    let response = receive_envelope(&mut controller).await;
    assert!(matches!(
        response.message,
        SignalMessage::Offer { session_id: id, ref sdp }
            if id == session_id && sdp == "test-webrtc-offer"
    ));

    send_envelope(
        &mut controller,
        SignalEnvelope::new(SignalMessage::Answer {
            session_id,
            sdp: "test-webrtc-answer".to_string(),
        }),
    )
    .await;

    let response = receive_envelope(&mut host).await;
    assert!(matches!(
        response.message,
        SignalMessage::Answer { session_id: id, ref sdp }
            if id == session_id && sdp == "test-webrtc-answer"
    ));

    send_envelope(
        &mut host,
        SignalEnvelope::new(SignalMessage::IceCandidate {
            session_id,
            candidate: "host-ice-candidate".to_string(),
        }),
    )
    .await;

    let response = receive_envelope(&mut controller).await;
    assert!(matches!(
        response.message,
        SignalMessage::IceCandidate { session_id: id, ref candidate }
            if id == session_id && candidate == "host-ice-candidate"
    ));

    send_envelope(
        &mut controller,
        SignalEnvelope::new(SignalMessage::IceCandidate {
            session_id,
            candidate: "controller-ice-candidate".to_string(),
        }),
    )
    .await;

    let response = receive_envelope(&mut host).await;
    assert!(matches!(
        response.message,
        SignalMessage::IceCandidate { session_id: id, ref candidate }
            if id == session_id && candidate == "controller-ice-candidate"
    ));

    send_envelope(
        &mut host,
        SignalEnvelope::new(SignalMessage::EndSession { session_id }),
    )
    .await;

    let controller_response = receive_envelope(&mut controller).await;
    let host_response = receive_envelope(&mut host).await;

    assert!(matches!(
        controller_response.message,
        SignalMessage::EndSession { session_id: id } if id == session_id
    ));
    assert!(matches!(
        host_response.message,
        SignalMessage::EndSession { session_id: id } if id == session_id
    ));
}

#[tokio::test]
async fn test_second_controller_cannot_join_occupied_session() {
    let url = start_test_server().await;

    let mut host = connect_client(&url, TEST_TOKEN).await;
    let mut first_controller = connect_client(&url, TEST_TOKEN).await;
    let mut second_controller = connect_client(&url, TEST_TOKEN).await;

    let session_id = uuid::Uuid::new_v4();
    let host_id = register_client(&mut host, DeviceRole::Host).await;
    let first_id = register_client(&mut first_controller, DeviceRole::Controller).await;
    let second_id = register_client(&mut second_controller, DeviceRole::Controller).await;

    let first_identity = DeviceIdentity::generate();
    let second_identity = DeviceIdentity::generate();

    pair_and_authenticate(
        &mut host,
        &mut first_controller,
        host_id,
        first_id,
        &first_identity,
    )
    .await;

    pair_and_authenticate(
        &mut host,
        &mut second_controller,
        host_id,
        second_id,
        &second_identity,
    )
    .await;

    create_session(&mut host, session_id).await;
    join_session(&mut host, &mut first_controller, session_id).await;

    send_envelope(
        &mut second_controller,
        SignalEnvelope::new(SignalMessage::JoinSession { session_id }),
    )
    .await;

    expect_error(&mut second_controller, "session_full").await;
}

#[tokio::test]
async fn test_controller_cannot_create_session() {
    let url = start_test_server().await;
    let mut controller = connect_client(&url, TEST_TOKEN).await;

    register_client(&mut controller, DeviceRole::Controller).await;

    send_envelope(
        &mut controller,
        SignalEnvelope::new(SignalMessage::CreateSession {
            session_id: uuid::Uuid::new_v4(),
        }),
    )
    .await;

    expect_error(&mut controller, "forbidden").await;
}

#[tokio::test]
async fn test_host_cannot_join_session_as_controller() {
    let url = start_test_server().await;
    let mut host = connect_client(&url, TEST_TOKEN).await;

    register_client(&mut host, DeviceRole::Host).await;

    send_envelope(
        &mut host,
        SignalEnvelope::new(SignalMessage::JoinSession {
            session_id: uuid::Uuid::new_v4(),
        }),
    )
    .await;

    expect_error(&mut host, "forbidden").await;
}

#[tokio::test]
async fn test_unrelated_host_cannot_send_offer_or_end_session() {
    let url = start_test_server().await;

    let mut host = connect_client(&url, TEST_TOKEN).await;
    let mut controller = connect_client(&url, TEST_TOKEN).await;
    let mut unrelated_host = connect_client(&url, TEST_TOKEN).await;

    let session_id = uuid::Uuid::new_v4();

    let host_id = register_client(&mut host, DeviceRole::Host).await;
    let controller_id = register_client(&mut controller, DeviceRole::Controller).await;
    register_client(&mut unrelated_host, DeviceRole::Host).await;

    let identity = DeviceIdentity::generate();
    pair_and_authenticate(
        &mut host,
        &mut controller,
        host_id,
        controller_id,
        &identity,
    )
    .await;

    create_session(&mut host, session_id).await;
    join_session(&mut host, &mut controller, session_id).await;

    send_envelope(
        &mut unrelated_host,
        SignalEnvelope::new(SignalMessage::Offer {
            session_id,
            sdp: "unauthorized-offer".to_string(),
        }),
    )
    .await;

    expect_error(&mut unrelated_host, "forbidden").await;

    send_envelope(
        &mut unrelated_host,
        SignalEnvelope::new(SignalMessage::EndSession { session_id }),
    )
    .await;

    expect_error(&mut unrelated_host, "forbidden").await;

    send_envelope(
        &mut host,
        SignalEnvelope::new(SignalMessage::Offer {
            session_id,
            sdp: "legitimate-offer".to_string(),
        }),
    )
    .await;

    let response = receive_envelope(&mut controller).await;
    assert!(matches!(
        response.message,
        SignalMessage::Offer { session_id: id, ref sdp }
            if id == session_id && sdp == "legitimate-offer"
    ));
}

#[tokio::test]
async fn test_controller_disconnect_notifies_host_and_cleans_session() {
    let url = start_test_server().await;

    let mut host = connect_client(&url, TEST_TOKEN).await;
    let mut controller = connect_client(&url, TEST_TOKEN).await;

    let session_id = uuid::Uuid::new_v4();
    let host_id = register_client(&mut host, DeviceRole::Host).await;
    let controller_id = register_client(&mut controller, DeviceRole::Controller).await;
    let identity = DeviceIdentity::generate();

    pair_and_authenticate(
        &mut host,
        &mut controller,
        host_id,
        controller_id,
        &identity,
    )
    .await;

    create_session(&mut host, session_id).await;
    join_session(&mut host, &mut controller, session_id).await;

    drop(controller);

    let response = receive_envelope(&mut host).await;
    assert!(matches!(
        response.message,
        SignalMessage::EndSession { session_id: id } if id == session_id
    ));

    let mut another_controller = connect_client(&url, TEST_TOKEN).await;
    register_client(&mut another_controller, DeviceRole::Controller).await;

    send_envelope(
        &mut another_controller,
        SignalEnvelope::new(SignalMessage::JoinSession { session_id }),
    )
    .await;

    expect_error(&mut another_controller, "session_not_found").await;
}

#[tokio::test]
async fn test_host_disconnect_notifies_controller_and_cleans_session() {
    let url = start_test_server().await;

    let mut host = connect_client(&url, TEST_TOKEN).await;
    let mut controller = connect_client(&url, TEST_TOKEN).await;

    let session_id = uuid::Uuid::new_v4();
    let host_id = register_client(&mut host, DeviceRole::Host).await;
    let controller_id = register_client(&mut controller, DeviceRole::Controller).await;
    let identity = DeviceIdentity::generate();

    pair_and_authenticate(
        &mut host,
        &mut controller,
        host_id,
        controller_id,
        &identity,
    )
    .await;

    create_session(&mut host, session_id).await;
    join_session(&mut host, &mut controller, session_id).await;

    drop(host);

    let response = receive_envelope(&mut controller).await;
    assert!(matches!(
        response.message,
        SignalMessage::EndSession { session_id: id } if id == session_id
    ));
}

#[tokio::test]
async fn test_unauthenticated_controller_cannot_join_session() {
    let url = start_test_server().await;

    let mut host = connect_client(&url, TEST_TOKEN).await;
    let mut controller = connect_client(&url, TEST_TOKEN).await;

    register_client(&mut host, DeviceRole::Host).await;
    register_client(&mut controller, DeviceRole::Controller).await;

    let session_id = uuid::Uuid::new_v4();
    create_session(&mut host, session_id).await;

    send_envelope(
        &mut controller,
        SignalEnvelope::new(SignalMessage::JoinSession { session_id }),
    )
    .await;

    expect_error(&mut controller, "host_authentication_required").await;
}

#[tokio::test]
async fn test_oversized_websocket_message_is_rejected() {
    let url = start_test_server().await;
    let mut socket = connect_client(&url, TEST_TOKEN).await;

    let oversized_payload = "x".repeat(MAX_WS_MESSAGE_SIZE + 1);

    socket
        .send(Message::Text(oversized_payload.into()))
        .await
        .expect("Client could not send oversized test frame");

    let result = timeout(Duration::from_secs(5), socket.next())
        .await
        .expect("Timed out waiting for oversized-message rejection");

    match result {
        Some(Ok(Message::Close(_))) | Some(Err(_)) | None => {}
        other => panic!("Expected the server to reject the oversized message, received: {other:?}"),
    }
}

#[tokio::test]
async fn test_normal_sized_message_is_accepted() {
    let url = start_test_server().await;
    let mut socket = connect_client(&url, TEST_TOKEN).await;

    register_client(&mut socket, DeviceRole::Host).await;

    let session_id = uuid::Uuid::new_v4();
    create_session(&mut socket, session_id).await;
}
