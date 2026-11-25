use remotix_signaling::build_app;
use tokio::net::TcpListener;
use tracing::info;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let token = std::env::var("REMOTIX_DEV_TOKEN").expect("REMOTIX_DEV_TOKEN must be set");

    if token.len() < 32 {
        panic!("REMOTIX_DEV_TOKEN must contain at least 32 characters");
    }

    let bind_address =
        std::env::var("REMOTIX_BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8787".to_string());

    let app = build_app(token);

    let listener = TcpListener::bind(&bind_address)
        .await
        .expect("Failed to bind signalling server");

    info!("REMOTIX signalling server listening on {}", bind_address);

    axum::serve(listener, app)
        .await
        .expect("Signalling server failed");
}
