
use axum::{routing::get, Router};
use tokio::net::TcpListener;

async fn health() -> &'static str {
    "REMOTIX signalling online"
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let app = Router::new()
        .route("/health", get(health));

    let listener = TcpListener::bind("127.0.0.1:8787")
        .await
        .expect("Could not bind server");

    println!("REMOTIX signalling server starting...");

    axum::serve(listener, app)
        .await
        .expect("Server error");
}
