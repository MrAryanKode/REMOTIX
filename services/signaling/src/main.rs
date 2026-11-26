use rand::{RngCore, rngs::OsRng};
use remotix_signaling::{build_app, host_registry::HostRegistry};
use std::{
    env,
    error::Error,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::net::TcpListener;
use tracing::info;

const DEFAULT_TOKEN_TTL_SECONDS: u64 = 600;
const MAX_TOKEN_TTL_SECONDS: u64 = 86_400;

fn current_unix_time() -> Result<u64, Box<dyn Error>> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn generate_enrollment_token() -> String {
    let mut bytes = [0u8; 32];
    let mut rng = OsRng;
    rng.fill_bytes(&mut bytes);

    let mut output = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write;
        write!(&mut output, "{byte:02x}").expect("Writing to String cannot fail");
    }

    output
}

fn registry_path() -> PathBuf {
    env::var_os("REMOTIX_HOST_REGISTRY_DB")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("remotix-host-registry.db"))
}

fn provision_host_token(ttl_argument: Option<String>) -> Result<(), Box<dyn Error>> {
    let ttl = match ttl_argument {
        Some(value) => value.parse::<u64>()?,
        None => DEFAULT_TOKEN_TTL_SECONDS,
    };

    if !(60..=MAX_TOKEN_TTL_SECONDS).contains(&ttl) {
        return Err("Token lifetime must be between 60 and 86400 seconds".into());
    }

    let created_at = current_unix_time()?;
    let expires_at = created_at
        .checked_add(ttl)
        .ok_or("Token expiration timestamp overflow")?;

    let token = generate_enrollment_token();
    let path = registry_path();

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }

    let mut registry = HostRegistry::open(&path)?;
    registry.provision_token_with_expiry(&token, created_at, expires_at)?;

    println!("REMOTIX host enrollment token created.");
    println!("Registry: {}", path.display());
    println!("Lifetime: {ttl} seconds");
    println!("Expires at Unix timestamp: {expires_at}");
    println!();
    println!("ONE-TIME TOKEN (copy it now; it will not be shown again):");
    println!("{token}");
    println!();
    println!("Treat this token as a secret. Do not commit it or share it publicly.");

    Ok(())
}

async fn run() -> Result<(), Box<dyn Error>> {
    let mut arguments = env::args().skip(1);

    if let Some(command) = arguments.next() {
        if command == "provision-host-token" {
            let ttl = arguments.next();

            if arguments.next().is_some() {
                return Err("Usage: remotix-signaling provision-host-token [ttl_seconds]".into());
            }

            return provision_host_token(ttl);
        }

        return Err(
            format!("Unknown command: {command}\nUsage: remotix-signaling provision-host-token [ttl_seconds]").into()
        );
    }

    tracing_subscriber::fmt::init();

    let token = env::var("REMOTIX_DEV_TOKEN").map_err(|_| "REMOTIX_DEV_TOKEN must be set")?;

    if token.len() < 32 {
        return Err("REMOTIX_DEV_TOKEN must contain at least 32 characters".into());
    }

    let bind_address =
        env::var("REMOTIX_BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8787".to_string());

    let app = build_app(token);

    let listener = TcpListener::bind(&bind_address).await?;
    info!("REMOTIX signalling server listening on {}", bind_address);

    axum::serve(listener, app).await?;
    Ok(())
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("REMOTIX signalling error: {error}");
        std::process::exit(1);
    }
}
