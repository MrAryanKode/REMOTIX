mod host_identity;
mod trust_store;

use host_identity::HostIdentity;
use std::{env, error::Error, fs, path::PathBuf};
use trust_store::TrustStore;

fn main() -> Result<(), Box<dyn Error>> {
    let data_dir = env::var_os("REMOTIX_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".remotix"));

    fs::create_dir_all(&data_dir)?;

    let database_path = data_dir.join("host-trust.db");
    let identity_path = data_dir.join("host-identity.key");

    let store = TrustStore::open(&database_path)?;
    let host_id = store.load_or_create_host_id()?;

    let identity = HostIdentity::load_or_create(&identity_path)?;
    store.bind_host_identity(host_id, identity.public_key())?;
    let trusted_devices = store.list_trusted_devices(host_id)?;

    println!("REMOTIX Host Agent v0.1.0");
    println!("Platform: {}", env::consts::OS);
    println!("Status: Persistent host identity ready");
    println!("Host device ID: {host_id}");
    println!("Public-key fingerprint: {}", identity.fingerprint());
    println!("Trusted controllers: {}", trusted_devices.len());
    println!("Identity key: {}", identity.key_path().display());
    println!("Trust database: {}", database_path.display());
    println!();
    println!("Note: Host identity is not yet authenticated with the signalling server.");
    println!(
        "Note: OS-level secret protection beyond Linux file permissions is not yet implemented."
    );

    Ok(())
}
