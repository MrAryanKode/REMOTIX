use remotix_device_identity::DeviceIdentity;
use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use zeroize::Zeroize;

pub struct HostIdentity {
    identity: DeviceIdentity,
    path: PathBuf,
}

impl HostIdentity {
    pub fn load_or_create(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let identity = match Self::read_existing(&path) {
            Ok(identity) => identity,
            Err(error) if error.kind() == io::ErrorKind::NotFound => Self::create_new(&path)?,
            Err(error) => return Err(error),
        };

        Ok(Self { identity, path })
    }

    fn read_existing(path: &Path) -> io::Result<DeviceIdentity> {
        let metadata = fs::symlink_metadata(path)?;

        if !metadata.file_type().is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Host identity path must be a regular file",
            ));
        }

        #[cfg(unix)]
        {
            let mut permissions = metadata.permissions();
            if permissions.mode() & 0o777 != 0o600 {
                permissions.set_mode(0o600);
                fs::set_permissions(path, permissions)?;
            }
        }

        let mut file = OpenOptions::new().read(true).open(path)?;
        let mut secret = [0u8; 32];

        let result = file.read_exact(&mut secret);

        if let Err(error) = result {
            secret.zeroize();
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Host identity key must contain exactly 32 bytes: {error}"),
            ));
        }

        let mut extra = [0u8; 1];

        if file.read(&mut extra)? != 0 {
            secret.zeroize();
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Host identity key contains unexpected extra data",
            ));
        }

        let identity = DeviceIdentity::from_secret_bytes(secret);
        secret.zeroize();

        Ok(identity)
    }

    fn create_new(path: &Path) -> io::Result<DeviceIdentity> {
        let identity = DeviceIdentity::generate();
        let mut secret = identity.secret_bytes();

        let mut options = OpenOptions::new();
        options.write(true).create_new(true);

        #[cfg(unix)]
        options.mode(0o600);

        let creation = options.open(path);

        let mut file = match creation {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                secret.zeroize();
                return Self::read_existing(path);
            }
            Err(error) => {
                secret.zeroize();
                return Err(error);
            }
        };

        let write_result = (|| {
            file.write_all(&secret)?;
            file.sync_all()?;
            Ok::<(), io::Error>(())
        })();

        secret.zeroize();

        if let Err(error) = write_result {
            drop(file);
            let _ = fs::remove_file(path);
            return Err(error);
        }

        Ok(identity)
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.identity.public_key()
    }

    pub fn fingerprint(&self) -> String {
        self.identity.fingerprint()
    }

    pub fn key_path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_survives_reopening() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("host-identity.key");

        let first = HostIdentity::load_or_create(&path).unwrap();
        let first_public_key = first.public_key();
        let first_fingerprint = first.fingerprint();

        drop(first);

        let second = HostIdentity::load_or_create(&path).unwrap();

        assert_eq!(second.public_key(), first_public_key);
        assert_eq!(second.fingerprint(), first_fingerprint);
    }

    #[test]
    fn creates_exactly_32_byte_key_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("host-identity.key");

        HostIdentity::load_or_create(&path).unwrap();

        let bytes = fs::read(&path).unwrap();
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn rejects_invalid_key_file_length() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("host-identity.key");

        fs::write(&path, b"short").unwrap();

        let result = HostIdentity::load_or_create(&path);

        assert_eq!(
            result.err().expect("Expected an error").kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn rejects_extra_key_file_data() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("host-identity.key");

        fs::write(&path, [vec![1u8; 32], vec![2u8; 1]].concat()).unwrap();

        let result = HostIdentity::load_or_create(&path);

        assert_eq!(
            result.err().expect("Expected an error").kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[cfg(unix)]
    #[test]
    fn key_file_has_restrictive_permissions() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("host-identity.key");

        HostIdentity::load_or_create(&path).unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn rejects_directory_instead_of_key_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("identity");

        fs::create_dir(&path).unwrap();

        let result = HostIdentity::load_or_create(&path);

        assert_eq!(
            result.err().expect("Expected an error").kind(),
            io::ErrorKind::InvalidData
        );
    }
}
