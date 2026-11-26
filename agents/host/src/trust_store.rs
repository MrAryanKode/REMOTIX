use rusqlite::{Connection, OptionalExtension, params};
use std::path::Path;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedDevice {
    pub controller_device_id: Uuid,
    pub public_key: [u8; 32],
    pub approved_at_unix: u64,
}

pub struct TrustStore {
    connection: Connection,
}

#[derive(Debug)]
pub enum IdentityBindingError {
    Database(rusqlite::Error),
    HostIdMissing,
    HostIdMismatch,
    PublicKeyMismatch,
}

impl std::fmt::Display for IdentityBindingError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Database(error) => write!(formatter, "Trust database error: {error}"),
            Self::HostIdMissing => write!(formatter, "Host ID is missing from trust database"),
            Self::HostIdMismatch => write!(formatter, "Host ID does not match the trust database"),
            Self::PublicKeyMismatch => write!(
                formatter,
                "Host identity public key does not match the key bound to this database"
            ),
        }
    }
}

impl std::error::Error for IdentityBindingError {}

impl From<rusqlite::Error> for IdentityBindingError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Database(error)
    }
}

impl TrustStore {
    pub fn open(path: impl AsRef<Path>) -> rusqlite::Result<Self> {
        let connection = Connection::open(path)?;

        connection.busy_timeout(std::time::Duration::from_secs(5))?;

        connection.execute_batch(
            "
            PRAGMA foreign_keys = ON;
            PRAGMA secure_delete = ON;

            CREATE TABLE IF NOT EXISTS host_metadata (
                key TEXT PRIMARY KEY NOT NULL,
                value BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS trusted_devices (
                host_device_id BLOB NOT NULL
                    CHECK(length(host_device_id) = 16),
                controller_device_id BLOB NOT NULL
                    CHECK(length(controller_device_id) = 16),
                controller_public_key BLOB NOT NULL
                    CHECK(length(controller_public_key) = 32),
                approved_at_unix INTEGER NOT NULL
                    CHECK(approved_at_unix >= 0),
                revoked_at_unix INTEGER,
                PRIMARY KEY(host_device_id, controller_device_id)
            );

            CREATE INDEX IF NOT EXISTS idx_trusted_devices_host
            ON trusted_devices(host_device_id, revoked_at_unix);
            ",
        )?;

        Ok(Self { connection })
    }

    pub fn load_or_create_host_id(&self) -> rusqlite::Result<Uuid> {
        let existing: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT value FROM host_metadata WHERE key = 'host_device_id'",
                [],
                |row| row.get(0),
            )
            .optional()?;

        if let Some(bytes) = existing {
            return Uuid::from_slice(&bytes).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Blob,
                    Box::new(error),
                )
            });
        }

        let host_id = Uuid::new_v4();

        self.connection.execute(
            "INSERT INTO host_metadata(key, value) VALUES('host_device_id', ?1)",
            params![host_id.as_bytes().as_slice()],
        )?;

        Ok(host_id)
    }

    /// Binds this database to the host's persistent Ed25519 public key.
    ///
    /// Existing databases without a public-key binding are migrated on first use.
    /// A different key or host ID is rejected instead of silently replacing identity.
    pub fn bind_host_identity(
        &self,
        host_id: Uuid,
        public_key: [u8; 32],
    ) -> Result<(), IdentityBindingError> {
        let stored_host_id: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT value FROM host_metadata WHERE key = 'host_device_id'",
                [],
                |row| row.get(0),
            )
            .optional()?;

        let stored_host_id = stored_host_id.ok_or(IdentityBindingError::HostIdMissing)?;

        if stored_host_id.as_slice() != host_id.as_bytes() {
            return Err(IdentityBindingError::HostIdMismatch);
        }

        // INSERT OR IGNORE makes the first successful binding authoritative.
        self.connection.execute(
            "INSERT OR IGNORE INTO host_metadata(key, value) VALUES('host_public_key', ?1)",
            params![public_key.as_slice()],
        )?;

        let stored_public_key: Vec<u8> = self.connection.query_row(
            "SELECT value FROM host_metadata WHERE key = 'host_public_key'",
            [],
            |row| row.get(0),
        )?;

        if stored_public_key.as_slice() != public_key.as_slice() {
            return Err(IdentityBindingError::PublicKeyMismatch);
        }

        Ok(())
    }

    pub fn approve_device(
        &self,
        host_id: Uuid,
        controller_id: Uuid,
        public_key: [u8; 32],
        approved_at_unix: u64,
    ) -> rusqlite::Result<()> {
        let timestamp =
            i64::try_from(approved_at_unix).map_err(|_| rusqlite::Error::InvalidQuery)?;

        self.connection.execute(
            "
            INSERT INTO trusted_devices (
                host_device_id,
                controller_device_id,
                controller_public_key,
                approved_at_unix,
                revoked_at_unix
            )
            VALUES (?1, ?2, ?3, ?4, NULL)
            ON CONFLICT(host_device_id, controller_device_id)
            DO UPDATE SET
                controller_public_key = excluded.controller_public_key,
                approved_at_unix = excluded.approved_at_unix,
                revoked_at_unix = NULL
            ",
            params![
                host_id.as_bytes().as_slice(),
                controller_id.as_bytes().as_slice(),
                public_key.as_slice(),
                timestamp
            ],
        )?;

        Ok(())
    }

    pub fn get_trusted_device(
        &self,
        host_id: Uuid,
        controller_id: Uuid,
    ) -> rusqlite::Result<Option<TrustedDevice>> {
        let row: Option<(Vec<u8>, Vec<u8>, i64)> = self
            .connection
            .query_row(
                "
                SELECT controller_device_id,
                       controller_public_key,
                       approved_at_unix
                FROM trusted_devices
                WHERE host_device_id = ?1
                  AND controller_device_id = ?2
                  AND revoked_at_unix IS NULL
                ",
                params![
                    host_id.as_bytes().as_slice(),
                    controller_id.as_bytes().as_slice()
                ],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;

        row.map(|(device_bytes, key_bytes, timestamp)| {
            let controller_device_id = Uuid::from_slice(&device_bytes).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Blob,
                    Box::new(error),
                )
            })?;

            let public_key: [u8; 32] = key_bytes
                .try_into()
                .map_err(|_| rusqlite::Error::InvalidQuery)?;

            let approved_at_unix =
                u64::try_from(timestamp).map_err(|_| rusqlite::Error::InvalidQuery)?;

            Ok(TrustedDevice {
                controller_device_id,
                public_key,
                approved_at_unix,
            })
        })
        .transpose()
    }

    pub fn revoke_device(
        &self,
        host_id: Uuid,
        controller_id: Uuid,
        revoked_at_unix: u64,
    ) -> rusqlite::Result<bool> {
        let timestamp =
            i64::try_from(revoked_at_unix).map_err(|_| rusqlite::Error::InvalidQuery)?;

        let changed = self.connection.execute(
            "
            UPDATE trusted_devices
            SET revoked_at_unix = ?3
            WHERE host_device_id = ?1
              AND controller_device_id = ?2
              AND revoked_at_unix IS NULL
            ",
            params![
                host_id.as_bytes().as_slice(),
                controller_id.as_bytes().as_slice(),
                timestamp
            ],
        )?;

        Ok(changed == 1)
    }

    pub fn list_trusted_devices(&self, host_id: Uuid) -> rusqlite::Result<Vec<TrustedDevice>> {
        let mut statement = self.connection.prepare(
            "
            SELECT controller_device_id,
                   controller_public_key,
                   approved_at_unix
            FROM trusted_devices
            WHERE host_device_id = ?1
              AND revoked_at_unix IS NULL
            ORDER BY approved_at_unix DESC
            ",
        )?;

        let rows = statement.query_map(params![host_id.as_bytes().as_slice()], |row| {
            let device_bytes: Vec<u8> = row.get(0)?;
            let key_bytes: Vec<u8> = row.get(1)?;
            let timestamp: i64 = row.get(2)?;

            let controller_device_id = Uuid::from_slice(&device_bytes).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Blob,
                    Box::new(error),
                )
            })?;

            let public_key: [u8; 32] = key_bytes
                .try_into()
                .map_err(|_| rusqlite::Error::InvalidQuery)?;

            let approved_at_unix =
                u64::try_from(timestamp).map_err(|_| rusqlite::Error::InvalidQuery)?;

            Ok(TrustedDevice {
                controller_device_id,
                public_key,
                approved_at_unix,
            })
        })?;

        rows.collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_store() -> (tempfile::TempDir, TrustStore) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("remotix-test.db");
        let store = TrustStore::open(path).unwrap();
        (directory, store)
    }

    #[test]
    fn host_id_survives_reopening_database() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("host.db");

        let first_id = TrustStore::open(&path)
            .unwrap()
            .load_or_create_host_id()
            .unwrap();

        let second_id = TrustStore::open(&path)
            .unwrap()
            .load_or_create_host_id()
            .unwrap();

        assert_eq!(first_id, second_id);
    }

    #[test]
    fn host_identity_binding_accepts_same_key() {
        let (_directory, store) = test_store();
        let host = store.load_or_create_host_id().unwrap();
        let key = [41u8; 32];

        store.bind_host_identity(host, key).unwrap();
        store.bind_host_identity(host, key).unwrap();
    }

    #[test]
    fn host_identity_binding_rejects_replaced_key() {
        let (_directory, store) = test_store();
        let host = store.load_or_create_host_id().unwrap();

        store.bind_host_identity(host, [41u8; 32]).unwrap();

        let result = store.bind_host_identity(host, [42u8; 32]);

        assert!(matches!(
            result,
            Err(IdentityBindingError::PublicKeyMismatch)
        ));
    }

    #[test]
    fn host_identity_binding_rejects_different_host_id() {
        let (_directory, store) = test_store();
        let host = store.load_or_create_host_id().unwrap();

        let result = store.bind_host_identity(Uuid::new_v4(), [41u8; 32]);

        assert!(matches!(result, Err(IdentityBindingError::HostIdMismatch)));
        assert_ne!(host, Uuid::nil());
    }

    #[test]
    fn host_identity_binding_survives_database_reopening() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("host.db");
        let key = [51u8; 32];

        let host = {
            let store = TrustStore::open(&path).unwrap();
            let host = store.load_or_create_host_id().unwrap();
            store.bind_host_identity(host, key).unwrap();
            host
        };

        let reopened = TrustStore::open(&path).unwrap();
        assert!(reopened.bind_host_identity(host, key).is_ok());
        assert!(matches!(
            reopened.bind_host_identity(host, [52u8; 32]),
            Err(IdentityBindingError::PublicKeyMismatch)
        ));
    }

    #[test]
    fn approved_device_can_be_retrieved() {
        let (_directory, store) = test_store();
        let host = store.load_or_create_host_id().unwrap();
        let controller = Uuid::new_v4();
        let key = [7u8; 32];

        store.approve_device(host, controller, key, 100).unwrap();

        let trusted = store.get_trusted_device(host, controller).unwrap().unwrap();

        assert_eq!(trusted.controller_device_id, controller);
        assert_eq!(trusted.public_key, key);
        assert_eq!(trusted.approved_at_unix, 100);
    }

    #[test]
    fn revocation_removes_device_from_active_trust() {
        let (_directory, store) = test_store();
        let host = store.load_or_create_host_id().unwrap();
        let controller = Uuid::new_v4();

        store
            .approve_device(host, controller, [9u8; 32], 100)
            .unwrap();

        assert!(store.revoke_device(host, controller, 200).unwrap());

        assert!(
            store
                .get_trusted_device(host, controller)
                .unwrap()
                .is_none()
        );

        assert!(store.list_trusted_devices(host).unwrap().is_empty());
    }

    #[test]
    fn reapproval_restores_revoked_device() {
        let (_directory, store) = test_store();
        let host = store.load_or_create_host_id().unwrap();
        let controller = Uuid::new_v4();

        store
            .approve_device(host, controller, [1u8; 32], 100)
            .unwrap();

        store.revoke_device(host, controller, 200).unwrap();

        store
            .approve_device(host, controller, [2u8; 32], 300)
            .unwrap();

        let trusted = store.get_trusted_device(host, controller).unwrap().unwrap();

        assert_eq!(trusted.public_key, [2u8; 32]);
        assert_eq!(trusted.approved_at_unix, 300);
    }

    #[test]
    fn trusted_devices_are_isolated_by_host() {
        let (_directory, store) = test_store();
        let host_a = Uuid::new_v4();
        let host_b = Uuid::new_v4();
        let controller = Uuid::new_v4();

        store
            .approve_device(host_a, controller, [3u8; 32], 100)
            .unwrap();

        assert!(
            store
                .get_trusted_device(host_b, controller)
                .unwrap()
                .is_none()
        );
    }
}
