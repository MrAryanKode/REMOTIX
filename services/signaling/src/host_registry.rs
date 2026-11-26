use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use std::{path::Path, time::Duration};
use uuid::Uuid;

const TOKEN_MIN_LENGTH: usize = 32;
const DEFAULT_TOKEN_TTL_SECONDS: u64 = 600;

#[derive(Debug)]
pub enum EnrollmentError {
    Database(rusqlite::Error),
    InvalidToken,
    TokenExpired,
    TokenAlreadyUsed,
    HostAlreadyEnrolled,
    InvalidTimestamp,
    InvalidTokenLength,
}

impl std::fmt::Display for EnrollmentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Database(error) => write!(f, "Host registry database error: {error}"),
            Self::InvalidToken => write!(f, "Enrollment token is invalid"),
            Self::TokenExpired => write!(f, "Enrollment token has expired"),
            Self::TokenAlreadyUsed => write!(f, "Enrollment token has already been used"),
            Self::HostAlreadyEnrolled => write!(f, "Host is already enrolled"),
            Self::InvalidTimestamp => write!(f, "Enrollment timestamp is out of range"),
            Self::InvalidTokenLength => {
                write!(f, "Enrollment token must contain at least 32 characters")
            }
        }
    }
}

impl std::error::Error for EnrollmentError {}

impl From<rusqlite::Error> for EnrollmentError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Database(error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrolledHost {
    pub host_device_id: Uuid,
    pub public_key: [u8; 32],
    pub enrolled_at_unix: u64,
}

pub struct HostRegistry {
    connection: Connection,
}

impl HostRegistry {
    pub fn open(path: impl AsRef<Path>) -> rusqlite::Result<Self> {
        let connection = Connection::open(path)?;
        connection.busy_timeout(Duration::from_secs(5))?;

        connection.execute_batch(
            "
            PRAGMA foreign_keys = ON;
            PRAGMA secure_delete = ON;

            CREATE TABLE IF NOT EXISTS enrolled_hosts (
                host_device_id BLOB PRIMARY KEY NOT NULL
                    CHECK(length(host_device_id) = 16),
                host_public_key BLOB NOT NULL
                    CHECK(length(host_public_key) = 32),
                enrolled_at_unix INTEGER NOT NULL
                    CHECK(enrolled_at_unix >= 0),
                revoked_at_unix INTEGER
            );

            CREATE TABLE IF NOT EXISTS enrollment_tokens (
                token_hash BLOB PRIMARY KEY NOT NULL
                    CHECK(length(token_hash) = 32),
                created_at_unix INTEGER NOT NULL
                    CHECK(created_at_unix >= 0),
                expires_at_unix INTEGER NOT NULL
                    CHECK(expires_at_unix > created_at_unix),
                consumed_at_unix INTEGER
            );

            CREATE INDEX IF NOT EXISTS idx_enrolled_hosts_active
            ON enrolled_hosts(host_device_id, revoked_at_unix);
            ",
        )?;

        // Backward-compatible migration for databases created before expiry
        // was introduced. Existing unused tokens receive a 10-minute window
        // measured from their original creation time.
        let has_expiry_column = {
            let mut statement = connection.prepare("PRAGMA table_info(enrollment_tokens)")?;
            let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
            let mut found = false;
            for column in columns {
                if column? == "expires_at_unix" {
                    found = true;
                    break;
                }
            }
            found
        };

        if !has_expiry_column {
            connection.execute_batch(
                "ALTER TABLE enrollment_tokens
                 ADD COLUMN expires_at_unix INTEGER;",
            )?;

            connection.execute(
                "UPDATE enrollment_tokens
                 SET expires_at_unix = created_at_unix + ?1
                 WHERE expires_at_unix IS NULL",
                [DEFAULT_TOKEN_TTL_SECONDS as i64],
            )?;
        }

        Ok(Self { connection })
    }

    /// Provisions a one-time token with the default 10-minute lifetime.
    ///
    /// Only the SHA-256 digest is stored.
    pub fn provision_token(
        &mut self,
        token: &str,
        created_at_unix: u64,
    ) -> Result<(), EnrollmentError> {
        let expires_at_unix = created_at_unix
            .checked_add(DEFAULT_TOKEN_TTL_SECONDS)
            .ok_or(EnrollmentError::InvalidTimestamp)?;

        self.provision_token_with_expiry(token, created_at_unix, expires_at_unix)
    }

    /// Provisions a one-time token with an explicit expiration timestamp.
    pub fn provision_token_with_expiry(
        &mut self,
        token: &str,
        created_at_unix: u64,
        expires_at_unix: u64,
    ) -> Result<(), EnrollmentError> {
        if token.len() < TOKEN_MIN_LENGTH {
            return Err(EnrollmentError::InvalidTokenLength);
        }

        let created =
            i64::try_from(created_at_unix).map_err(|_| EnrollmentError::InvalidTimestamp)?;
        let expires =
            i64::try_from(expires_at_unix).map_err(|_| EnrollmentError::InvalidTimestamp)?;

        if expires <= created {
            return Err(EnrollmentError::InvalidTimestamp);
        }

        let digest = Self::token_digest(token);

        self.connection.execute(
            "INSERT INTO enrollment_tokens
             (token_hash, created_at_unix, expires_at_unix, consumed_at_unix)
             VALUES (?1, ?2, ?3, NULL)",
            params![digest.as_slice(), created, expires],
        )?;

        Ok(())
    }

    /// Atomically consumes a token and enrolls a host.
    ///
    /// An enrolled host's public key cannot be silently replaced.
    pub fn enroll_host(
        &mut self,
        token: &str,
        host_device_id: Uuid,
        public_key: [u8; 32],
        enrolled_at_unix: u64,
    ) -> Result<(), EnrollmentError> {
        if token.len() < TOKEN_MIN_LENGTH {
            return Err(EnrollmentError::InvalidToken);
        }

        let timestamp =
            i64::try_from(enrolled_at_unix).map_err(|_| EnrollmentError::InvalidTimestamp)?;

        let digest = Self::token_digest(token);
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;

        let (consumed_at, expires_at): (Option<i64>, i64) = transaction
            .query_row(
                "SELECT consumed_at_unix, expires_at_unix
                 FROM enrollment_tokens
                 WHERE token_hash = ?1",
                params![digest.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .ok_or(EnrollmentError::InvalidToken)?;

        if consumed_at.is_some() {
            return Err(EnrollmentError::TokenAlreadyUsed);
        }

        if timestamp >= expires_at {
            return Err(EnrollmentError::TokenExpired);
        }

        let existing_host: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT host_device_id FROM enrolled_hosts
                 WHERE host_device_id = ?1",
                params![host_device_id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()?;

        if existing_host.is_some() {
            return Err(EnrollmentError::HostAlreadyEnrolled);
        }

        transaction.execute(
            "INSERT INTO enrolled_hosts
             (host_device_id, host_public_key, enrolled_at_unix, revoked_at_unix)
             VALUES (?1, ?2, ?3, NULL)",
            params![
                host_device_id.as_bytes().as_slice(),
                public_key.as_slice(),
                timestamp
            ],
        )?;

        let changed = transaction.execute(
            "UPDATE enrollment_tokens
             SET consumed_at_unix = ?2
             WHERE token_hash = ?1 AND consumed_at_unix IS NULL",
            params![digest.as_slice(), timestamp],
        )?;

        if changed != 1 {
            return Err(EnrollmentError::TokenAlreadyUsed);
        }

        transaction.commit()?;
        Ok(())
    }

    pub fn get_host(&self, host_device_id: Uuid) -> rusqlite::Result<Option<EnrolledHost>> {
        let row: Option<(Vec<u8>, Vec<u8>, i64)> = self
            .connection
            .query_row(
                "SELECT host_device_id, host_public_key, enrolled_at_unix
                 FROM enrolled_hosts
                 WHERE host_device_id = ?1 AND revoked_at_unix IS NULL",
                params![host_device_id.as_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;

        row.map(|(id, key, timestamp)| {
            let host_device_id = Uuid::from_slice(&id).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Blob,
                    Box::new(error),
                )
            })?;

            let public_key: [u8; 32] = key.try_into().map_err(|_| rusqlite::Error::InvalidQuery)?;

            let enrolled_at_unix =
                u64::try_from(timestamp).map_err(|_| rusqlite::Error::InvalidQuery)?;

            Ok(EnrolledHost {
                host_device_id,
                public_key,
                enrolled_at_unix,
            })
        })
        .transpose()
    }

    pub fn revoke_host(
        &mut self,
        host_device_id: Uuid,
        revoked_at_unix: u64,
    ) -> rusqlite::Result<bool> {
        let timestamp =
            i64::try_from(revoked_at_unix).map_err(|_| rusqlite::Error::InvalidQuery)?;

        let changed = self.connection.execute(
            "UPDATE enrolled_hosts
             SET revoked_at_unix = ?2
             WHERE host_device_id = ?1 AND revoked_at_unix IS NULL",
            params![host_device_id.as_bytes().as_slice(), timestamp],
        )?;

        Ok(changed == 1)
    }

    fn token_digest(token: &str) -> [u8; 32] {
        Sha256::digest(token.as_bytes()).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_registry() -> (tempfile::TempDir, HostRegistry) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("host-registry.db");
        let registry = HostRegistry::open(path).unwrap();
        (directory, registry)
    }

    const TOKEN: &str = "remotix-test-enrollment-token-0123456789abcdef";

    #[test]
    fn provisions_and_consumes_one_time_token() {
        let (_directory, mut registry) = test_registry();
        let host_id = Uuid::new_v4();
        let public_key = [11u8; 32];

        registry.provision_token(TOKEN, 100).unwrap();
        registry
            .enroll_host(TOKEN, host_id, public_key, 200)
            .unwrap();

        let enrolled = registry.get_host(host_id).unwrap().unwrap();
        assert_eq!(enrolled.host_device_id, host_id);
        assert_eq!(enrolled.public_key, public_key);
        assert_eq!(enrolled.enrolled_at_unix, 200);
    }

    #[test]
    fn rejects_unknown_token() {
        let (_directory, mut registry) = test_registry();

        let result = registry.enroll_host(TOKEN, Uuid::new_v4(), [1u8; 32], 100);

        assert!(matches!(result, Err(EnrollmentError::InvalidToken)));
    }

    #[test]
    fn rejects_short_tokens() {
        let (_directory, mut registry) = test_registry();

        assert!(matches!(
            registry.provision_token("short", 100),
            Err(EnrollmentError::InvalidTokenLength)
        ));
    }

    #[test]
    fn rejects_expired_enrollment_token() {
        let (_directory, mut registry) = test_registry();

        registry
            .provision_token_with_expiry(TOKEN, 100, 150)
            .unwrap();

        let result = registry.enroll_host(TOKEN, Uuid::new_v4(), [9u8; 32], 150);

        assert!(matches!(result, Err(EnrollmentError::TokenExpired)));
    }

    #[test]
    fn rejects_invalid_expiry_timestamp() {
        let (_directory, mut registry) = test_registry();

        let result = registry.provision_token_with_expiry(TOKEN, 200, 200);

        assert!(matches!(result, Err(EnrollmentError::InvalidTimestamp)));
    }

    #[test]
    fn rejects_reuse_of_consumed_token() {
        let (_directory, mut registry) = test_registry();
        registry.provision_token(TOKEN, 100).unwrap();

        registry
            .enroll_host(TOKEN, Uuid::new_v4(), [2u8; 32], 200)
            .unwrap();

        let result = registry.enroll_host(TOKEN, Uuid::new_v4(), [3u8; 32], 300);

        assert!(matches!(result, Err(EnrollmentError::TokenAlreadyUsed)));
    }

    #[test]
    fn rejects_duplicate_host_enrollment_without_replacing_key() {
        let (_directory, mut registry) = test_registry();
        let host_id = Uuid::new_v4();

        registry.provision_token(TOKEN, 100).unwrap();
        registry
            .enroll_host(TOKEN, host_id, [4u8; 32], 200)
            .unwrap();

        registry
            .provision_token("another-remotix-enrollment-token-0123456789", 300)
            .unwrap();

        let result = registry.enroll_host(
            "another-remotix-enrollment-token-0123456789",
            host_id,
            [5u8; 32],
            400,
        );

        assert!(matches!(result, Err(EnrollmentError::HostAlreadyEnrolled)));

        let enrolled = registry.get_host(host_id).unwrap().unwrap();
        assert_eq!(enrolled.public_key, [4u8; 32]);
    }

    #[test]
    fn revocation_removes_host_from_active_lookup() {
        let (_directory, mut registry) = test_registry();
        let host_id = Uuid::new_v4();

        registry.provision_token(TOKEN, 100).unwrap();
        registry
            .enroll_host(TOKEN, host_id, [6u8; 32], 200)
            .unwrap();

        assert!(registry.revoke_host(host_id, 300).unwrap());
        assert!(registry.get_host(host_id).unwrap().is_none());
        assert!(!registry.revoke_host(host_id, 400).unwrap());
    }

    #[test]
    fn enrollment_survives_database_reopening() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("registry.db");
        let host_id = Uuid::new_v4();

        {
            let mut registry = HostRegistry::open(&path).unwrap();
            registry.provision_token(TOKEN, 100).unwrap();
            registry
                .enroll_host(TOKEN, host_id, [7u8; 32], 200)
                .unwrap();
        }

        let mut reopened = HostRegistry::open(&path).unwrap();
        let enrolled = reopened.get_host(host_id).unwrap().unwrap();
        assert_eq!(enrolled.public_key, [7u8; 32]);

        let result = reopened.enroll_host(TOKEN, Uuid::new_v4(), [8u8; 32], 300);
        assert!(matches!(result, Err(EnrollmentError::TokenAlreadyUsed)));
    }
}
