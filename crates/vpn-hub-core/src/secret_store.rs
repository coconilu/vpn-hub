use std::{collections::BTreeMap, path::Path};

use serde::Serialize;
use thiserror::Error;

use crate::{
    OutletKind, PrivateRoutingConfig, ResolvedSubscriptionUrls,
    mihomo::{validate_secret_ref, validate_subscription_url},
};

const CREDENTIAL_SERVICE: &str = "VPN Hub subscription";
const CREDENTIAL_TARGET_PREFIX: &str = "VPNHub:subscription:";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialState {
    Configured,
    Missing,
    Unavailable,
    Corrupted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SubscriptionCredentialStatus {
    pub subscription_id: String,
    pub secret_ref: String,
    pub state: CredentialState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum LegacyMigrationOutcome {
    NotNeeded,
    EmptyLegacyUpgraded,
    Migrated {
        subscription_id: String,
        secret_ref: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SecretStoreError {
    #[error("the protected credential store is unavailable")]
    Unavailable,
    #[error("access to the protected credential store was denied")]
    AccessDenied,
    #[error("the protected credential is corrupted")]
    Corrupted,
    #[error("the credential reference is invalid")]
    InvalidReference,
    #[error("the subscription credential is invalid")]
    InvalidCredential,
    #[error("the subscription is unknown or is not a subscription outlet")]
    UnknownSubscription,
    #[error("the legacy credential migration could not be committed")]
    MigrationFailed,
    #[error("the legacy credential migration rollback failed")]
    RollbackFailed,
}

/// Minimal protected-storage contract. Implementations must not include secret
/// values or platform error details in returned diagnostics.
pub trait SecretStore: Send + Sync {
    /// Reads one protected value without enumerating unrelated credentials.
    ///
    /// # Errors
    ///
    /// Returns only sanitized store diagnostics.
    fn get(&self, secret_ref: &str) -> Result<Option<String>, SecretStoreError>;

    /// Creates or overwrites one protected value.
    ///
    /// # Errors
    ///
    /// Returns only sanitized store diagnostics.
    fn set(&self, secret_ref: &str, secret: &str) -> Result<(), SecretStoreError>;

    /// Deletes one protected value and treats an absent entry as success.
    ///
    /// # Errors
    ///
    /// Returns only sanitized store diagnostics.
    fn delete(&self, secret_ref: &str) -> Result<(), SecretStoreError>;
}

#[cfg(target_os = "windows")]
#[derive(Clone)]
pub struct SystemSecretStore {
    store: std::sync::Arc<windows_native_keyring_store::Store>,
    gate: std::sync::Arc<std::sync::Mutex<()>>,
}

#[cfg(target_os = "windows")]
impl std::fmt::Debug for SystemSecretStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SystemSecretStore(Windows Credential Manager)")
    }
}

#[cfg(target_os = "windows")]
impl SystemSecretStore {
    /// Opens the current Windows user's Credential Manager.
    ///
    /// # Errors
    ///
    /// Returns a sanitized error if Windows cannot initialize the store.
    pub fn new() -> Result<Self, SecretStoreError> {
        windows_native_keyring_store::Store::new()
            .map(|store| Self {
                store,
                gate: std::sync::Arc::new(std::sync::Mutex::new(())),
            })
            .map_err(|error| map_keyring_error(&error))
    }

    fn entry(&self, secret_ref: &str) -> Result<keyring_core::Entry, SecretStoreError> {
        use keyring_core::api::CredentialStoreApi;

        validate_reference(secret_ref)?;
        let target = format!("{CREDENTIAL_TARGET_PREFIX}{secret_ref}");
        let modifiers = std::collections::HashMap::from([
            ("target", target.as_str()),
            ("persistence", "Local"),
        ]);
        self.store
            .build(CREDENTIAL_SERVICE, secret_ref, Some(&modifiers))
            .map_err(|error| map_keyring_error(&error))
    }
}

#[cfg(target_os = "windows")]
impl SecretStore for SystemSecretStore {
    fn get(&self, secret_ref: &str) -> Result<Option<String>, SecretStoreError> {
        let _guard = self
            .gate
            .lock()
            .map_err(|_| SecretStoreError::Unavailable)?;
        match self.entry(secret_ref)?.get_password() {
            Ok(secret) => Ok(Some(secret)),
            Err(keyring_core::Error::NoEntry) => Ok(None),
            Err(error) => Err(map_keyring_error(&error)),
        }
    }

    fn set(&self, secret_ref: &str, secret: &str) -> Result<(), SecretStoreError> {
        let _guard = self
            .gate
            .lock()
            .map_err(|_| SecretStoreError::Unavailable)?;
        self.entry(secret_ref)?
            .set_password(secret)
            .map_err(|error| map_keyring_error(&error))
    }

    fn delete(&self, secret_ref: &str) -> Result<(), SecretStoreError> {
        let _guard = self
            .gate
            .lock()
            .map_err(|_| SecretStoreError::Unavailable)?;
        match self.entry(secret_ref)?.delete_credential() {
            Ok(()) | Err(keyring_core::Error::NoEntry) => Ok(()),
            Err(error) => Err(map_keyring_error(&error)),
        }
    }
}

#[cfg(target_os = "windows")]
fn map_keyring_error(error: &keyring_core::Error) -> SecretStoreError {
    match error {
        keyring_core::Error::NoStorageAccess(_) => SecretStoreError::AccessDenied,
        keyring_core::Error::BadEncoding(_)
        | keyring_core::Error::BadDataFormat(_, _)
        | keyring_core::Error::BadStoreFormat(_) => SecretStoreError::Corrupted,
        keyring_core::Error::Invalid(_, _) | keyring_core::Error::TooLong(_, _) => {
            SecretStoreError::InvalidReference
        }
        _ => SecretStoreError::Unavailable,
    }
}

#[cfg(not(target_os = "windows"))]
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemSecretStore;

#[cfg(not(target_os = "windows"))]
impl SystemSecretStore {
    /// VPN Hub's protected store is intentionally Windows-only.
    ///
    /// # Errors
    ///
    /// Always returns `Unavailable` on non-Windows targets.
    pub const fn new() -> Result<Self, SecretStoreError> {
        Err(SecretStoreError::Unavailable)
    }
}

#[cfg(not(target_os = "windows"))]
impl SecretStore for SystemSecretStore {
    fn get(&self, _secret_ref: &str) -> Result<Option<String>, SecretStoreError> {
        Err(SecretStoreError::Unavailable)
    }

    fn set(&self, _secret_ref: &str, _secret: &str) -> Result<(), SecretStoreError> {
        Err(SecretStoreError::Unavailable)
    }

    fn delete(&self, _secret_ref: &str) -> Result<(), SecretStoreError> {
        Err(SecretStoreError::Unavailable)
    }
}

pub struct SubscriptionSecrets<'a, S: SecretStore + ?Sized> {
    store: &'a S,
}

impl<'a, S: SecretStore + ?Sized> SubscriptionSecrets<'a, S> {
    #[must_use]
    pub const fn new(store: &'a S) -> Self {
        Self { store }
    }

    /// Resolves configured subscription URLs for the short-lived runtime
    /// configuration generation path. Missing credentials are omitted.
    ///
    /// # Errors
    ///
    /// Returns only sanitized protected-store diagnostics.
    pub fn resolve(
        &self,
        config: &PrivateRoutingConfig,
    ) -> Result<ResolvedSubscriptionUrls, SecretStoreError> {
        let mut resolved = BTreeMap::new();
        for outlet in &config.outlets {
            if let OutletKind::Subscription { secret_ref, .. } = &outlet.kind
                && let Some(secret) = self.store.get(secret_ref)?
            {
                validate_subscription_url(&secret).map_err(|_| SecretStoreError::Corrupted)?;
                resolved.insert(secret_ref.clone(), secret);
            }
        }
        Ok(resolved)
    }

    #[must_use]
    pub fn statuses(&self, config: &PrivateRoutingConfig) -> Vec<SubscriptionCredentialStatus> {
        config
            .outlets
            .iter()
            .filter_map(|outlet| {
                let OutletKind::Subscription { secret_ref, .. } = &outlet.kind else {
                    return None;
                };
                let state = match self.store.get(secret_ref) {
                    Ok(Some(secret)) if validate_subscription_url(&secret).is_ok() => {
                        CredentialState::Configured
                    }
                    Ok(Some(_)) | Err(SecretStoreError::Corrupted) => CredentialState::Corrupted,
                    Ok(None) => CredentialState::Missing,
                    Err(_) => CredentialState::Unavailable,
                };
                Some(SubscriptionCredentialStatus {
                    subscription_id: outlet.id.clone(),
                    secret_ref: secret_ref.clone(),
                    state,
                })
            })
            .collect()
    }

    /// Creates or overwrites one configured subscription's protected value.
    ///
    /// # Errors
    ///
    /// Rejects unknown IDs, invalid URLs, and sanitized store failures.
    pub fn set(
        &self,
        config: &PrivateRoutingConfig,
        subscription_id: &str,
        credential: &str,
    ) -> Result<SubscriptionCredentialStatus, SecretStoreError> {
        validate_subscription_url(credential).map_err(|_| SecretStoreError::InvalidCredential)?;
        let secret_ref = subscription_ref(config, subscription_id)?;
        self.store.set(secret_ref, credential)?;
        Ok(SubscriptionCredentialStatus {
            subscription_id: subscription_id.into(),
            secret_ref: secret_ref.into(),
            state: CredentialState::Configured,
        })
    }

    /// Removes one configured subscription's protected value. The stable ID
    /// and non-secret routing definition remain available for reconfiguration.
    ///
    /// # Errors
    ///
    /// Rejects unknown IDs and sanitized store failures.
    pub fn delete(
        &self,
        config: &PrivateRoutingConfig,
        subscription_id: &str,
    ) -> Result<SubscriptionCredentialStatus, SecretStoreError> {
        let secret_ref = subscription_ref(config, subscription_id)?;
        self.store.delete(secret_ref)?;
        Ok(SubscriptionCredentialStatus {
            subscription_id: subscription_id.into(),
            secret_ref: secret_ref.into(),
            state: CredentialState::Missing,
        })
    }
}

/// Migrates the one legacy plaintext subscription into protected storage.
/// The credential write happens before the atomic config rewrite; if the
/// rewrite fails, the previous credential value is restored or removed.
///
/// # Errors
///
/// Returns sanitized migration or rollback failures. A failed credential
/// write leaves the original legacy file untouched.
pub fn migrate_legacy_subscription<S: SecretStore + ?Sized>(
    path: impl AsRef<Path>,
    store: &S,
) -> Result<LegacyMigrationOutcome, SecretStoreError> {
    let path = path.as_ref();
    let backup = path.with_extension("toml.bak");
    let original_primary = snapshot_file(path)?;
    let original_backup = snapshot_file(&backup)?;
    let mut config =
        PrivateRoutingConfig::load(path).map_err(|_| SecretStoreError::MigrationFailed)?;
    if !config.is_legacy_format() {
        return Ok(LegacyMigrationOutcome::NotNeeded);
    }

    let legacy = config
        .legacy_subscription_credential()
        .map(|(id, secret_ref, secret)| (id.to_owned(), secret_ref.to_owned(), secret.to_owned()));
    let previous = if let Some((_, secret_ref, secret)) = &legacy {
        let previous = store.get(secret_ref)?;
        store.set(secret_ref, secret)?;
        Some((secret_ref.clone(), previous))
    } else {
        None
    };

    config.promote_legacy_format();
    if config.save(path).is_err() {
        restore_snapshot(path, original_primary.as_deref())?;
        restore_snapshot(&backup, original_backup.as_deref())?;
        if let Some((secret_ref, previous)) = previous {
            let rollback = match previous {
                Some(secret) => store.set(&secret_ref, &secret),
                None => store.delete(&secret_ref),
            };
            if rollback.is_err() {
                return Err(SecretStoreError::RollbackFailed);
            }
        }
        return Err(SecretStoreError::MigrationFailed);
    }

    Ok(legacy.map_or(
        LegacyMigrationOutcome::EmptyLegacyUpgraded,
        |(id, secret_ref, _)| LegacyMigrationOutcome::Migrated {
            subscription_id: id,
            secret_ref,
        },
    ))
}

fn snapshot_file(path: &Path) -> Result<Option<Vec<u8>>, SecretStoreError> {
    if path.exists() {
        std::fs::read(path)
            .map(Some)
            .map_err(|_| SecretStoreError::MigrationFailed)
    } else {
        Ok(None)
    }
}

fn restore_snapshot(path: &Path, content: Option<&[u8]>) -> Result<(), SecretStoreError> {
    match content {
        Some(content) => {
            std::fs::write(path, content).map_err(|_| SecretStoreError::RollbackFailed)
        }
        None if path.exists() => {
            std::fs::remove_file(path).map_err(|_| SecretStoreError::RollbackFailed)
        }
        None => Ok(()),
    }
}

fn subscription_ref<'a>(
    config: &'a PrivateRoutingConfig,
    subscription_id: &str,
) -> Result<&'a str, SecretStoreError> {
    config
        .outlets
        .iter()
        .find_map(|outlet| {
            (outlet.id == subscription_id)
                .then(|| outlet.secret_ref())
                .flatten()
        })
        .ok_or(SecretStoreError::UnknownSubscription)
}

fn validate_reference(secret_ref: &str) -> Result<(), SecretStoreError> {
    validate_secret_ref(secret_ref).map_err(|_| SecretStoreError::InvalidReference)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::{OutletConfig, generate_controller_secret};

    #[derive(Default)]
    struct MemorySecretStore {
        values: Mutex<BTreeMap<String, String>>,
    }

    impl SecretStore for MemorySecretStore {
        fn get(&self, secret_ref: &str) -> Result<Option<String>, SecretStoreError> {
            Ok(self.values.lock().expect("values").get(secret_ref).cloned())
        }

        fn set(&self, secret_ref: &str, secret: &str) -> Result<(), SecretStoreError> {
            validate_reference(secret_ref)?;
            self.values
                .lock()
                .expect("values")
                .insert(secret_ref.into(), secret.into());
            Ok(())
        }

        fn delete(&self, secret_ref: &str) -> Result<(), SecretStoreError> {
            self.values.lock().expect("values").remove(secret_ref);
            Ok(())
        }
    }

    fn three_subscription_config() -> PrivateRoutingConfig {
        let mut config = PrivateRoutingConfig::default();
        for suffix in ['a', 'b', 'c'] {
            config.outlets.push(OutletConfig {
                id: format!("subscription-{suffix}"),
                label: format!("Subscription {suffix}"),
                enabled: true,
                kind: OutletKind::Subscription {
                    secret_ref: format!("subscription.{suffix}"),
                    provider_update_seconds: 180,
                },
            });
        }
        config
    }

    fn random_url() -> String {
        format!(
            "https://example.invalid/subscription/{}",
            generate_controller_secret()
        )
    }

    #[test]
    fn persists_three_stable_subscriptions_and_isolates_overwrite_and_delete() {
        let config = three_subscription_config();
        let store = MemorySecretStore::default();
        let original = [random_url(), random_url(), random_url()];
        {
            let secrets = SubscriptionSecrets::new(&store);
            for (suffix, credential) in ['a', 'b', 'c'].into_iter().zip(&original) {
                secrets
                    .set(&config, &format!("subscription-{suffix}"), credential)
                    .expect("set");
            }
        }

        let restarted = SubscriptionSecrets::new(&store);
        let statuses = restarted.statuses(&config);
        assert!(
            statuses
                .iter()
                .all(|status| status.state == CredentialState::Configured)
        );
        let status_json = serde_json::to_string(&statuses).expect("status json");
        for credential in &original {
            assert!(!status_json.contains(credential));
        }
        let replacement = random_url();
        restarted
            .set(&config, "subscription-b", &replacement)
            .expect("overwrite b");
        restarted
            .delete(&config, "subscription-c")
            .expect("delete c");

        let resolved = restarted.resolve(&config).expect("resolve");
        assert_eq!(resolved.get("subscription.a"), Some(&original[0]));
        assert_eq!(resolved.get("subscription.b"), Some(&replacement));
        assert!(!resolved.contains_key("subscription.c"));
        assert_eq!(
            restarted.statuses(&config)[2].state,
            CredentialState::Missing
        );
    }

    #[test]
    fn migrates_legacy_plaintext_without_leaving_it_in_config_or_backup() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("private-routing.toml");
        let credential = random_url();
        std::fs::write(
            &path,
            format!(
                r#"subscription_url = "{credential}"
provider_update_seconds = 180
controller_port = 39090
route_mode = "priority"
priority = ["subscription-a", "chaoshihui"]
cooldown_seconds = 60
minimum_improvement_ms = 150
probe_targets = ["https://example.com/a", "https://example.com/b"]
"#
            ),
        )
        .expect("legacy config");
        let store = MemorySecretStore::default();

        let outcome = migrate_legacy_subscription(&path, &store).expect("migration");
        assert!(matches!(outcome, LegacyMigrationOutcome::Migrated { .. }));
        for config_path in [&path, &path.with_extension("toml.bak")] {
            let content = std::fs::read_to_string(config_path).expect("versioned config");
            assert!(!content.contains(&credential));
            assert!(!content.contains("subscription_url"));
        }
        let config = PrivateRoutingConfig::load(&path).expect("versioned config");
        let resolved = SubscriptionSecrets::new(&store)
            .resolve(&config)
            .expect("resolved migrated credential");
        assert_eq!(resolved.get("legacy.subscription-a"), Some(&credential));
    }

    struct FailingStore;

    impl SecretStore for FailingStore {
        fn get(&self, _secret_ref: &str) -> Result<Option<String>, SecretStoreError> {
            Ok(None)
        }

        fn set(&self, _secret_ref: &str, _secret: &str) -> Result<(), SecretStoreError> {
            Err(SecretStoreError::Unavailable)
        }

        fn delete(&self, _secret_ref: &str) -> Result<(), SecretStoreError> {
            Ok(())
        }
    }

    #[test]
    fn failed_store_write_keeps_the_single_legacy_copy() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("private-routing.toml");
        let credential = random_url();
        let original = format!(
            r#"subscription_url = "{credential}"
provider_update_seconds = 180
controller_port = 39090
route_mode = "priority"
priority = ["subscription-a", "chaoshihui"]
cooldown_seconds = 60
minimum_improvement_ms = 150
probe_targets = ["https://example.com/a", "https://example.com/b"]
"#
        );
        std::fs::write(&path, &original).expect("legacy config");

        assert_eq!(
            migrate_legacy_subscription(&path, &FailingStore),
            Err(SecretStoreError::Unavailable)
        );
        assert_eq!(
            std::fs::read_to_string(path).expect("legacy remains"),
            original
        );
    }

    #[test]
    fn failed_config_commit_restores_files_and_removes_new_credential() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("private-routing.toml");
        let credential = random_url();
        let original = format!(
            r#"subscription_url = "{credential}"
provider_update_seconds = 180
controller_port = 39090
route_mode = "priority"
priority = ["subscription-a", "chaoshihui"]
cooldown_seconds = 60
minimum_improvement_ms = 150
probe_targets = ["https://example.com/a", "https://example.com/b"]
"#
        );
        std::fs::write(&path, &original).expect("legacy config");
        std::fs::create_dir(path.with_extension("toml.tmp")).expect("block atomic temp file");
        let store = MemorySecretStore::default();

        assert_eq!(
            migrate_legacy_subscription(&path, &store),
            Err(SecretStoreError::MigrationFailed)
        );
        assert_eq!(
            std::fs::read_to_string(path).expect("legacy restored"),
            original
        );
        assert_eq!(
            store.get("legacy.subscription-a").expect("store state"),
            None
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_credential_manager_round_trip_uses_random_values_and_cleans_up() {
        struct Cleanup {
            store: SystemSecretStore,
            refs: Vec<String>,
        }
        impl Drop for Cleanup {
            fn drop(&mut self) {
                for secret_ref in &self.refs {
                    let _ = self.store.delete(secret_ref);
                }
            }
        }

        let store = SystemSecretStore::new().expect("Windows Credential Manager");
        let token = generate_controller_secret().to_lowercase();
        let refs = ['a', 'b', 'c']
            .map(|suffix| format!("test.{token}.{suffix}"))
            .to_vec();
        let cleanup = Cleanup {
            store: store.clone(),
            refs: refs.clone(),
        };
        for secret_ref in &refs {
            store.delete(secret_ref).expect("pre-test cleanup");
            let value = random_url();
            store
                .set(secret_ref, &value)
                .expect("set random credential");
            assert_eq!(
                store.get(secret_ref).expect("get random credential"),
                Some(value)
            );
        }
        drop(cleanup);
        for secret_ref in &refs {
            assert_eq!(store.get(secret_ref).expect("verify cleanup"), None);
        }
    }
}
