use std::{
    collections::BTreeMap,
    fs,
    io::{BufWriter, Write},
    path::Path,
    time::{Duration, Instant},
};

use chrono::{DateTime, SecondsFormat, Utc};
use rusqlite::{Connection, OptionalExtension, params, params_from_iter, types::Value};
use thiserror::Error;

use crate::{
    HealthStatus, HistoryEventType, HistoryFilter, HistoryMetric, HistoryOutletKind,
    HistoryOutletOption, HistoryOutletSnapshot, HistoryRecord, HistoryResponse, LatencySample,
    OutletHealth, OutletSummary, ProbeOutletConfig, ProbeResult, RouteSwitchEvent, StateEvent,
    UdpCapabilityEvidence, UdpCapabilityStatus,
};

const CURRENT_DATABASE_VERSION: i64 = 4;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("failed to prepare database directory: {0}")]
    Directory(#[from] std::io::Error),
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("invalid stored status: {0}")]
    InvalidStatus(String),
    #[error("invalid stored UDP capability: {0}")]
    InvalidUdpCapability(String),
    #[error("invalid stored outlet kind: {0}")]
    InvalidOutletKind(String),
    #[error("invalid history timestamp: {0}")]
    InvalidTimestamp(String),
    #[error("invalid retention days: {0}; expected 1..=3650")]
    InvalidRetention(u32),
    #[error("UDP configuration generation is outside the supported SQLite integer range")]
    InvalidUdpGeneration,
    #[error("database version {0} is newer than this application supports")]
    UnsupportedDatabaseVersion(i64),
    #[error("Guardian durable batch exceeded its cycle deadline")]
    Deadline,
}

pub struct GuardianStore {
    connection: Connection,
}

#[derive(Debug)]
struct StoredState {
    status: HealthStatus,
    consecutive_successes: u32,
    consecutive_failures: u32,
}

impl GuardianStore {
    /// Opens or creates a Guardian `SQLite` database and applies its schema.
    ///
    /// # Errors
    ///
    /// Returns an error when the parent directory or database cannot be opened.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let connection = Connection::open(path)?;
        Self::from_connection(connection)
    }

    #[cfg(test)]
    fn open_in_memory() -> Result<Self, StoreError> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    #[allow(clippy::too_many_lines)]
    fn from_connection(mut connection: Connection) -> Result<Self, StoreError> {
        let user_version = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if user_version > CURRENT_DATABASE_VERSION {
            return Err(StoreError::UnsupportedDatabaseVersion(user_version));
        }
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        let transaction = connection.transaction()?;
        transaction.execute_batch(
            r"
            CREATE TABLE IF NOT EXISTS outlets (
                id TEXT PRIMARY KEY,
                label TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                kind TEXT NOT NULL DEFAULT 'unknown',
                enabled INTEGER NOT NULL DEFAULT 1,
                deleted_at TEXT
            );
            CREATE TABLE IF NOT EXISTS probe_samples (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                outlet_id TEXT NOT NULL REFERENCES outlets(id) ON DELETE CASCADE,
                observed_at TEXT NOT NULL,
                port_reachable INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL,
                http_status INTEGER,
                latency_ms INTEGER,
                error_code TEXT,
                successful_targets INTEGER NOT NULL DEFAULT 0,
                total_targets INTEGER NOT NULL DEFAULT 1,
                outlet_label TEXT NOT NULL DEFAULT '',
                outlet_kind TEXT NOT NULL DEFAULT 'unknown'
            );
            CREATE INDEX IF NOT EXISTS idx_probe_samples_outlet_time
                ON probe_samples(outlet_id, observed_at DESC);
            CREATE TABLE IF NOT EXISTS outlet_state (
                outlet_id TEXT PRIMARY KEY REFERENCES outlets(id) ON DELETE CASCADE,
                status TEXT NOT NULL,
                consecutive_successes INTEGER NOT NULL,
                consecutive_failures INTEGER NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS state_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                outlet_id TEXT NOT NULL REFERENCES outlets(id) ON DELETE CASCADE,
                occurred_at TEXT NOT NULL,
                from_status TEXT NOT NULL,
                to_status TEXT NOT NULL,
                reason TEXT NOT NULL,
                outlet_label TEXT NOT NULL DEFAULT '',
                outlet_kind TEXT NOT NULL DEFAULT 'unknown'
            );
            CREATE INDEX IF NOT EXISTS idx_state_events_outlet_time
                ON state_events(outlet_id, occurred_at DESC);
            CREATE TABLE IF NOT EXISTS route_switches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                occurred_at TEXT NOT NULL,
                from_outlet TEXT,
                to_outlet TEXT NOT NULL,
                mode TEXT NOT NULL,
                reason TEXT NOT NULL,
                duration_ms INTEGER NOT NULL,
                from_label TEXT,
                from_kind TEXT,
                to_label TEXT NOT NULL DEFAULT '',
                to_kind TEXT NOT NULL DEFAULT 'unknown'
            );
            CREATE INDEX IF NOT EXISTS idx_route_switches_time
                ON route_switches(occurred_at DESC);
            CREATE TABLE IF NOT EXISTS udp_capability_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                outlet_id TEXT NOT NULL REFERENCES outlets(id) ON DELETE CASCADE,
                status TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                evidence_version INTEGER NOT NULL,
                probe_version TEXT NOT NULL,
                model_version INTEGER NOT NULL,
                configuration_fingerprint TEXT NOT NULL,
                configuration_generation INTEGER NOT NULL,
                reason_code TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_udp_capability_history_outlet_time
                ON udp_capability_history(outlet_id, observed_at DESC);
            CREATE TABLE IF NOT EXISTS udp_capability_current (
                outlet_id TEXT PRIMARY KEY REFERENCES outlets(id) ON DELETE CASCADE,
                history_id INTEGER NOT NULL REFERENCES udp_capability_history(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS history_settings (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                retention_days INTEGER NOT NULL CHECK (retention_days BETWEEN 1 AND 3650)
            );
            INSERT OR IGNORE INTO history_settings(id, retention_days) VALUES (1, 30);
            ",
        )?;
        ensure_probe_column(&transaction, "port_reachable", "INTEGER NOT NULL DEFAULT 0")?;
        ensure_probe_column(&transaction, "http_status", "INTEGER")?;
        ensure_probe_column(
            &transaction,
            "successful_targets",
            "INTEGER NOT NULL DEFAULT 0",
        )?;
        ensure_probe_column(&transaction, "total_targets", "INTEGER NOT NULL DEFAULT 1")?;
        ensure_column(
            &transaction,
            "outlets",
            "kind",
            "TEXT NOT NULL DEFAULT 'unknown'",
        )?;
        ensure_column(
            &transaction,
            "outlets",
            "enabled",
            "INTEGER NOT NULL DEFAULT 1",
        )?;
        ensure_column(&transaction, "outlets", "deleted_at", "TEXT")?;
        ensure_column(
            &transaction,
            "probe_samples",
            "outlet_label",
            "TEXT NOT NULL DEFAULT ''",
        )?;
        ensure_column(
            &transaction,
            "probe_samples",
            "outlet_kind",
            "TEXT NOT NULL DEFAULT 'unknown'",
        )?;
        ensure_column(
            &transaction,
            "state_events",
            "outlet_label",
            "TEXT NOT NULL DEFAULT ''",
        )?;
        ensure_column(
            &transaction,
            "state_events",
            "outlet_kind",
            "TEXT NOT NULL DEFAULT 'unknown'",
        )?;
        ensure_column(&transaction, "route_switches", "from_label", "TEXT")?;
        ensure_column(&transaction, "route_switches", "from_kind", "TEXT")?;
        ensure_column(
            &transaction,
            "route_switches",
            "to_label",
            "TEXT NOT NULL DEFAULT ''",
        )?;
        ensure_column(
            &transaction,
            "route_switches",
            "to_kind",
            "TEXT NOT NULL DEFAULT 'unknown'",
        )?;
        transaction.execute_batch(
            r"
            UPDATE probe_samples
               SET outlet_label = COALESCE(NULLIF(outlet_label, ''), (SELECT label FROM outlets WHERE id=probe_samples.outlet_id)),
                   outlet_kind = COALESCE(NULLIF(outlet_kind, 'unknown'), (SELECT kind FROM outlets WHERE id=probe_samples.outlet_id), 'unknown')
             WHERE outlet_label = '';
            UPDATE state_events
               SET outlet_label = COALESCE(NULLIF(outlet_label, ''), (SELECT label FROM outlets WHERE id=state_events.outlet_id)),
                   outlet_kind = COALESCE(NULLIF(outlet_kind, 'unknown'), (SELECT kind FROM outlets WHERE id=state_events.outlet_id), 'unknown')
             WHERE outlet_label = '';
            UPDATE route_switches
               SET from_label = COALESCE(from_label, (SELECT label FROM outlets WHERE id=route_switches.from_outlet)),
                   from_kind = COALESCE(from_kind, (SELECT kind FROM outlets WHERE id=route_switches.from_outlet)),
                   to_label = COALESCE(NULLIF(to_label, ''), (SELECT label FROM outlets WHERE id=route_switches.to_outlet), to_outlet),
                   to_kind = COALESCE(NULLIF(to_kind, 'unknown'), (SELECT kind FROM outlets WHERE id=route_switches.to_outlet), 'unknown')
             WHERE to_label = '' OR (from_outlet IS NOT NULL AND from_label IS NULL);
            CREATE INDEX IF NOT EXISTS idx_probe_samples_time_outlet_status
                ON probe_samples(observed_at DESC, outlet_id, status);
            CREATE INDEX IF NOT EXISTS idx_state_events_time_outlet_status
                ON state_events(occurred_at DESC, outlet_id, to_status);
            CREATE INDEX IF NOT EXISTS idx_route_switches_time_outlets
                ON route_switches(occurred_at DESC, from_outlet, to_outlet);
            ",
        )?;
        if user_version < CURRENT_DATABASE_VERSION {
            sanitize_persisted_history_labels(&transaction)?;
            canonicalize_persisted_timestamps(&transaction)?;
        }
        transaction.pragma_update(None, "user_version", CURRENT_DATABASE_VERSION)?;
        transaction.commit()?;
        Ok(Self { connection })
    }

    /// Synchronizes the current non-sensitive outlet catalogue. Rows missing
    /// from the supplied configuration are tombstoned rather than deleted so
    /// historical foreign keys and display snapshots remain explainable.
    ///
    /// # Errors
    ///
    /// Returns an error when the catalogue transaction cannot be committed.
    pub fn sync_history_outlets(
        &mut self,
        outlets: &[HistoryOutletSnapshot],
        observed_at: &str,
    ) -> Result<(), StoreError> {
        let observed_at = canonical_timestamp(observed_at)?;
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "UPDATE outlets SET enabled=0, deleted_at=COALESCE(deleted_at, ?1)",
            [&observed_at],
        )?;
        for outlet in outlets {
            let label = crate::history::sanitized_label(&outlet.label);
            transaction.execute(
                r"INSERT INTO outlets(id, label, updated_at, kind, enabled, deleted_at)
                   VALUES (?1, ?2, ?3, ?4, ?5, NULL)
                   ON CONFLICT(id) DO UPDATE SET label=excluded.label, updated_at=excluded.updated_at,
                       kind=excluded.kind, enabled=excluded.enabled, deleted_at=NULL",
                params![
                    outlet.outlet_id,
                    label,
                    observed_at,
                    outlet.kind.as_str(),
                    outlet.enabled,
                ],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    /// Keeps the current UDP projection limited to outlets that still exist
    /// in the active configuration while preserving the append-only evidence
    /// history for audit and later explanation.
    ///
    /// # Errors
    ///
    /// Returns an error when the projection transaction cannot be committed.
    pub fn sync_udp_current_outlets(&mut self, outlet_ids: &[&str]) -> Result<(), StoreError> {
        let configured = outlet_ids
            .iter()
            .copied()
            .collect::<std::collections::HashSet<_>>();
        let transaction = self.connection.transaction()?;
        {
            let mut statement =
                transaction.prepare("SELECT outlet_id FROM udp_capability_current")?;
            let existing = statement
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            for outlet_id in existing {
                if !configured.contains(outlet_id.as_str()) {
                    transaction.execute(
                        "DELETE FROM udp_capability_current WHERE outlet_id=?1",
                        [outlet_id],
                    )?;
                }
            }
        }
        transaction.commit()?;
        Ok(())
    }

    fn outlet_display(
        &self,
        outlet_id: &str,
    ) -> Result<Option<(String, HistoryOutletKind)>, StoreError> {
        let stored = self
            .connection
            .query_row(
                "SELECT label, kind FROM outlets WHERE id=?1",
                [outlet_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        stored
            .map(|(label, kind)| {
                Ok((
                    crate::history::sanitized_label(&label),
                    HistoryOutletKind::try_from(kind.as_str())
                        .map_err(StoreError::InvalidOutletKind)?,
                ))
            })
            .transpose()
    }

    /// Persists one sanitized probe and emits a state transition when a
    /// configured failure or recovery threshold is reached.
    ///
    /// # Errors
    ///
    /// Returns an error when the transaction cannot be read or committed.
    #[allow(clippy::too_many_lines)]
    pub fn record_probe(
        &mut self,
        outlet: &ProbeOutletConfig,
        result: &ProbeResult,
        failure_threshold: u32,
        recovery_threshold: u32,
    ) -> Result<Option<StateEvent>, StoreError> {
        let transaction = self.connection.transaction()?;
        let event = Self::record_probe_in_transaction(
            &transaction,
            outlet,
            result,
            failure_threshold,
            recovery_threshold,
        )?;
        transaction.commit()?;
        Ok(event)
    }

    #[allow(clippy::too_many_lines)]
    fn record_probe_in_transaction(
        transaction: &rusqlite::Transaction<'_>,
        outlet: &ProbeOutletConfig,
        result: &ProbeResult,
        failure_threshold: u32,
        recovery_threshold: u32,
    ) -> Result<Option<StateEvent>, StoreError> {
        let observed_at = canonical_timestamp(&result.observed_at)?;
        transaction.execute(
            r"INSERT INTO outlets(id, label, updated_at, enabled, deleted_at) VALUES (?1, ?2, ?3, 1, NULL)
               ON CONFLICT(id) DO UPDATE SET label=excluded.label, updated_at=excluded.updated_at,
                   enabled=1, deleted_at=NULL",
            params![
                outlet.id,
                crate::history::sanitized_label(&outlet.label),
                observed_at
            ],
        )?;
        let outlet_kind = transaction.query_row(
            "SELECT kind FROM outlets WHERE id=?1",
            [&outlet.id],
            |row| row.get::<_, String>(0),
        )?;
        transaction.execute(
            "INSERT INTO probe_samples(outlet_id, observed_at, port_reachable, status, http_status, latency_ms, error_code, successful_targets, total_targets, outlet_label, outlet_kind) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                outlet.id,
                observed_at,
                result.port_reachable,
                result.status.as_str(),
                result.http_status,
                result.latency_ms.map(|value| i64::try_from(value).unwrap_or(i64::MAX)),
                result
                    .error_code
                    .as_deref()
                    .map(crate::history::sanitized_code),
                result.successful_targets,
                result.total_targets,
                crate::history::sanitized_label(&outlet.label),
                outlet_kind,
            ],
        )?;

        let previous = transaction
            .query_row(
                "SELECT status, consecutive_successes, consecutive_failures FROM outlet_state WHERE outlet_id=?1",
                [&outlet.id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, u32>(1)?,
                        row.get::<_, u32>(2)?,
                    ))
                },
            )
            .optional()?;
        let previous = match previous {
            Some((status, successes, failures)) => StoredState {
                status: HealthStatus::try_from(status.as_str())
                    .map_err(StoreError::InvalidStatus)?,
                consecutive_successes: successes,
                consecutive_failures: failures,
            },
            None => StoredState {
                status: HealthStatus::Unknown,
                consecutive_successes: 0,
                consecutive_failures: 0,
            },
        };

        let (next_status, successes, failures) = next_state(
            &previous,
            result.status,
            failure_threshold,
            recovery_threshold,
        );
        transaction.execute(
            r"INSERT INTO outlet_state(outlet_id, status, consecutive_successes, consecutive_failures, updated_at)
               VALUES (?1, ?2, ?3, ?4, ?5)
               ON CONFLICT(outlet_id) DO UPDATE SET
                 status=excluded.status,
                 consecutive_successes=excluded.consecutive_successes,
                 consecutive_failures=excluded.consecutive_failures,
                 updated_at=excluded.updated_at",
            params![outlet.id, next_status.as_str(), successes, failures, observed_at],
        )?;

        let event = (previous.status != next_status).then(|| StateEvent {
            outlet_id: outlet.id.clone(),
            occurred_at: observed_at,
            from_status: previous.status,
            to_status: next_status,
            reason: result
                .error_code
                .as_deref()
                .map_or_else(|| "probe_result".into(), crate::history::sanitized_code),
        });
        if let Some(event) = &event {
            transaction.execute(
                "INSERT INTO state_events(outlet_id, occurred_at, from_status, to_status, reason, outlet_label, outlet_kind) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    event.outlet_id,
                    event.occurred_at,
                    event.from_status.as_str(),
                    event.to_status.as_str(),
                    crate::history::sanitized_code(&event.reason),
                    crate::history::sanitized_label(&outlet.label),
                    outlet_kind,
                ],
            )?;
        }
        Ok(event)
    }

    /// Projects the post-cycle health state without mutating `SQLite`. Guardian
    /// uses this to choose selectors before committing a generation, so a
    /// configuration invalidation can discard the whole late cycle.
    ///
    /// # Errors
    ///
    /// Returns an error when the current state cannot be read.
    pub fn project_probe_health(
        &self,
        observed: &[(ProbeOutletConfig, ProbeResult)],
        failure_threshold: u32,
        recovery_threshold: u32,
    ) -> Result<BTreeMap<String, OutletHealth>, StoreError> {
        let mut health = BTreeMap::new();
        for (outlet, result) in observed {
            let previous = self
                .connection
                .query_row(
                    "SELECT status, consecutive_successes, consecutive_failures FROM outlet_state WHERE outlet_id=?1",
                    [&outlet.id],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, u32>(1)?,
                            row.get::<_, u32>(2)?,
                        ))
                    },
                )
                .optional()?;
            let previous = match previous {
                Some((status, successes, failures)) => StoredState {
                    status: HealthStatus::try_from(status.as_str())
                        .map_err(StoreError::InvalidStatus)?,
                    consecutive_successes: successes,
                    consecutive_failures: failures,
                },
                None => StoredState {
                    status: HealthStatus::Unknown,
                    consecutive_successes: 0,
                    consecutive_failures: 0,
                },
            };
            let (status, _, _) = next_state(
                &previous,
                result.status,
                failure_threshold,
                recovery_threshold,
            );
            health.insert(
                outlet.id.clone(),
                OutletHealth {
                    status,
                    latency_ms: result.latency_ms,
                },
            );
        }
        Ok(health)
    }

    /// Commits every durable projection of one Guardian generation in a
    /// single `SQLite` transaction. The connection busy timeout and explicit
    /// pre-commit checks share the caller's absolute cycle deadline; dropping
    /// the transaction on any error leaves no partial probes, UDP projection,
    /// state events, or route switch.
    ///
    /// # Errors
    ///
    /// Returns `Deadline` when the batch cannot atomically commit before the
    /// supplied deadline, or the corresponding SQLite/validation error.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    pub fn commit_guardian_cycle_batch(
        &mut self,
        initial_udp: &[(String, String, UdpCapabilityEvidence)],
        observed: &[(ProbeOutletConfig, ProbeResult)],
        failure_threshold: u32,
        recovery_threshold: u32,
        route_event: Option<&RouteSwitchEvent>,
        deadline: Instant,
    ) -> Result<(), StoreError> {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(StoreError::Deadline)?;
        self.connection.busy_timeout(remaining)?;
        let result = (|| {
            let transaction = self.connection.transaction()?;
            let constrain_to_deadline = |transaction: &rusqlite::Transaction<'_>| {
                let remaining = deadline
                    .checked_duration_since(Instant::now())
                    .ok_or(StoreError::Deadline)?;
                transaction
                    .busy_timeout(remaining)
                    .map_err(StoreError::from)
            };
            for (outlet_id, label, evidence) in initial_udp {
                constrain_to_deadline(&transaction)?;
                let exists = transaction.query_row(
                    "SELECT EXISTS(SELECT 1 FROM udp_capability_current WHERE outlet_id=?1)",
                    [outlet_id],
                    |row| row.get::<_, bool>(0),
                )?;
                if !exists {
                    let observed_at = canonical_timestamp(&evidence.observed_at)?;
                    let generation = i64::try_from(evidence.configuration_generation)
                        .ok()
                        .filter(|generation| *generation != i64::MAX)
                        .ok_or(StoreError::InvalidUdpGeneration)?;
                    transaction.execute(
                        r"INSERT INTO outlets(id, label, updated_at) VALUES (?1, ?2, ?3)
                           ON CONFLICT(id) DO UPDATE SET label=excluded.label, updated_at=excluded.updated_at",
                        params![outlet_id, crate::history::sanitized_label(label), observed_at],
                    )?;
                    transaction.execute(
                        "INSERT INTO udp_capability_history(outlet_id, status, observed_at, evidence_version, probe_version, model_version, configuration_fingerprint, configuration_generation, reason_code) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                        params![
                            outlet_id,
                            evidence.status.as_str(),
                            observed_at,
                            evidence.evidence_version,
                            evidence.probe_version,
                            evidence.model_version,
                            evidence.configuration_fingerprint,
                            generation,
                            evidence.reason_code,
                        ],
                    )?;
                    let history_id = transaction.last_insert_rowid();
                    transaction.execute(
                        "INSERT INTO udp_capability_current(outlet_id, history_id) VALUES (?1, ?2)",
                        params![outlet_id, history_id],
                    )?;
                }
            }
            for (outlet, probe) in observed {
                constrain_to_deadline(&transaction)?;
                Self::record_probe_in_transaction(
                    &transaction,
                    outlet,
                    probe,
                    failure_threshold,
                    recovery_threshold,
                )?;
            }
            if let Some(event) = route_event {
                constrain_to_deadline(&transaction)?;
                let occurred_at = canonical_timestamp(&event.occurred_at)?;
                for outlet_id in event
                    .from_outlet
                    .iter()
                    .chain(std::iter::once(&event.to_outlet))
                {
                    transaction.execute(
                        "INSERT OR IGNORE INTO outlets(id, label, updated_at, kind, enabled) VALUES (?1, '已脱敏出口', ?2, 'unknown', 0)",
                        params![outlet_id, occurred_at],
                    )?;
                }
                let snapshot =
                    |outlet_id: &str| -> Result<Option<(String, HistoryOutletKind)>, StoreError> {
                        transaction
                            .query_row(
                                "SELECT label, kind FROM outlets WHERE id=?1",
                                [outlet_id],
                                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                            )
                            .optional()?
                            .map(|(label, kind)| {
                                Ok((
                                    crate::history::sanitized_label(&label),
                                    HistoryOutletKind::try_from(kind.as_str())
                                        .map_err(StoreError::InvalidOutletKind)?,
                                ))
                            })
                            .transpose()
                    };
                let from_snapshot = event
                    .from_outlet
                    .as_deref()
                    .map(snapshot)
                    .transpose()?
                    .flatten();
                let to_snapshot = snapshot(&event.to_outlet)?
                    .unwrap_or_else(|| (event.to_outlet.clone(), HistoryOutletKind::Unknown));
                transaction.execute(
                    "INSERT INTO route_switches(occurred_at, from_outlet, to_outlet, mode, reason, duration_ms, from_label, from_kind, to_label, to_kind) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                    params![
                        occurred_at,
                        event.from_outlet,
                        event.to_outlet,
                        crate::history::sanitized_code(&event.mode),
                        crate::history::sanitized_code(&event.reason),
                        i64::try_from(event.duration_ms).unwrap_or(i64::MAX),
                        from_snapshot.as_ref().map(|value| value.0.as_str()),
                        from_snapshot.as_ref().map(|value| value.1.as_str()),
                        to_snapshot.0,
                        to_snapshot.1.as_str(),
                    ],
                )?;
            }
            constrain_to_deadline(&transaction)?;
            transaction.commit()?;
            Ok(())
        })();
        let reset = self.connection.busy_timeout(Duration::from_secs(5));
        match (result, reset) {
            (Err(_), _) if Instant::now() >= deadline => Err(StoreError::Deadline),
            (Err(error), _) => Err(error),
            (Ok(()), Err(error)) => Err(StoreError::Database(error)),
            (Ok(()), Ok(())) => Ok(()),
        }
    }

    /// Returns aggregate availability and latency summaries for all outlets.
    ///
    /// # Errors
    ///
    /// Returns an error when stored rows cannot be queried or decoded.
    pub fn summaries(&self) -> Result<Vec<OutletSummary>, StoreError> {
        let mut statement = self.connection.prepare(
            r"
            SELECT
              o.id,
              o.label,
              COUNT(p.id),
              COALESCE(SUM(CASE WHEN p.status != 'down' THEN 1 ELSE 0 END), 0),
              COALESCE(SUM(CASE WHEN p.status = 'down' THEN 1 ELSE 0 END), 0),
              COALESCE(100.0 * SUM(CASE WHEN p.status != 'down' THEN 1 ELSE 0 END) / NULLIF(COUNT(p.id), 0), 0.0),
              AVG(CASE WHEN p.status != 'down' THEN p.latency_ms END),
              COALESCE(s.status, 'unknown'),
              MAX(p.observed_at)
            FROM outlets o
            LEFT JOIN probe_samples p ON p.outlet_id = o.id
            LEFT JOIN outlet_state s ON s.outlet_id = o.id
            GROUP BY o.id, o.label, s.status
            ORDER BY o.id
            ",
        )?;
        let rows = statement.query_map([], |row| {
            let samples = u64::try_from(row.get::<_, i64>(2)?).unwrap_or(0);
            let successful_samples = u64::try_from(row.get::<_, i64>(3)?).unwrap_or(0);
            let status = row.get::<_, String>(7)?;
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                samples,
                successful_samples,
                u64::try_from(row.get::<_, i64>(4)?).unwrap_or(0),
                row.get::<_, f64>(5)?,
                row.get::<_, Option<f64>>(6)?,
                status,
                row.get::<_, Option<String>>(8)?,
            ))
        })?;
        rows.map(|row| {
            let (id, label, samples, successful, failed, availability, average, status, last_seen) =
                row?;
            Ok(OutletSummary {
                outlet_id: id,
                label,
                samples,
                successful_samples: successful,
                failed_samples: failed,
                availability_percent: availability,
                average_latency_ms: average,
                last_status: HealthStatus::try_from(status.as_str())
                    .map_err(StoreError::InvalidStatus)?,
                last_observed_at: last_seen,
            })
        })
        .collect()
    }

    /// Returns the newest sanitized latency samples in chronological order.
    ///
    /// # Errors
    ///
    /// Returns an error when stored rows cannot be queried or decoded.
    pub fn recent_samples(&self, limit: u32) -> Result<Vec<LatencySample>, StoreError> {
        let mut statement = self.connection.prepare(
            r"
            SELECT outlet_id, observed_at, port_reachable, status, latency_ms, error_code, successful_targets, total_targets
            FROM (
              SELECT id, outlet_id, observed_at, port_reachable, status, latency_ms, error_code, successful_targets, total_targets
              FROM probe_samples
              ORDER BY id DESC
              LIMIT ?1
            )
            ORDER BY id ASC
            ",
        )?;
        let rows = statement.query_map([limit], |row| {
            let status = row.get::<_, String>(3)?;
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, bool>(2)?,
                status,
                row.get::<_, Option<i64>>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, u32>(6)?,
                row.get::<_, u32>(7)?,
            ))
        })?;
        rows.map(|row| {
            let (
                outlet_id,
                observed_at,
                port_reachable,
                status,
                latency_ms,
                error_code,
                successful_targets,
                total_targets,
            ) = row?;
            Ok(LatencySample {
                outlet_id,
                observed_at,
                port_reachable,
                status: HealthStatus::try_from(status.as_str())
                    .map_err(StoreError::InvalidStatus)?,
                latency_ms: latency_ms.and_then(|value| u64::try_from(value).ok()),
                error_code,
                successful_targets,
                total_targets,
            })
        })
        .collect()
    }

    /// Returns the newest state transitions, newest first.
    ///
    /// # Errors
    ///
    /// Returns an error when stored rows cannot be queried or decoded.
    pub fn recent_events(&self, limit: u32) -> Result<Vec<StateEvent>, StoreError> {
        let mut statement = self.connection.prepare(
            r"
            SELECT outlet_id, occurred_at, from_status, to_status, reason
            FROM state_events
            ORDER BY id DESC
            LIMIT ?1
            ",
        )?;
        let rows = statement.query_map([limit], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?;
        rows.map(|row| {
            let (outlet_id, occurred_at, from_status, to_status, reason) = row?;
            Ok(StateEvent {
                outlet_id,
                occurred_at,
                from_status: HealthStatus::try_from(from_status.as_str())
                    .map_err(StoreError::InvalidStatus)?,
                to_status: HealthStatus::try_from(to_status.as_str())
                    .map_err(StoreError::InvalidStatus)?,
                reason,
            })
        })
        .collect()
    }

    /// Persists a sanitized selector change after the controller confirms it.
    ///
    /// # Errors
    ///
    /// Returns an error when the event cannot be inserted.
    pub fn record_route_switch(&self, event: &RouteSwitchEvent) -> Result<(), StoreError> {
        let occurred_at = canonical_timestamp(&event.occurred_at)?;
        for outlet_id in event
            .from_outlet
            .iter()
            .chain(std::iter::once(&event.to_outlet))
        {
            self.connection.execute(
                "INSERT OR IGNORE INTO outlets(id, label, updated_at, kind, enabled) VALUES (?1, '已脱敏出口', ?2, 'unknown', 0)",
                params![outlet_id, occurred_at],
            )?;
        }
        let from_snapshot = event
            .from_outlet
            .as_ref()
            .map(|outlet_id| self.outlet_display(outlet_id))
            .transpose()?
            .flatten();
        let to_snapshot = self
            .outlet_display(&event.to_outlet)?
            .unwrap_or_else(|| (event.to_outlet.clone(), HistoryOutletKind::Unknown));
        self.connection.execute(
            "INSERT INTO route_switches(occurred_at, from_outlet, to_outlet, mode, reason, duration_ms, from_label, from_kind, to_label, to_kind) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                occurred_at,
                event.from_outlet,
                event.to_outlet,
                crate::history::sanitized_code(&event.mode),
                crate::history::sanitized_code(&event.reason),
                i64::try_from(event.duration_ms).unwrap_or(i64::MAX),
                from_snapshot.as_ref().map(|snapshot| snapshot.0.as_str()),
                from_snapshot.as_ref().map(|snapshot| snapshot.1.as_str()),
                to_snapshot.0,
                to_snapshot.1.as_str(),
            ],
        )?;
        Ok(())
    }

    /// Returns the newest confirmed selector changes, newest first.
    ///
    /// # Errors
    ///
    /// Returns an error when stored rows cannot be queried.
    pub fn recent_route_switches(&self, limit: u32) -> Result<Vec<RouteSwitchEvent>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT occurred_at, from_outlet, to_outlet, mode, reason, duration_ms FROM route_switches ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = statement.query_map([limit], |row| {
            Ok(RouteSwitchEvent {
                occurred_at: row.get(0)?,
                from_outlet: row.get(1)?,
                to_outlet: row.get(2)?,
                mode: row.get(3)?,
                reason: row.get(4)?,
                duration_ms: u64::try_from(row.get::<_, i64>(5)?).unwrap_or(u64::MAX),
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    /// Persists a sanitized, versioned UDP capability conclusion and updates
    /// the current summary without changing the independent TCP health state.
    ///
    /// # Errors
    ///
    /// Returns an error when the evidence transaction cannot be committed.
    pub fn record_udp_capability(
        &mut self,
        outlet_id: &str,
        label: &str,
        evidence: &UdpCapabilityEvidence,
    ) -> Result<(), StoreError> {
        let observed_at = canonical_timestamp(&evidence.observed_at)?;
        let configuration_generation = i64::try_from(evidence.configuration_generation)
            .ok()
            .filter(|generation| *generation != i64::MAX)
            .ok_or(StoreError::InvalidUdpGeneration)?;
        let transaction = self.connection.transaction()?;
        transaction.execute(
            r"INSERT INTO outlets(id, label, updated_at) VALUES (?1, ?2, ?3)
               ON CONFLICT(id) DO UPDATE SET label=excluded.label, updated_at=excluded.updated_at",
            params![
                outlet_id,
                crate::history::sanitized_label(label),
                observed_at
            ],
        )?;
        transaction.execute(
            "INSERT INTO udp_capability_history(outlet_id, status, observed_at, evidence_version, probe_version, model_version, configuration_fingerprint, configuration_generation, reason_code) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                outlet_id,
                evidence.status.as_str(),
                observed_at,
                evidence.evidence_version,
                evidence.probe_version,
                evidence.model_version,
                evidence.configuration_fingerprint,
                configuration_generation,
                evidence.reason_code,
            ],
        )?;
        let history_id = transaction.last_insert_rowid();
        transaction.execute(
            r"INSERT INTO udp_capability_current(outlet_id, history_id) VALUES (?1, ?2)
               ON CONFLICT(outlet_id) DO UPDATE SET history_id=excluded.history_id",
            params![outlet_id, history_id],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Creates the initial auditable unknown conclusion when an outlet has no
    /// UDP evidence yet. Existing conclusions and history are left untouched.
    ///
    /// # Errors
    ///
    /// Returns an error when the current summary cannot be checked or written.
    pub fn ensure_udp_capability(
        &mut self,
        outlet_id: &str,
        label: &str,
        evidence: &UdpCapabilityEvidence,
    ) -> Result<(), StoreError> {
        let exists = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM udp_capability_current WHERE outlet_id=?1)",
            [outlet_id],
            |row| row.get::<_, bool>(0),
        )?;
        if !exists {
            self.record_udp_capability(outlet_id, label, evidence)?;
        }
        Ok(())
    }

    /// Returns the newest UDP conclusion for every outlet.
    ///
    /// # Errors
    ///
    /// Returns an error when stored evidence cannot be queried or decoded.
    pub fn udp_capabilities(&self) -> Result<Vec<UdpCapabilityEvidence>, StoreError> {
        let mut statement = self.connection.prepare(
            r"SELECT h.outlet_id, h.status, h.observed_at, h.evidence_version,
                     h.probe_version, h.model_version, h.configuration_fingerprint,
                     h.configuration_generation, h.reason_code
              FROM udp_capability_current c
              JOIN udp_capability_history h ON h.id = c.history_id
              ORDER BY h.outlet_id",
        )?;
        let rows = statement.query_map([], read_udp_capability_row)?;
        rows.map(|row| decode_udp_capability(row?)).collect()
    }

    /// Returns append-only UDP evidence for one outlet, newest first.
    ///
    /// # Errors
    ///
    /// Returns an error when stored evidence cannot be queried or decoded.
    pub fn udp_capability_history(
        &self,
        outlet_id: &str,
        limit: u32,
    ) -> Result<Vec<UdpCapabilityEvidence>, StoreError> {
        let mut statement = self.connection.prepare(
            r"SELECT outlet_id, status, observed_at, evidence_version,
                     probe_version, model_version, configuration_fingerprint,
                     configuration_generation, reason_code
              FROM udp_capability_history
              WHERE outlet_id=?1
              ORDER BY id DESC
              LIMIT ?2",
        )?;
        let rows = statement.query_map(params![outlet_id, limit], read_udp_capability_row)?;
        rows.map(|row| decode_udp_capability(row?)).collect()
    }

    /// Queries a bounded, sanitized history page and its fixed metrics.
    ///
    /// Availability is `(healthy + degraded) / all probe samples`. Latency
    /// percentiles use nearest-rank over non-down samples with a latency. A
    /// failure is a `down` interval overlapping the window; intervals are
    /// truncated at the window boundaries and same-time transitions use row ID.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid timestamps or unreadable stored values.
    pub fn query_history(
        &self,
        filter: &HistoryFilter,
        now: &str,
    ) -> Result<HistoryResponse, StoreError> {
        let end = parse_timestamp(now)?;
        let start = filter.window.start(end);
        let start_text = start.to_rfc3339_opts(SecondsFormat::Millis, true);
        let end_text = end.to_rfc3339_opts(SecondsFormat::Millis, true);
        let page_size = filter.bounded_page_size();
        let total_count = self.history_record_count(filter, &start_text, &end_text)?;
        let total_pages_u64 = total_count.div_ceil(u64::from(page_size));
        let total_pages = u32::try_from(total_pages_u64).unwrap_or(u32::MAX);
        let page = if total_pages == 0 {
            0
        } else {
            filter.page.min(total_pages.saturating_sub(1))
        };
        let metrics = self.history_metrics(filter, &start_text, &end_text)?;
        let outlets = self.history_outlet_catalogue(&start_text, &end_text)?;
        let records = self.history_records(
            filter,
            &start_text,
            &end_text,
            page_size,
            page.saturating_mul(page_size),
        )?;
        Ok(HistoryResponse {
            window_start: start_text,
            window_end: end_text,
            metrics,
            outlets,
            records,
            total_count,
            page,
            total_pages,
            next_page: (page.saturating_add(1) < total_pages).then(|| page.saturating_add(1)),
            retention_days: self.retention_days()?,
        })
    }

    /// Streams the filtered, sanitized event projection to a CSV file. Memory
    /// is bounded to one database page and no raw configuration fields are read.
    ///
    /// # Errors
    ///
    /// Returns an error when the destination cannot be written or queried.
    pub fn export_history_csv(
        &self,
        destination: impl AsRef<Path>,
        filter: &HistoryFilter,
        now: &str,
    ) -> Result<u64, StoreError> {
        let end = parse_timestamp(now)?;
        let start = filter.window.start(end);
        let start_text = start.to_rfc3339_opts(SecondsFormat::Millis, true);
        let end_text = end.to_rfc3339_opts(SecondsFormat::Millis, true);
        let file = fs::File::create(destination)?;
        let mut writer = BufWriter::new(file);
        writer.write_all(b"event_type,occurred_at,outlet_id,outlet_label,outlet_kind,deleted,status,from_status,to_status,latency_ms,from_outlet_id,to_outlet_id,mode,reason,duration_ms\r\n")?;
        let mut written = 0_u64;
        let (sql, values) = history_record_query(filter, &start_text, &end_text, u32::MAX, 0);
        let mut statement = self.connection.prepare(&sql)?;
        let rows = statement.query_map(params_from_iter(values), read_history_record)?;
        for row in rows {
            let record = decode_history_record(row?)?;
            let values = [
                record.event_type.as_str().to_owned(),
                record.occurred_at,
                record.outlet_id,
                record.outlet_label,
                record.outlet_kind.as_str().to_owned(),
                record.deleted.to_string(),
                record
                    .status
                    .map_or_else(String::new, |value| value.as_str().into()),
                record
                    .from_status
                    .map_or_else(String::new, |value| value.as_str().into()),
                record
                    .to_status
                    .map_or_else(String::new, |value| value.as_str().into()),
                record
                    .latency_ms
                    .map_or_else(String::new, |value| value.to_string()),
                record.from_outlet_id.unwrap_or_default(),
                record.to_outlet_id.unwrap_or_default(),
                record.mode.unwrap_or_default(),
                record.reason.unwrap_or_default(),
                record
                    .duration_ms
                    .map_or_else(String::new, |value| value.to_string()),
            ];
            let line = values
                .iter()
                .map(|value| crate::history::csv_cell(value))
                .collect::<Vec<_>>()
                .join(",");
            writer.write_all(line.as_bytes())?;
            writer.write_all(b"\r\n")?;
            written = written.saturating_add(1);
        }
        writer.flush()?;
        Ok(written)
    }

    /// Reads the local retention policy.
    ///
    /// # Errors
    ///
    /// Returns an error when the setting cannot be read.
    pub fn retention_days(&self) -> Result<u32, StoreError> {
        self.connection
            .query_row(
                "SELECT retention_days FROM history_settings WHERE id=1",
                [],
                |row| row.get(0),
            )
            .map_err(StoreError::from)
    }

    /// Updates retention and removes expired data without deleting the latest
    /// state transition for an outlet, ongoing failures, or current UDP evidence.
    ///
    /// # Errors
    ///
    /// Returns an error for an out-of-range value or failed transaction.
    pub fn set_retention_days(&mut self, days: u32, now: &str) -> Result<u64, StoreError> {
        if !(1..=3650).contains(&days) {
            return Err(StoreError::InvalidRetention(days));
        }
        let now = parse_timestamp(now)?;
        let cutoff = now - chrono::Duration::days(i64::from(days));
        let cutoff = cutoff.to_rfc3339_opts(SecondsFormat::Millis, true);
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "UPDATE history_settings SET retention_days=?1 WHERE id=1",
            [days],
        )?;
        let mut removed = 0_u64;
        removed = removed.saturating_add(
            u64::try_from(transaction.execute(
                "DELETE FROM probe_samples WHERE observed_at < ?1",
                [&cutoff],
            )?)
            .unwrap_or(u64::MAX),
        );
        removed = removed.saturating_add(
            u64::try_from(transaction.execute(
                r"DELETE FROM state_events
               WHERE occurred_at < ?1
                 AND id NOT IN (SELECT MAX(id) FROM state_events GROUP BY outlet_id)",
                [&cutoff],
            )?)
            .unwrap_or(u64::MAX),
        );
        removed = removed.saturating_add(
            u64::try_from(transaction.execute(
                "DELETE FROM route_switches WHERE occurred_at < ?1",
                [&cutoff],
            )?)
            .unwrap_or(u64::MAX),
        );
        removed = removed.saturating_add(
            u64::try_from(transaction.execute(
                r"DELETE FROM udp_capability_history
               WHERE observed_at < ?1
                 AND id NOT IN (SELECT history_id FROM udp_capability_current)",
                [&cutoff],
            )?)
            .unwrap_or(u64::MAX),
        );
        transaction.commit()?;
        Ok(removed)
    }

    fn history_outlet_catalogue(
        &self,
        start: &str,
        end: &str,
    ) -> Result<Vec<HistoryOutletOption>, StoreError> {
        let (candidates, _) =
            self.history_metric_candidates(&HistoryFilter::default(), start, end)?;
        Ok(candidates
            .into_iter()
            .map(|(outlet_id, candidate)| HistoryOutletOption {
                outlet_id,
                label: candidate.label,
                kind: candidate.kind,
                deleted: candidate.deleted,
            })
            .collect())
    }

    #[allow(clippy::too_many_lines)]
    fn history_metric_candidates(
        &self,
        filter: &HistoryFilter,
        start: &str,
        end: &str,
    ) -> Result<MetricCandidateSet, StoreError> {
        let mut candidates = BTreeMap::new();
        let mut switch_counts = BTreeMap::<String, u64>::new();
        if filter.event_type.is_none() || filter.event_type == Some(HistoryEventType::Probe) {
            let (predicate, values) = sample_filter(filter, start, end);
            let sql = format!(
                "SELECT p.outlet_id, MAX(p.outlet_label), MAX(p.outlet_kind), MAX(CASE WHEN o.deleted_at IS NULL THEN 0 ELSE 1 END) FROM probe_samples p JOIN outlets o ON o.id=p.outlet_id WHERE {predicate} GROUP BY p.outlet_id"
            );
            let mut statement = self.connection.prepare(&sql)?;
            let rows = statement.query_map(params_from_iter(values), read_metric_candidate)?;
            for row in rows {
                insert_metric_candidate(&mut candidates, row?)?;
            }
        }

        if filter.event_type.is_none() || filter.event_type == Some(HistoryEventType::State) {
            let (predicate, values) =
                record_predicate(filter, "s", "occurred_at", "to_status", start, end, false);
            let sql = format!(
                "SELECT s.outlet_id, MAX(s.outlet_label), MAX(s.outlet_kind), MAX(CASE WHEN o.deleted_at IS NULL THEN 0 ELSE 1 END) FROM state_events s JOIN outlets o ON o.id=s.outlet_id WHERE {predicate} GROUP BY s.outlet_id"
            );
            let mut statement = self.connection.prepare(&sql)?;
            let rows = statement.query_map(params_from_iter(values), read_metric_candidate)?;
            for row in rows {
                insert_metric_candidate(&mut candidates, row?)?;
            }

            if matches!(filter.status, None | Some(HealthStatus::Down)) {
                let mut clauses = vec![
                    "s.occurred_at < ?",
                    "s.to_status = 'down'",
                    "s.id = (SELECT s2.id FROM state_events s2 WHERE s2.outlet_id=s.outlet_id AND s2.occurred_at < ? ORDER BY s2.occurred_at DESC, s2.id DESC LIMIT 1)",
                ];
                let mut values = vec![Value::Text(start.into()), Value::Text(start.into())];
                if let Some(outlet_id) = &filter.outlet_id {
                    clauses.push("s.outlet_id = ?");
                    values.push(Value::Text(outlet_id.clone()));
                }
                if let Some(kind) = filter.kind {
                    clauses.push("s.outlet_kind = ?");
                    values.push(Value::Text(kind.as_str().into()));
                }
                let sql = format!(
                    "SELECT s.outlet_id, s.outlet_label, s.outlet_kind, CASE WHEN o.deleted_at IS NULL THEN 0 ELSE 1 END FROM state_events s JOIN outlets o ON o.id=s.outlet_id WHERE {}",
                    clauses.join(" AND ")
                );
                let mut statement = self.connection.prepare(&sql)?;
                let rows = statement.query_map(params_from_iter(values), read_metric_candidate)?;
                for row in rows {
                    insert_metric_candidate(&mut candidates, row?)?;
                }
            }
        }

        if (filter.event_type.is_none() || filter.event_type == Some(HistoryEventType::RouteSwitch))
            && filter.status.is_none()
        {
            let (predicate, values) =
                record_predicate(filter, "r", "occurred_at", "", start, end, true);
            let sql = format!(
                r"SELECT r.from_outlet, COALESCE(r.from_label, fo.label, '已脱敏出口'),
                          COALESCE(r.from_kind, fo.kind, 'unknown'),
                          CASE WHEN fo.id IS NULL OR fo.deleted_at IS NOT NULL THEN 1 ELSE 0 END,
                          r.to_outlet, COALESCE(NULLIF(r.to_label,''), too.label, '已脱敏出口'),
                          COALESCE(NULLIF(r.to_kind,'unknown'), too.kind, 'unknown'),
                          CASE WHEN too.id IS NULL OR too.deleted_at IS NOT NULL THEN 1 ELSE 0 END
                     FROM route_switches r
                     LEFT JOIN outlets fo ON fo.id=r.from_outlet
                     LEFT JOIN outlets too ON too.id=r.to_outlet
                    WHERE {predicate} ORDER BY r.occurred_at, r.id"
            );
            let mut statement = self.connection.prepare(&sql)?;
            let rows = statement.query_map(params_from_iter(values), |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, bool>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, bool>(7)?,
                ))
            })?;
            for row in rows {
                let (
                    from_id,
                    from_label,
                    from_kind,
                    from_deleted,
                    to_id,
                    to_label,
                    to_kind,
                    to_deleted,
                ) = row?;
                if let Some(from_id) = from_id {
                    add_switch_participant(
                        filter,
                        &mut candidates,
                        &mut switch_counts,
                        from_id,
                        &from_label,
                        &from_kind,
                        from_deleted,
                    )?;
                }
                add_switch_participant(
                    filter,
                    &mut candidates,
                    &mut switch_counts,
                    to_id,
                    &to_label,
                    &to_kind,
                    to_deleted,
                )?;
            }
        }
        Ok((candidates, switch_counts))
    }

    fn history_record_count(
        &self,
        filter: &HistoryFilter,
        start: &str,
        end: &str,
    ) -> Result<u64, StoreError> {
        let (sql, values) = history_record_union(filter, start, end);
        self.connection
            .query_row(
                &format!("SELECT COUNT(*) FROM ({sql})"),
                params_from_iter(values),
                |row| Ok(u64::try_from(row.get::<_, i64>(0)?).unwrap_or(0)),
            )
            .map_err(StoreError::from)
    }

    fn history_metrics(
        &self,
        filter: &HistoryFilter,
        start: &str,
        end: &str,
    ) -> Result<Vec<HistoryMetric>, StoreError> {
        let (candidates, switch_counts) = self.history_metric_candidates(filter, start, end)?;
        let include_probes =
            filter.event_type.is_none() || filter.event_type == Some(HistoryEventType::Probe);
        let include_failures = (filter.event_type.is_none()
            || filter.event_type == Some(HistoryEventType::State))
            && matches!(filter.status, None | Some(HealthStatus::Down));
        candidates
            .into_iter()
            .map(|(outlet_id, candidate)| {
                let (samples, online, latency_count) = if include_probes {
                    self.sample_aggregate(filter, start, end, &outlet_id)?
                } else {
                    (0, 0, 0)
                };
                let p50 =
                    self.percentile_latency(filter, start, end, &outlet_id, latency_count, 50)?;
                let p95 =
                    self.percentile_latency(filter, start, end, &outlet_id, latency_count, 95)?;
                let (failures, duration, ongoing) = if include_failures {
                    self.failure_metrics(&outlet_id, start, end)?
                } else {
                    (0, 0, false)
                };
                Ok(HistoryMetric {
                    outlet_id: outlet_id.clone(),
                    label: candidate.label,
                    kind: candidate.kind,
                    deleted: candidate.deleted,
                    sample_count: samples,
                    online_samples: online,
                    availability_percent: if samples == 0 {
                        0.0
                    } else {
                        let online = u32::try_from(online).unwrap_or(u32::MAX);
                        let samples = u32::try_from(samples).unwrap_or(u32::MAX);
                        100.0 * f64::from(online) / f64::from(samples)
                    },
                    p50_latency_ms: p50,
                    p95_latency_ms: p95,
                    failure_count: failures,
                    failure_duration_seconds: duration,
                    ongoing_failure: ongoing,
                    confirmed_route_switches: switch_counts.get(&outlet_id).copied().unwrap_or(0),
                })
            })
            .collect()
    }

    fn sample_aggregate(
        &self,
        filter: &HistoryFilter,
        start: &str,
        end: &str,
        outlet_id: &str,
    ) -> Result<(u64, u64, u64), StoreError> {
        let (mut predicate, mut values) = sample_filter(filter, start, end);
        predicate.push_str(" AND p.outlet_id=?");
        values.push(Value::Text(outlet_id.into()));
        self.connection
            .query_row(
                &format!(
                    "SELECT COUNT(*), COALESCE(SUM(CASE WHEN p.status IN ('healthy','degraded') THEN 1 ELSE 0 END),0), COALESCE(SUM(CASE WHEN p.status != 'down' AND p.latency_ms IS NOT NULL THEN 1 ELSE 0 END),0) FROM probe_samples p WHERE {predicate}"
                ),
                params_from_iter(values),
                |row| {
                    Ok((
                        u64::try_from(row.get::<_, i64>(0)?).unwrap_or(0),
                        u64::try_from(row.get::<_, i64>(1)?).unwrap_or(0),
                        u64::try_from(row.get::<_, i64>(2)?).unwrap_or(0),
                    ))
                },
            )
            .map_err(StoreError::from)
    }

    fn percentile_latency(
        &self,
        filter: &HistoryFilter,
        start: &str,
        end: &str,
        outlet_id: &str,
        count: u64,
        percentile: u64,
    ) -> Result<Option<u64>, StoreError> {
        if count == 0 {
            return Ok(None);
        }
        let rank = count.saturating_mul(percentile).div_ceil(100).max(1);
        let (mut predicate, mut values) = sample_filter(filter, start, end);
        predicate.push_str(" AND p.outlet_id=?");
        values.push(Value::Text(outlet_id.into()));
        values.push(Value::Integer(
            i64::try_from(rank.saturating_sub(1)).unwrap_or(i64::MAX),
        ));
        let sql = format!(
            "SELECT p.latency_ms FROM probe_samples p WHERE {predicate} AND p.status != 'down' AND p.latency_ms IS NOT NULL ORDER BY p.latency_ms, p.id LIMIT 1 OFFSET ?"
        );
        self.connection
            .query_row(&sql, params_from_iter(values), |row| {
                row.get::<_, Option<i64>>(0)
            })
            .map(|value| value.and_then(|latency| u64::try_from(latency).ok()))
            .map_err(StoreError::from)
    }

    fn failure_metrics(
        &self,
        outlet_id: &str,
        start: &str,
        end: &str,
    ) -> Result<(u64, u64, bool), StoreError> {
        let start_time = parse_timestamp(start)?;
        let end_time = parse_timestamp(end)?;
        let prior = self.connection.query_row(
            "SELECT to_status FROM state_events WHERE outlet_id=?1 AND occurred_at < ?2 ORDER BY occurred_at DESC, id DESC LIMIT 1",
            params![outlet_id, start],
            |row| row.get::<_, String>(0),
        ).optional()?;
        let mut down_since = prior
            .as_deref()
            .is_some_and(|status| status == "down")
            .then_some(start_time);
        let mut failures = u64::from(down_since.is_some());
        let mut duration = 0_u64;
        let mut statement = self.connection.prepare(
            "SELECT occurred_at, to_status FROM state_events WHERE outlet_id=?1 AND occurred_at >= ?2 AND occurred_at <= ?3 ORDER BY occurred_at, id",
        )?;
        let rows = statement.query_map(params![outlet_id, start, end], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        for row in rows {
            let (occurred_at, status) = row?;
            let occurred_at = parse_timestamp(&occurred_at)?;
            if status == "down" && down_since.is_none() {
                down_since = Some(occurred_at);
                failures = failures.saturating_add(1);
            } else if status != "down"
                && let Some(since) = down_since.take()
            {
                duration = duration.saturating_add(
                    u64::try_from((occurred_at - since).num_seconds().max(0)).unwrap_or(u64::MAX),
                );
            }
        }
        let ongoing = down_since.is_some();
        if let Some(since) = down_since {
            duration = duration.saturating_add(
                u64::try_from((end_time - since).num_seconds().max(0)).unwrap_or(u64::MAX),
            );
        }
        Ok((failures, duration, ongoing))
    }

    fn history_records(
        &self,
        filter: &HistoryFilter,
        start: &str,
        end: &str,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<HistoryRecord>, StoreError> {
        let (sql, values) = history_record_query(filter, start, end, limit, offset);
        let mut statement = self.connection.prepare(&sql)?;
        let rows = statement.query_map(params_from_iter(values), read_history_record)?;
        rows.map(|row| decode_history_record(row?)).collect()
    }
}

#[derive(Debug)]
struct MetricCandidate {
    label: String,
    kind: HistoryOutletKind,
    deleted: bool,
}

type MetricCandidateSet = (BTreeMap<String, MetricCandidate>, BTreeMap<String, u64>);

fn read_metric_candidate(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<(String, String, String, bool)> {
    Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
}

fn insert_metric_candidate(
    candidates: &mut BTreeMap<String, MetricCandidate>,
    stored: (String, String, String, bool),
) -> Result<(), StoreError> {
    let (outlet_id, label, kind, deleted) = stored;
    candidates.entry(outlet_id).or_insert(MetricCandidate {
        label: crate::history::sanitized_label(&label),
        kind: HistoryOutletKind::try_from(kind.as_str()).map_err(StoreError::InvalidOutletKind)?,
        deleted,
    });
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn add_switch_participant(
    filter: &HistoryFilter,
    candidates: &mut BTreeMap<String, MetricCandidate>,
    switch_counts: &mut BTreeMap<String, u64>,
    outlet_id: String,
    label: &str,
    kind: &str,
    deleted: bool,
) -> Result<(), StoreError> {
    let kind = HistoryOutletKind::try_from(kind).map_err(StoreError::InvalidOutletKind)?;
    if filter
        .outlet_id
        .as_ref()
        .is_some_and(|selected| selected != &outlet_id)
        || filter.kind.is_some_and(|selected| selected != kind)
    {
        return Ok(());
    }
    candidates
        .entry(outlet_id.clone())
        .or_insert(MetricCandidate {
            label: crate::history::sanitized_label(label),
            kind,
            deleted,
        });
    let count = switch_counts.entry(outlet_id).or_default();
    *count = count.saturating_add(1);
    Ok(())
}

type StoredHistoryRecord = (
    i64,
    i64,
    String,
    String,
    String,
    String,
    String,
    bool,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<i64>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<i64>,
);

fn read_history_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredHistoryRecord> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
        row.get(10)?,
        row.get(11)?,
        row.get(12)?,
        row.get(13)?,
        row.get(14)?,
        row.get(15)?,
        row.get(16)?,
    ))
}

fn decode_history_record(row: StoredHistoryRecord) -> Result<HistoryRecord, StoreError> {
    let event_type = match row.2.as_str() {
        "probe" => HistoryEventType::Probe,
        "state" => HistoryEventType::State,
        "route_switch" => HistoryEventType::RouteSwitch,
        other => return Err(StoreError::InvalidStatus(other.into())),
    };
    let decode_status = |status: Option<String>| {
        status
            .map(|value| HealthStatus::try_from(value.as_str()).map_err(StoreError::InvalidStatus))
            .transpose()
    };
    Ok(HistoryRecord {
        event_type,
        occurred_at: row.3,
        outlet_id: row.4,
        outlet_label: crate::history::sanitized_label(&row.5),
        outlet_kind: HistoryOutletKind::try_from(row.6.as_str())
            .map_err(StoreError::InvalidOutletKind)?,
        deleted: row.7,
        status: decode_status(row.8)?,
        from_status: decode_status(row.9)?,
        to_status: decode_status(row.10)?,
        latency_ms: row.11.and_then(|value| u64::try_from(value).ok()),
        from_outlet_id: row.12,
        to_outlet_id: row.13,
        mode: row.14.map(|value| crate::history::sanitized_code(&value)),
        reason: row.15.map(|value| crate::history::sanitized_code(&value)),
        duration_ms: row.16.and_then(|value| u64::try_from(value).ok()),
    })
}

fn sample_filter(filter: &HistoryFilter, start: &str, end: &str) -> (String, Vec<Value>) {
    let mut clauses = vec!["p.observed_at >= ?", "p.observed_at <= ?"];
    let mut values = vec![Value::Text(start.into()), Value::Text(end.into())];
    if let Some(outlet_id) = &filter.outlet_id {
        clauses.push("p.outlet_id = ?");
        values.push(Value::Text(outlet_id.clone()));
    }
    if let Some(kind) = filter.kind {
        clauses.push("p.outlet_kind = ?");
        values.push(Value::Text(kind.as_str().into()));
    }
    if let Some(status) = filter.status {
        clauses.push("p.status = ?");
        values.push(Value::Text(status.as_str().into()));
    }
    (clauses.join(" AND "), values)
}

fn history_record_query(
    filter: &HistoryFilter,
    start: &str,
    end: &str,
    limit: u32,
    offset: u32,
) -> (String, Vec<Value>) {
    let (union, mut values) = history_record_union(filter, start, end);
    values.push(Value::Integer(i64::from(limit)));
    values.push(Value::Integer(i64::from(offset)));
    (
        format!(
            "SELECT * FROM ({union}) ORDER BY occurred_at DESC, source_order DESC, source_id DESC LIMIT ? OFFSET ?"
        ),
        values,
    )
}

fn history_record_union(filter: &HistoryFilter, start: &str, end: &str) -> (String, Vec<Value>) {
    let mut branches = Vec::new();
    let mut values = Vec::new();
    if filter.event_type.is_none() || filter.event_type == Some(HistoryEventType::Probe) {
        let (predicate, branch_values) =
            record_predicate(filter, "p", "observed_at", "status", start, end, false);
        branches.push(format!(
            r"SELECT 1 source_order, p.id source_id, 'probe' event_type, p.observed_at occurred_at,
                      p.outlet_id, p.outlet_label, p.outlet_kind,
                      CASE WHEN o.deleted_at IS NULL THEN 0 ELSE 1 END deleted,
                      p.status status, NULL from_status, NULL to_status, p.latency_ms,
                      NULL from_outlet_id, NULL to_outlet_id, NULL mode, p.error_code reason, NULL duration_ms
                 FROM probe_samples p JOIN outlets o ON o.id=p.outlet_id WHERE {predicate}"
        ));
        values.extend(branch_values);
    }
    if filter.event_type.is_none() || filter.event_type == Some(HistoryEventType::State) {
        let (predicate, branch_values) =
            record_predicate(filter, "s", "occurred_at", "to_status", start, end, false);
        branches.push(format!(
            r"SELECT 2 source_order, s.id source_id, 'state' event_type, s.occurred_at,
                      s.outlet_id, s.outlet_label, s.outlet_kind,
                      CASE WHEN o.deleted_at IS NULL THEN 0 ELSE 1 END deleted,
                      NULL status, s.from_status, s.to_status, NULL latency_ms,
                      NULL from_outlet_id, NULL to_outlet_id, NULL mode, s.reason, NULL duration_ms
                 FROM state_events s JOIN outlets o ON o.id=s.outlet_id WHERE {predicate}"
        ));
        values.extend(branch_values);
    }
    if (filter.event_type.is_none() || filter.event_type == Some(HistoryEventType::RouteSwitch))
        && filter.status.is_none()
    {
        let (predicate, branch_values) =
            record_predicate(filter, "r", "occurred_at", "", start, end, true);
        branches.push(format!(
            r"SELECT 3 source_order, r.id source_id, 'route_switch' event_type, r.occurred_at,
                      r.to_outlet outlet_id, r.to_label outlet_label, r.to_kind outlet_kind,
                      CASE WHEN o.deleted_at IS NULL THEN 0 ELSE 1 END deleted,
                      NULL status, NULL from_status, NULL to_status, NULL latency_ms,
                      r.from_outlet from_outlet_id, r.to_outlet to_outlet_id, r.mode, r.reason, r.duration_ms
                 FROM route_switches r LEFT JOIN outlets o ON o.id=r.to_outlet WHERE {predicate}"
        ));
        values.extend(branch_values);
    }
    if branches.is_empty() {
        branches.push(
            "SELECT 0 source_order, 0 source_id, 'probe' event_type, '' occurred_at, '' outlet_id, '' outlet_label, 'unknown' outlet_kind, 0 deleted, NULL status, NULL from_status, NULL to_status, NULL latency_ms, NULL from_outlet_id, NULL to_outlet_id, NULL mode, NULL reason, NULL duration_ms WHERE 0"
                .into(),
        );
    }
    (branches.join(" UNION ALL "), values)
}

fn record_predicate(
    filter: &HistoryFilter,
    alias: &str,
    time_column: &str,
    status_column: &str,
    start: &str,
    end: &str,
    route_switch: bool,
) -> (String, Vec<Value>) {
    let mut clauses = vec![
        format!("{alias}.{time_column} >= ?"),
        format!("{alias}.{time_column} <= ?"),
    ];
    let mut values = vec![Value::Text(start.into()), Value::Text(end.into())];
    if route_switch {
        if let Some((participant_predicate, participant_values)) =
            route_switch_participant_predicate(filter, alias)
        {
            clauses.push(participant_predicate);
            values.extend(participant_values);
        }
    } else {
        if let Some(outlet_id) = &filter.outlet_id {
            clauses.push(format!("{alias}.outlet_id = ?"));
            values.push(Value::Text(outlet_id.clone()));
        }
        if let Some(kind) = filter.kind {
            clauses.push(format!("{alias}.outlet_kind = ?"));
            values.push(Value::Text(kind.as_str().into()));
        }
        if let Some(status) = filter.status {
            clauses.push(format!("{alias}.{status_column} = ?"));
            values.push(Value::Text(status.as_str().into()));
        }
    }
    (clauses.join(" AND "), values)
}

fn route_switch_participant_predicate(
    filter: &HistoryFilter,
    alias: &str,
) -> Option<(String, Vec<Value>)> {
    match (&filter.outlet_id, filter.kind) {
        (Some(outlet_id), Some(kind)) => Some((
            format!(
                "(({alias}.from_outlet = ? AND {alias}.from_kind = ?) OR ({alias}.to_outlet = ? AND {alias}.to_kind = ?))"
            ),
            vec![
                Value::Text(outlet_id.clone()),
                Value::Text(kind.as_str().into()),
                Value::Text(outlet_id.clone()),
                Value::Text(kind.as_str().into()),
            ],
        )),
        (Some(outlet_id), None) => Some((
            format!("({alias}.from_outlet = ? OR {alias}.to_outlet = ?)"),
            vec![
                Value::Text(outlet_id.clone()),
                Value::Text(outlet_id.clone()),
            ],
        )),
        (None, Some(kind)) => Some((
            format!("({alias}.from_kind = ? OR {alias}.to_kind = ?)"),
            vec![
                Value::Text(kind.as_str().into()),
                Value::Text(kind.as_str().into()),
            ],
        )),
        (None, None) => None,
    }
}

fn parse_timestamp(value: &str) -> Result<DateTime<Utc>, StoreError> {
    DateTime::parse_from_rfc3339(value)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .map_err(|_| StoreError::InvalidTimestamp(value.into()))
}

fn canonical_timestamp(value: &str) -> Result<String, StoreError> {
    parse_timestamp(value).map(|timestamp| timestamp.to_rfc3339_opts(SecondsFormat::Millis, true))
}

fn sanitize_persisted_history_labels(
    transaction: &rusqlite::Transaction<'_>,
) -> Result<(), StoreError> {
    for (table, id_column, label_column) in [
        ("outlets", "rowid", "label"),
        ("probe_samples", "id", "outlet_label"),
        ("state_events", "id", "outlet_label"),
        ("route_switches", "id", "from_label"),
        ("route_switches", "id", "to_label"),
    ] {
        let sql = format!("SELECT {id_column}, {label_column} FROM {table}");
        let mut statement = transaction.prepare(&sql)?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, Option<String>>(1)?))
        })?;
        let values = rows.collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        for (id, label) in values {
            if let Some(label) = label {
                transaction.execute(
                    &format!("UPDATE {table} SET {label_column}=?1 WHERE {id_column}=?2"),
                    params![crate::history::sanitized_label(&label), id],
                )?;
            }
        }
    }
    Ok(())
}

fn canonicalize_persisted_timestamps(
    transaction: &rusqlite::Transaction<'_>,
) -> Result<(), StoreError> {
    for (table, id_column, timestamp_column) in [
        ("outlets", "rowid", "updated_at"),
        ("probe_samples", "id", "observed_at"),
        ("outlet_state", "rowid", "updated_at"),
        ("state_events", "id", "occurred_at"),
        ("route_switches", "id", "occurred_at"),
        ("udp_capability_history", "id", "observed_at"),
    ] {
        let sql = format!("SELECT {id_column}, {timestamp_column} FROM {table}");
        let mut statement = transaction.prepare(&sql)?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })?;
        let values = rows.collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        for (id, timestamp) in values {
            transaction.execute(
                &format!("UPDATE {table} SET {timestamp_column}=?1 WHERE {id_column}=?2"),
                params![canonical_timestamp(&timestamp)?, id],
            )?;
        }
    }
    Ok(())
}

type StoredUdpCapability = (
    String,
    String,
    String,
    u32,
    String,
    u32,
    String,
    i64,
    String,
);

fn read_udp_capability_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredUdpCapability> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
    ))
}

fn decode_udp_capability(row: StoredUdpCapability) -> Result<UdpCapabilityEvidence, StoreError> {
    Ok(UdpCapabilityEvidence {
        outlet_id: row.0,
        status: UdpCapabilityStatus::try_from(row.1.as_str())
            .map_err(StoreError::InvalidUdpCapability)?,
        observed_at: row.2,
        evidence_version: row.3,
        probe_version: row.4,
        model_version: row.5,
        configuration_fingerprint: row.6,
        configuration_generation: u64::try_from(row.7).unwrap_or(u64::MAX),
        reason_code: row.8,
    })
}

fn ensure_probe_column(
    connection: &rusqlite::Transaction<'_>,
    column_name: &str,
    definition: &str,
) -> Result<(), rusqlite::Error> {
    ensure_column(connection, "probe_samples", column_name, definition)
}

fn ensure_column(
    connection: &rusqlite::Transaction<'_>,
    table_name: &str,
    column_name: &str,
    definition: &str,
) -> Result<(), rusqlite::Error> {
    let exists = connection.query_row(
        &format!("SELECT EXISTS(SELECT 1 FROM pragma_table_info('{table_name}') WHERE name=?1)"),
        [column_name],
        |row| row.get::<_, bool>(0),
    )?;
    if !exists {
        connection.execute(
            &format!("ALTER TABLE {table_name} ADD COLUMN {column_name} {definition}"),
            [],
        )?;
    }
    Ok(())
}

fn next_state(
    previous: &StoredState,
    observed: HealthStatus,
    failure_threshold: u32,
    recovery_threshold: u32,
) -> (HealthStatus, u32, u32) {
    if previous.status == HealthStatus::Unknown {
        return (
            observed,
            u32::from(observed != HealthStatus::Down),
            u32::from(observed == HealthStatus::Down),
        );
    }
    if observed == HealthStatus::Down {
        let failures = previous.consecutive_failures.saturating_add(1);
        let status = if previous.status == HealthStatus::Down || failures >= failure_threshold {
            HealthStatus::Down
        } else {
            previous.status
        };
        return (status, 0, failures);
    }

    let successes = previous.consecutive_successes.saturating_add(1);
    let status = if previous.status == HealthStatus::Down && successes < recovery_threshold {
        HealthStatus::Down
    } else {
        observed
    };
    (status, successes, 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn outlet() -> ProbeOutletConfig {
        ProbeOutletConfig {
            id: "a".into(),
            label: "A".into(),
            proxy_url: "socks5h://127.0.0.1:16666".into(),
            probe_url: "https://example.com".into(),
            degraded_latency_ms: 2_500,
            enabled: true,
        }
    }

    fn result(status: HealthStatus, timestamp: &str) -> ProbeResult {
        ProbeResult {
            outlet_id: "a".into(),
            label: "A".into(),
            observed_at: timestamp.into(),
            port_reachable: true,
            status,
            http_status: Some(204),
            latency_ms: Some(10),
            error_code: (status == HealthStatus::Down).then(|| "timeout".into()),
            successful_targets: u32::from(status != HealthStatus::Down),
            total_targets: 1,
        }
    }

    #[test]
    fn locked_sqlite_batch_obeys_deadline_and_rolls_back_every_projection() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("guardian.db");
        let mut store = GuardianStore::open(&path).expect("store");
        let locker = Connection::open(&path).expect("locker");
        locker
            .execute_batch("BEGIN IMMEDIATE")
            .expect("hold writer lock");
        let observed = vec![(
            outlet(),
            result(HealthStatus::Healthy, "2026-01-01T00:00:00Z"),
        )];
        let started = Instant::now();

        let error = store
            .commit_guardian_cycle_batch(
                &[],
                &observed,
                2,
                2,
                None,
                Instant::now() + Duration::from_millis(120),
            )
            .expect_err("locked durable batch must time out");
        let elapsed = started.elapsed();
        locker.execute_batch("ROLLBACK").expect("unlock");

        assert!(matches!(error, StoreError::Deadline), "error={error:?}");
        assert!(elapsed < Duration::from_millis(300), "elapsed={elapsed:?}");
        assert!(store.recent_samples(10).expect("samples").is_empty());
        assert!(store.recent_events(10).expect("events").is_empty());
        assert!(store.recent_route_switches(10).expect("routes").is_empty());
        assert!(store.udp_capabilities().expect("udp").is_empty());
    }

    #[test]
    fn applies_failure_and_recovery_thresholds() {
        let mut store = GuardianStore::open_in_memory().expect("store");
        let outlet = outlet();
        let initial = store
            .record_probe(
                &outlet,
                &result(HealthStatus::Healthy, "2026-01-01T00:00:00Z"),
                2,
                3,
            )
            .expect("initial event")
            .expect("transition");
        assert_eq!(initial.to_status, HealthStatus::Healthy);

        let first_failure = store
            .record_probe(
                &outlet,
                &result(HealthStatus::Down, "2026-01-01T00:00:01Z"),
                2,
                3,
            )
            .expect("first failure");
        assert!(first_failure.is_none());
        let second_failure = store
            .record_probe(
                &outlet,
                &result(HealthStatus::Down, "2026-01-01T00:00:02Z"),
                2,
                3,
            )
            .expect("second failure")
            .expect("down transition");
        assert_eq!(second_failure.to_status, HealthStatus::Down);

        for second in 3..5 {
            assert!(
                store
                    .record_probe(
                        &outlet,
                        &result(
                            HealthStatus::Healthy,
                            &format!("2026-01-01T00:00:0{second}Z")
                        ),
                        2,
                        3,
                    )
                    .expect("recovery sample")
                    .is_none()
            );
        }
        let recovered = store
            .record_probe(
                &outlet,
                &result(HealthStatus::Healthy, "2026-01-01T00:00:05Z"),
                2,
                3,
            )
            .expect("third recovery")
            .expect("recovery transition");
        assert_eq!(recovered.to_status, HealthStatus::Healthy);

        let summaries = store.summaries().expect("summaries");
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].samples, 6);
        assert_eq!(summaries[0].successful_samples, 4);
        assert_eq!(summaries[0].failed_samples, 2);
        assert!((summaries[0].availability_percent - 66.666).abs() < 0.01);
        assert_eq!(summaries[0].last_status, HealthStatus::Healthy);
    }

    #[test]
    fn records_sanitized_route_switches() {
        let store = GuardianStore::open_in_memory().expect("store");
        let event = RouteSwitchEvent {
            occurred_at: "2026-01-01T00:00:00Z".into(),
            from_outlet: Some("subscription-a".into()),
            to_outlet: "local-client".into(),
            mode: "priority".into(),
            reason: "priority_policy".into(),
            duration_ms: 12,
        };
        store.record_route_switch(&event).expect("record");
        assert_eq!(
            store.recent_route_switches(1).expect("list")[0].reason,
            "priority_policy"
        );
    }

    #[test]
    fn udp_current_summary_updates_without_losing_audit_history_or_tcp_state() {
        let mut store = GuardianStore::open_in_memory().expect("store");
        let outlet = outlet();
        store
            .record_probe(
                &outlet,
                &result(HealthStatus::Healthy, "2026-01-01T00:00:00Z"),
                2,
                3,
            )
            .expect("TCP probe");
        for (status, observed_at, reason_code) in [
            (
                UdpCapabilityStatus::Unknown,
                "2026-01-01T00:00:01Z",
                "not_yet_validated",
            ),
            (
                UdpCapabilityStatus::TcpOnly,
                "2026-01-01T00:00:02Z",
                "socks5_udp_associate_rejected",
            ),
            (
                UdpCapabilityStatus::Supported,
                "2026-01-01T00:00:03Z",
                "controlled_udp_echo_succeeded",
            ),
        ] {
            store
                .record_udp_capability(
                    "a",
                    "A",
                    &UdpCapabilityEvidence {
                        outlet_id: "a".into(),
                        status,
                        observed_at: observed_at.into(),
                        evidence_version: 1,
                        probe_version: "test-probe-v1".into(),
                        model_version: 1,
                        configuration_fingerprint: "test-fingerprint".into(),
                        configuration_generation: 1,
                        reason_code: reason_code.into(),
                    },
                )
                .expect("record UDP evidence");
        }

        let current = store.udp_capabilities().expect("current");
        assert_eq!(current.len(), 1);
        assert_eq!(current[0].status, UdpCapabilityStatus::Supported);
        let history = store.udp_capability_history("a", 10).expect("history");
        assert_eq!(history.len(), 3);
        assert_eq!(history[0].status, UdpCapabilityStatus::Supported);
        assert_eq!(history[2].status, UdpCapabilityStatus::Unknown);
        assert_eq!(
            store.summaries().expect("TCP summary")[0].last_status,
            HealthStatus::Healthy,
            "UDP evidence must not alter Guardian TCP health"
        );
        store
            .sync_udp_current_outlets(&[])
            .expect("remove deleted outlet from current projection");
        assert!(
            store
                .udp_capabilities()
                .expect("current after removal")
                .is_empty()
        );
        assert_eq!(
            store
                .udp_capability_history("a", 10)
                .expect("audit history after removal")
                .len(),
            3,
            "removing a current projection must preserve UDP audit history"
        );
        assert_eq!(
            store.summaries().expect("TCP summary after removal")[0].last_status,
            HealthStatus::Healthy,
            "removing a UDP projection must preserve TCP history"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn high_bit_configuration_survives_restart_for_generator_and_guardian_selector() {
        let outlet = (10_000..u16::MAX)
            .map(|port| crate::OutletConfig {
                id: "high-bit-local".into(),
                label: "High bit local".into(),
                enabled: true,
                kind: crate::OutletKind::LocalProxy {
                    endpoint: format!("socks5://127.0.0.1:{port}"),
                },
            })
            .find(|candidate| {
                let digest = Sha256::digest(serde_json::to_vec(candidate).expect("serialize"));
                digest[0] & 0x80 != 0
            })
            .expect("a high-bit SHA-256 fixture");
        let raw_digest = Sha256::digest(serde_json::to_vec(&outlet).expect("serialize"));
        assert_ne!(raw_digest[0] & 0x80, 0, "fixture must exercise high bit");

        let mut evidence = crate::unknown_udp_evidence(&outlet, "test");
        evidence.status = UdpCapabilityStatus::Supported;
        assert!(i64::try_from(evidence.configuration_generation).is_ok());
        assert_ne!(evidence.configuration_generation, i64::MAX as u64);
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("guardian.db");
        {
            let mut store = GuardianStore::open(&path).expect("create store");
            store
                .record_udp_capability(&outlet.id, &outlet.label, &evidence)
                .expect("persist supported evidence");
        }

        let store = GuardianStore::open(&path).expect("restart store");
        let restored = store.udp_capabilities().expect("restored evidence");
        assert_eq!(
            restored[0].configuration_generation,
            evidence.configuration_generation
        );
        assert_eq!(
            crate::current_udp_status(&outlet, restored.first()),
            UdpCapabilityStatus::Supported
        );
        let mut config = crate::PrivateRoutingConfig::default();
        config.entry = crate::EntryConfig {
            host: "127.0.0.1".into(),
            port: 45_123,
        };
        config.controller_port = 45_124;
        config.outlets = vec![outlet.clone()];
        let capabilities = restored
            .iter()
            .map(|item| (item.outlet_id.clone(), item.clone()))
            .collect();
        let (yaml, _) = crate::generate_mihomo_config_with_udp_capabilities(
            &config,
            &crate::ResolvedSubscriptionUrls::new(),
            "test-secret",
            &capabilities,
        )
        .expect("generate after restart");
        let document = serde_yaml::from_str::<serde_yaml::Value>(&yaml).expect("runtime yaml");
        let udp_candidates = document
            .get("proxy-groups")
            .and_then(serde_yaml::Value::as_sequence)
            .and_then(|groups| {
                groups.iter().find(|group| {
                    group.get("name").and_then(serde_yaml::Value::as_str)
                        == Some(crate::UDP_SELECTOR)
                })
            })
            .and_then(|group| group.get("proxies"))
            .and_then(serde_yaml::Value::as_sequence)
            .expect("UDP selector candidates")
            .iter()
            .filter_map(serde_yaml::Value::as_str)
            .collect::<Vec<_>>();
        assert_eq!(
            udp_candidates,
            [
                crate::outlet_proxy_name(&outlet.id),
                crate::FAIL_CLOSED_PROXY.into()
            ]
        );
        assert_eq!(
            crate::guardian_cycle::udp_selector_target(&config, Some(&outlet.id), &restored),
            crate::outlet_proxy_name(&outlet.id)
        );
        drop(store);

        let connection = Connection::open(&path).expect("open legacy-clamped evidence");
        connection
            .execute(
                "UPDATE udp_capability_history SET configuration_generation=?1",
                [i64::MAX],
            )
            .expect("seed previously clamped generation");
        drop(connection);
        let store = GuardianStore::open(&path).expect("restart legacy-clamped store");
        let clamped = store.udp_capabilities().expect("clamped evidence");
        assert_eq!(clamped[0].configuration_generation, i64::MAX as u64);
        assert_eq!(
            crate::current_udp_status(&outlet, clamped.first()),
            UdpCapabilityStatus::Unknown
        );
        assert_eq!(
            crate::guardian_cycle::udp_selector_target(&config, Some(&outlet.id), &clamped),
            crate::FAIL_CLOSED_PROXY
        );
    }

    fn history_snapshot(id: &str, label: &str) -> HistoryOutletSnapshot {
        HistoryOutletSnapshot {
            outlet_id: id.into(),
            label: label.into(),
            kind: HistoryOutletKind::LocalProxy,
            enabled: true,
        }
    }

    #[test]
    fn history_metrics_use_fixed_percentiles_and_window_truncated_failures() {
        let mut store = GuardianStore::open_in_memory().expect("store");
        let outlet_id = "test-outlet-7f3a";
        store
            .sync_history_outlets(
                &[history_snapshot(outlet_id, "测试出口")],
                "2026-02-01T00:00:00Z",
            )
            .expect("sync outlet");
        for (timestamp, status, latency) in [
            ("2026-01-31T23:01:00Z", "healthy", 10),
            ("2026-01-31T23:02:00Z", "degraded", 20),
            ("2026-01-31T23:03:00Z", "down", 30),
            ("2026-01-31T23:04:00Z", "healthy", 40),
        ] {
            store
                .connection
                .execute(
                    "INSERT INTO probe_samples(outlet_id, observed_at, status, latency_ms, outlet_label, outlet_kind) VALUES (?1, ?2, ?3, ?4, '测试出口', 'local_proxy')",
                    params![outlet_id, timestamp, status, latency],
                )
                .expect("sample");
        }
        for (timestamp, from, to) in [
            ("2026-01-31T22:50:00Z", "healthy", "down"),
            ("2026-01-31T23:30:00Z", "down", "healthy"),
            ("2026-01-31T23:35:00Z", "healthy", "down"),
            ("2026-01-31T23:35:00Z", "down", "healthy"),
            ("2026-01-31T23:40:00Z", "healthy", "down"),
        ] {
            store
                .connection
                .execute(
                    "INSERT INTO state_events(outlet_id, occurred_at, from_status, to_status, reason, outlet_label, outlet_kind) VALUES (?1, ?2, ?3, ?4, 'synthetic', '测试出口', 'local_proxy')",
                    params![outlet_id, timestamp, from, to],
                )
                .expect("state event");
        }
        let response = store
            .query_history(
                &HistoryFilter {
                    window: crate::HistoryWindow::OneHour,
                    ..HistoryFilter::default()
                },
                "2026-02-01T00:00:00Z",
            )
            .expect("history");
        let metric = response.metrics.first().expect("metric");
        assert_eq!(metric.sample_count, 4);
        assert_eq!(metric.online_samples, 3);
        assert!((metric.availability_percent - 75.0).abs() < f64::EPSILON);
        assert_eq!(metric.p50_latency_ms, Some(20));
        assert_eq!(metric.p95_latency_ms, Some(40));
        assert_eq!(metric.failure_count, 3);
        assert_eq!(metric.failure_duration_seconds, 3_000);
        assert!(metric.ongoing_failure);
        let status_filtered = store
            .query_history(
                &HistoryFilter {
                    window: crate::HistoryWindow::OneHour,
                    status: Some(HealthStatus::Down),
                    ..HistoryFilter::default()
                },
                "2026-02-01T00:00:00Z",
            )
            .expect("status-filtered events");
        assert_eq!(status_filtered.metrics[0].sample_count, 1);
        assert_eq!(status_filtered.metrics[0].online_samples, 0);
        assert!(status_filtered.metrics[0].availability_percent.abs() < f64::EPSILON);
        assert!(status_filtered.records.iter().all(|record| {
            record.status == Some(HealthStatus::Down)
                || record.to_status == Some(HealthStatus::Down)
        }));
        let state_only = store
            .query_history(
                &HistoryFilter {
                    window: crate::HistoryWindow::OneHour,
                    event_type: Some(HistoryEventType::State),
                    status: Some(HealthStatus::Down),
                    ..HistoryFilter::default()
                },
                "2026-02-01T00:00:00Z",
            )
            .expect("state-only intersection");
        assert_eq!(state_only.metrics[0].sample_count, 0);
        assert_eq!(state_only.metrics[0].failure_count, 3);
        assert_eq!(state_only.metrics[0].confirmed_route_switches, 0);
    }

    #[test]
    fn confirmed_switch_metrics_use_full_filter_not_current_page() {
        let mut store = GuardianStore::open_in_memory().expect("store");
        let first = HistoryOutletSnapshot {
            outlet_id: "switch-subscription-a1".into(),
            label: "订阅出口".into(),
            kind: HistoryOutletKind::Subscription,
            enabled: true,
        };
        let second = history_snapshot("switch-local-b2", "本地出口");
        store
            .sync_history_outlets(&[first.clone(), second.clone()], "2026-02-01T00:00:00Z")
            .expect("catalogue");
        for minute in 1..=3 {
            store
                .record_route_switch(&RouteSwitchEvent {
                    occurred_at: "2026-02-01T00:01:00Z".into(),
                    from_outlet: Some(if minute % 2 == 0 {
                        second.outlet_id.clone()
                    } else {
                        first.outlet_id.clone()
                    }),
                    to_outlet: if minute % 2 == 0 {
                        first.outlet_id.clone()
                    } else {
                        second.outlet_id.clone()
                    },
                    mode: "priority".into(),
                    reason: "confirmed".into(),
                    duration_ms: minute,
                })
                .expect("confirmed switch");
        }
        let response = store
            .query_history(
                &HistoryFilter {
                    window: crate::HistoryWindow::OneHour,
                    event_type: Some(HistoryEventType::RouteSwitch),
                    outlet_id: Some(first.outlet_id.clone()),
                    kind: Some(HistoryOutletKind::Subscription),
                    page_size: 1,
                    ..HistoryFilter::default()
                },
                "2026-02-01T01:00:00Z",
            )
            .expect("switch history");
        assert_eq!(response.records.len(), 1);
        assert_eq!(response.total_count, 3);
        assert_eq!(response.total_pages, 3);
        assert_eq!(response.metrics.len(), 1);
        assert_eq!(response.metrics[0].outlet_id, first.outlet_id);
        assert_eq!(response.metrics[0].confirmed_route_switches, 3);
        assert_eq!(response.metrics[0].sample_count, 0);
        assert_eq!(response.metrics[0].failure_count, 0);
        let ordered = store
            .query_history(
                &HistoryFilter {
                    window: crate::HistoryWindow::OneHour,
                    event_type: Some(HistoryEventType::RouteSwitch),
                    outlet_id: Some(first.outlet_id),
                    kind: Some(HistoryOutletKind::Subscription),
                    ..HistoryFilter::default()
                },
                "2026-02-01T01:00:00Z",
            )
            .expect("same-time switch order");
        assert_eq!(
            ordered
                .records
                .iter()
                .map(|record| record.duration_ms)
                .collect::<Vec<_>>(),
            [Some(3), Some(2), Some(1)]
        );
    }

    #[test]
    fn route_switch_filters_match_one_participant_across_records_metrics_and_csv() {
        let mut store = GuardianStore::open_in_memory().expect("store");
        let local_id = "switch-local-a";
        let subscription_id = "switch-subscription-b";
        let local = history_snapshot(local_id, "Local A");
        let subscription = HistoryOutletSnapshot {
            outlet_id: subscription_id.into(),
            label: "Subscription B".into(),
            kind: HistoryOutletKind::Subscription,
            enabled: true,
        };
        store
            .sync_history_outlets(&[local, subscription], "2026-02-01T00:00:00Z")
            .expect("catalogue");
        store
            .record_route_switch(&RouteSwitchEvent {
                occurred_at: "2026-02-01T00:01:00Z".into(),
                from_outlet: Some(local_id.into()),
                to_outlet: subscription_id.into(),
                mode: "priority".into(),
                reason: "confirmed".into(),
                duration_ms: 1,
            })
            .expect("cross-kind switch");

        let cases = [
            (
                "cross-participant-mismatch",
                Some(local_id),
                Some(HistoryOutletKind::Subscription),
                0,
                None,
            ),
            (
                "local-participant",
                Some(local_id),
                Some(HistoryOutletKind::LocalProxy),
                1,
                Some(local_id),
            ),
            (
                "subscription-participant",
                Some(subscription_id),
                Some(HistoryOutletKind::Subscription),
                1,
                Some(subscription_id),
            ),
            ("outlet-only", Some(local_id), None, 1, Some(local_id)),
            (
                "kind-only",
                None,
                Some(HistoryOutletKind::Subscription),
                1,
                Some(subscription_id),
            ),
        ];
        let directory = tempfile::tempdir().expect("tempdir");
        for (name, outlet_id, kind, expected_count, expected_metric_id) in cases {
            let filter = HistoryFilter {
                window: crate::HistoryWindow::OneHour,
                outlet_id: outlet_id.map(str::to_owned),
                kind,
                event_type: Some(HistoryEventType::RouteSwitch),
                ..HistoryFilter::default()
            };
            let history = store
                .query_history(&filter, "2026-02-01T01:00:00Z")
                .expect("filtered history");
            assert_eq!(history.total_count, expected_count, "{name} total");
            assert_eq!(
                history.records.len(),
                usize::try_from(expected_count).expect("small fixture count"),
                "{name} records"
            );
            assert_eq!(history.outlets.len(), 2, "{name} historical catalogue");
            match expected_metric_id {
                Some(expected_metric_id) => {
                    assert_eq!(history.metrics.len(), 1, "{name} metric count");
                    assert_eq!(history.metrics[0].outlet_id, expected_metric_id, "{name}");
                    assert_eq!(
                        history.metrics[0].confirmed_route_switches, 1,
                        "{name} switch metric"
                    );
                }
                None => assert!(history.metrics.is_empty(), "{name} metrics"),
            }

            let csv_path = directory.path().join(format!("{name}.csv"));
            let csv_count = store
                .export_history_csv(&csv_path, &filter, "2026-02-01T01:00:00Z")
                .expect("filtered CSV");
            assert_eq!(csv_count, expected_count, "{name} CSV count");
            let csv = fs::read_to_string(csv_path).expect("CSV contents");
            assert_eq!(
                csv.lines().count(),
                usize::try_from(expected_count).expect("small fixture count") + 1,
                "{name} CSV rows"
            );
        }
    }

    #[test]
    fn ongoing_pre_window_failure_without_samples_remains_visible_after_retention() {
        let mut store = GuardianStore::open_in_memory().expect("store");
        let outlet_id = "ongoing-tombstone-f4";
        store
            .sync_history_outlets(
                &[history_snapshot(outlet_id, "持续故障出口")],
                "2026-02-10T00:00:00Z",
            )
            .expect("catalogue");
        store.connection.execute(
            "INSERT INTO state_events(outlet_id, occurred_at, from_status, to_status, reason, outlet_label, outlet_kind) VALUES (?1, '2026-02-01T00:00:00.000Z', 'healthy', 'down', 'synthetic', '持续故障出口', 'local_proxy')",
            [outlet_id],
        ).expect("pre-window down");
        store
            .set_retention_days(1, "2026-02-10T00:00:00Z")
            .expect("retention");
        store
            .sync_history_outlets(&[], "2026-02-10T00:01:00Z")
            .expect("delete outlet");
        let history = store
            .query_history(
                &HistoryFilter {
                    window: crate::HistoryWindow::OneHour,
                    event_type: Some(HistoryEventType::State),
                    ..HistoryFilter::default()
                },
                "2026-02-10T01:00:00Z",
            )
            .expect("ongoing history");
        assert_eq!(history.records.len(), 0);
        assert_eq!(history.metrics.len(), 1);
        assert_eq!(history.metrics[0].sample_count, 0);
        assert_eq!(history.metrics[0].failure_count, 1);
        assert_eq!(history.metrics[0].failure_duration_seconds, 3_600);
        assert!(history.metrics[0].ongoing_failure);
        assert!(history.metrics[0].deleted);
        assert_eq!(history.outlets.len(), 1);
        assert_eq!(history.outlets[0].outlet_id, outlet_id);
        assert!(history.outlets[0].deleted);
    }

    #[test]
    fn filtered_total_counts_union_and_clamps_page_after_cleanup() {
        let mut store = GuardianStore::open_in_memory().expect("store");
        let outlet_id = "total-outlet-c8";
        store
            .sync_history_outlets(
                &[history_snapshot(outlet_id, "总数出口")],
                "2026-02-01T00:00:00Z",
            )
            .expect("catalogue");
        store.connection.execute(
            "INSERT INTO probe_samples(outlet_id, observed_at, status, outlet_label, outlet_kind) VALUES (?1, '2026-02-01T00:01:00.000Z', 'healthy', '总数出口', 'local_proxy')",
            [outlet_id],
        ).expect("probe");
        store.connection.execute(
            "INSERT INTO state_events(outlet_id, occurred_at, from_status, to_status, reason, outlet_label, outlet_kind) VALUES (?1, '2026-02-01T00:02:00.000Z', 'unknown', 'healthy', 'synthetic', '总数出口', 'local_proxy')",
            [outlet_id],
        ).expect("state");
        store
            .record_route_switch(&RouteSwitchEvent {
                occurred_at: "2026-02-01T00:03:00Z".into(),
                from_outlet: None,
                to_outlet: outlet_id.into(),
                mode: "priority".into(),
                reason: "confirmed".into(),
                duration_ms: 3,
            })
            .expect("switch");
        let filter = HistoryFilter {
            window: crate::HistoryWindow::ThirtyDays,
            page: 99,
            page_size: 2,
            ..HistoryFilter::default()
        };
        let before = store
            .query_history(&filter, "2026-02-10T00:00:00Z")
            .expect("union total");
        assert_eq!(before.total_count, 3);
        assert_eq!(before.total_pages, 2);
        assert_eq!(before.page, 1);
        assert_eq!(before.records.len(), 1);
        store
            .set_retention_days(1, "2026-02-10T00:00:00Z")
            .expect("cleanup");
        let after = store
            .query_history(&filter, "2026-02-10T00:00:00Z")
            .expect("clamped total");
        assert_eq!(after.total_count, 1, "latest state evidence is retained");
        assert_eq!(after.total_pages, 1);
        assert_eq!(after.page, 0);
        assert_eq!(after.records.len(), 1);
    }

    #[test]
    fn history_snapshots_survive_rename_reorder_disable_and_delete() {
        let mut store = GuardianStore::open_in_memory().expect("store");
        let outlet_id = "stable-outlet-91b2";
        let mut probe = outlet();
        probe.id = outlet_id.into();
        probe.label = "旧名称".into();
        let mut first = result(HealthStatus::Healthy, "2026-02-01T00:01:00Z");
        first.outlet_id = outlet_id.into();
        first.label = probe.label.clone();
        store
            .sync_history_outlets(
                &[history_snapshot(outlet_id, "旧名称")],
                "2026-02-01T00:00:00Z",
            )
            .expect("initial catalogue");
        store
            .record_probe(&probe, &first, 1, 1)
            .expect("old sample");
        let mut renamed = history_snapshot(outlet_id, "新名称");
        renamed.enabled = false;
        store
            .sync_history_outlets(&[renamed], "2026-02-01T00:02:00Z")
            .expect("rename and disable");
        probe.label = "新名称".into();
        let mut second = result(HealthStatus::Healthy, "2026-02-01T00:03:00Z");
        second.outlet_id = outlet_id.into();
        second.label = probe.label.clone();
        store
            .record_probe(&probe, &second, 1, 1)
            .expect("new sample");
        store
            .sync_history_outlets(&[], "2026-02-01T00:04:00Z")
            .expect("delete catalogue item");
        let history = store
            .query_history(
                &HistoryFilter {
                    outlet_id: Some(outlet_id.into()),
                    ..HistoryFilter::default()
                },
                "2026-02-01T01:00:00Z",
            )
            .expect("history after delete");
        let probe_labels = history
            .records
            .iter()
            .filter(|record| record.event_type == HistoryEventType::Probe)
            .map(|record| record.outlet_label.as_str())
            .collect::<Vec<_>>();
        assert_eq!(probe_labels, ["新名称", "旧名称"]);
        assert!(history.records.iter().all(|record| record.deleted));
        assert!(history.metrics[0].deleted);
    }

    #[test]
    fn csv_export_is_filter_consistent_and_neutralizes_injection() {
        let mut store = GuardianStore::open_in_memory().expect("store");
        let outlet_id = "csv-outlet-2ca8";
        store
            .sync_history_outlets(
                &[history_snapshot(outlet_id, "CSV 出口")],
                "2026-02-01T00:00:00Z",
            )
            .expect("catalogue");
        store
            .connection
            .execute(
                "INSERT INTO probe_samples(outlet_id, observed_at, status, latency_ms, error_code, outlet_label, outlet_kind) VALUES (?1, '2026-02-01T00:10:00Z', 'down', NULL, ?2, '=cmd()', 'local_proxy')",
                params![outlet_id, "https://private.invalid/token-value"],
            )
            .expect("hostile synthetic row");
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("history.csv");
        let rows = store
            .export_history_csv(
                &path,
                &HistoryFilter {
                    outlet_id: Some(outlet_id.into()),
                    status: Some(HealthStatus::Down),
                    event_type: Some(HistoryEventType::Probe),
                    ..HistoryFilter::default()
                },
                "2026-02-01T01:00:00Z",
            )
            .expect("export");
        assert_eq!(rows, 1);
        let csv = fs::read_to_string(path).expect("csv");
        assert!(csv.contains("\"'=cmd()\""));
        assert!(csv.contains("redacted_reason"));
        for forbidden in ["private.invalid", "token-value", "://"] {
            assert!(!csv.contains(forbidden), "leaked {forbidden}: {csv}");
        }
    }

    #[test]
    fn retention_keeps_ongoing_failure_and_current_udp_evidence() {
        let mut store = GuardianStore::open_in_memory().expect("store");
        let outlet_id = "retention-outlet-18e4";
        store
            .sync_history_outlets(
                &[history_snapshot(outlet_id, "保留测试")],
                "2026-02-10T00:00:00Z",
            )
            .expect("catalogue");
        store.connection.execute(
            "INSERT INTO probe_samples(outlet_id, observed_at, status, outlet_label, outlet_kind) VALUES (?1, '2026-01-01T00:00:00Z', 'down', '保留测试', 'local_proxy')",
            [outlet_id],
        ).expect("old probe");
        store.connection.execute(
            "INSERT INTO state_events(outlet_id, occurred_at, from_status, to_status, reason, outlet_label, outlet_kind) VALUES (?1, '2026-01-01T00:00:00Z', 'healthy', 'down', 'synthetic', '保留测试', 'local_proxy')",
            [outlet_id],
        ).expect("ongoing failure");
        store.connection.execute(
            "INSERT INTO udp_capability_history(outlet_id, status, observed_at, evidence_version, probe_version, model_version, configuration_fingerprint, configuration_generation, reason_code) VALUES (?1, 'unknown', '2026-01-01T00:00:00Z', 1, 'synthetic', 1, 'synthetic', 1, 'synthetic')",
            [outlet_id],
        ).expect("old UDP evidence");
        let history_id = store.connection.last_insert_rowid();
        store
            .connection
            .execute(
                "INSERT INTO udp_capability_current(outlet_id, history_id) VALUES (?1, ?2)",
                params![outlet_id, history_id],
            )
            .expect("current UDP evidence");
        store
            .set_retention_days(1, "2026-02-10T00:00:00Z")
            .expect("cleanup");
        assert_eq!(
            store
                .connection
                .query_row("SELECT COUNT(*) FROM probe_samples", [], |row| row
                    .get::<_, i64>(0))
                .expect("probe count"),
            0
        );
        assert_eq!(
            store
                .connection
                .query_row("SELECT COUNT(*) FROM state_events", [], |row| row
                    .get::<_, i64>(0))
                .expect("event count"),
            1
        );
        assert_eq!(
            store
                .connection
                .query_row("SELECT COUNT(*) FROM udp_capability_history", [], |row| row
                    .get::<_, i64>(0))
                .expect("UDP count"),
            1
        );
        assert_eq!(store.retention_days().expect("setting"), 1);
    }

    #[test]
    fn empty_samples_and_status_filtered_route_switch_are_well_defined() {
        let mut store = GuardianStore::open_in_memory().expect("store");
        let outlet_id = "empty-outlet-33d1";
        store
            .sync_history_outlets(
                &[history_snapshot(outlet_id, "空样本出口")],
                "2026-02-01T00:00:00Z",
            )
            .expect("catalogue");
        let response = store
            .query_history(&HistoryFilter::default(), "2026-02-01T01:00:00Z")
            .expect("empty history");
        assert!(response.metrics.is_empty());
        assert!(response.records.is_empty());
        let route_with_status = store
            .query_history(
                &HistoryFilter {
                    status: Some(HealthStatus::Healthy),
                    event_type: Some(HistoryEventType::RouteSwitch),
                    ..HistoryFilter::default()
                },
                "2026-02-01T01:00:00Z",
            )
            .expect("empty intersection");
        assert!(route_with_status.records.is_empty());
    }

    #[test]
    fn thirty_day_volume_uses_time_index_and_stays_within_bounded_runtime() {
        let mut store = GuardianStore::open_in_memory().expect("store");
        let snapshots = (0..3)
            .map(|index| history_snapshot(&format!("volume-outlet-{index}-a9e2"), "规模测试"))
            .collect::<Vec<_>>();
        store
            .sync_history_outlets(&snapshots, "2026-03-01T00:00:00Z")
            .expect("catalogue");
        let end = parse_timestamp("2026-03-01T00:00:00Z").expect("timestamp");
        let transaction = store.connection.transaction().expect("transaction");
        {
            let mut insert = transaction
                .prepare(
                    "INSERT INTO probe_samples(outlet_id, observed_at, status, latency_ms, outlet_label, outlet_kind) VALUES (?1, ?2, ?3, ?4, '规模测试', 'local_proxy')",
                )
                .expect("prepare");
            for snapshot in &snapshots {
                for sample in 0..14_400_i64 {
                    let observed = end - chrono::Duration::seconds((14_400 - sample) * 180);
                    let status = if sample % 97 == 0 { "down" } else { "healthy" };
                    insert
                        .execute(params![
                            snapshot.outlet_id,
                            observed.to_rfc3339_opts(SecondsFormat::Millis, true),
                            status,
                            20 + sample % 400,
                        ])
                        .expect("insert sample");
                }
            }
        }
        transaction.commit().expect("commit samples");

        let plan = store
            .connection
            .prepare(
                "EXPLAIN QUERY PLAN SELECT id FROM probe_samples WHERE observed_at >= ?1 AND observed_at <= ?2 ORDER BY observed_at DESC LIMIT 100",
            )
            .and_then(|mut statement| {
                statement
                    .query_map(
                        params!["2026-01-30T00:00:00Z", "2026-03-01T00:00:00Z"],
                        |row| row.get::<_, String>(3),
                    )?
                    .collect::<Result<Vec<_>, _>>()
            })
            .expect("query plan");
        assert!(
            plan.iter()
                .any(|line| line.contains("idx_probe_samples_time_outlet_status")),
            "unexpected query plan: {plan:?}"
        );

        let filter = HistoryFilter {
            window: crate::HistoryWindow::ThirtyDays,
            ..HistoryFilter::default()
        };
        let query_started = std::time::Instant::now();
        let response = store
            .query_history(&filter, "2026-03-01T00:00:00Z")
            .expect("30-day query");
        assert_eq!(response.metrics.len(), 3);
        assert_eq!(response.records.len(), 100);
        assert!(query_started.elapsed() < std::time::Duration::from_secs(10));

        let directory = tempfile::tempdir().expect("tempdir");
        let export_started = std::time::Instant::now();
        let rows = store
            .export_history_csv(
                directory.path().join("volume.csv"),
                &filter,
                "2026-03-01T00:00:00Z",
            )
            .expect("streaming export");
        assert_eq!(rows, 43_200);
        assert!(export_started.elapsed() < std::time::Duration::from_secs(20));
    }

    #[test]
    fn migrates_v2_to_v4_transactionally_without_losing_existing_probe_data() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("guardian.db");
        {
            let connection = Connection::open(&path).expect("v2 database");
            connection
                .execute_batch(
                    r"
                    CREATE TABLE outlets (id TEXT PRIMARY KEY, label TEXT NOT NULL, updated_at TEXT NOT NULL);
                    CREATE TABLE probe_samples (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        outlet_id TEXT NOT NULL,
                        observed_at TEXT NOT NULL,
                        port_reachable INTEGER NOT NULL DEFAULT 0,
                        status TEXT NOT NULL,
                        http_status INTEGER,
                        latency_ms INTEGER,
                        error_code TEXT,
                        successful_targets INTEGER NOT NULL DEFAULT 0,
                        total_targets INTEGER NOT NULL DEFAULT 1
                    );
                    CREATE TABLE outlet_state (
                        outlet_id TEXT PRIMARY KEY,
                        status TEXT NOT NULL,
                        consecutive_successes INTEGER NOT NULL,
                        consecutive_failures INTEGER NOT NULL,
                        updated_at TEXT NOT NULL
                    );
                    INSERT INTO outlets VALUES ('legacy-a', 'Legacy A', '2026-01-01T00:00:00Z');
                    INSERT INTO probe_samples(outlet_id, observed_at, port_reachable, status, latency_ms, successful_targets, total_targets)
                    VALUES ('legacy-a', '2026-01-01T00:00:00Z', 1, 'healthy', 42, 2, 2);
                    INSERT INTO outlet_state VALUES ('legacy-a', 'healthy', 1, 0, '2026-01-01T00:00:00Z');
                    PRAGMA user_version=2;
                    ",
                )
                .expect("seed v2");
        }

        let store = GuardianStore::open(&path).expect("migrate v2");
        assert_eq!(
            store
                .connection
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .expect("version"),
            4
        );
        let summaries = store.summaries().expect("preserved summaries");
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].outlet_id, "legacy-a");
        assert_eq!(summaries[0].samples, 1);
        assert_eq!(summaries[0].average_latency_ms, Some(42.0));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn migrates_v3_to_v4_without_losing_udp_or_health_evidence() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("guardian-v3.db");
        {
            let connection = Connection::open(&path).expect("v3 database");
            connection
                .execute_batch(
                    r"
                    CREATE TABLE outlets (id TEXT PRIMARY KEY, label TEXT NOT NULL, updated_at TEXT NOT NULL);
                    CREATE TABLE probe_samples (
                        id INTEGER PRIMARY KEY AUTOINCREMENT, outlet_id TEXT NOT NULL,
                        observed_at TEXT NOT NULL, port_reachable INTEGER NOT NULL DEFAULT 0,
                        status TEXT NOT NULL, http_status INTEGER, latency_ms INTEGER,
                        error_code TEXT, successful_targets INTEGER NOT NULL DEFAULT 0,
                        total_targets INTEGER NOT NULL DEFAULT 1
                    );
                    CREATE TABLE outlet_state (
                        outlet_id TEXT PRIMARY KEY, status TEXT NOT NULL,
                        consecutive_successes INTEGER NOT NULL, consecutive_failures INTEGER NOT NULL,
                        updated_at TEXT NOT NULL
                    );
                    CREATE TABLE state_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT, outlet_id TEXT NOT NULL,
                        occurred_at TEXT NOT NULL, from_status TEXT NOT NULL,
                        to_status TEXT NOT NULL, reason TEXT NOT NULL
                    );
                    CREATE TABLE route_switches (
                        id INTEGER PRIMARY KEY AUTOINCREMENT, occurred_at TEXT NOT NULL,
                        from_outlet TEXT, to_outlet TEXT NOT NULL, mode TEXT NOT NULL,
                        reason TEXT NOT NULL, duration_ms INTEGER NOT NULL
                    );
                    CREATE TABLE udp_capability_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT, outlet_id TEXT NOT NULL,
                        status TEXT NOT NULL, observed_at TEXT NOT NULL, evidence_version INTEGER NOT NULL,
                        probe_version TEXT NOT NULL, model_version INTEGER NOT NULL,
                        configuration_fingerprint TEXT NOT NULL, configuration_generation INTEGER NOT NULL,
                        reason_code TEXT NOT NULL
                    );
                    CREATE TABLE udp_capability_current (
                        outlet_id TEXT PRIMARY KEY, history_id INTEGER NOT NULL
                    );
                    INSERT INTO outlets VALUES ('v3-outlet-a14f', 'https://private.invalid/token-value', '2026-01-01T00:00:00+00:00');
                    INSERT INTO outlets VALUES ('v3-outlet-b25e', '192.0.2.1', '2026-01-01T00:30:00Z');
                    INSERT INTO outlets VALUES ('v3-outlet-c36d', '节点-secret-shape', '2026-01-01T01:00:00.000Z');
                    INSERT INTO probe_samples(outlet_id, observed_at, status, latency_ms)
                    VALUES ('v3-outlet-a14f', '2026-01-01T00:00:00+00:00', 'healthy', 33);
                    INSERT INTO probe_samples(outlet_id, observed_at, status, latency_ms)
                    VALUES ('v3-outlet-b25e', '2026-01-01T00:30:00Z', 'healthy', 44);
                    INSERT INTO probe_samples(outlet_id, observed_at, status, latency_ms)
                    VALUES ('v3-outlet-c36d', '2026-01-01T01:00:00.000Z', 'healthy', 55);
                    INSERT INTO outlet_state VALUES ('v3-outlet-a14f', 'healthy', 1, 0, '2026-01-01T00:00:00Z');
                    INSERT INTO state_events(outlet_id, occurred_at, from_status, to_status, reason)
                    VALUES ('v3-outlet-a14f', '2026-01-01T00:15:00+00:00', 'unknown', 'healthy', 'synthetic');
                    INSERT INTO route_switches(occurred_at, from_outlet, to_outlet, mode, reason, duration_ms)
                    VALUES ('2026-01-01T00:45:00Z', 'v3-outlet-b25e', 'v3-outlet-c36d', 'priority', 'synthetic', 3);
                    INSERT INTO udp_capability_history(outlet_id, status, observed_at, evidence_version, probe_version, model_version, configuration_fingerprint, configuration_generation, reason_code)
                    VALUES ('v3-outlet-a14f', 'supported', '2026-01-01T00:00:00Z', 1, 'synthetic-v1', 1, 'synthetic-fingerprint', 7, 'synthetic');
                    INSERT INTO udp_capability_current VALUES ('v3-outlet-a14f', 1);
                    PRAGMA user_version=3;
                    ",
                )
                .expect("seed v3");
        }
        let store = GuardianStore::open(&path).expect("migrate v3");
        assert_eq!(
            store
                .connection
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .expect("version"),
            4
        );
        assert_eq!(store.summaries().expect("summary").len(), 3);
        let udp = store.udp_capabilities().expect("UDP evidence");
        assert_eq!(udp.len(), 1);
        assert_eq!(udp[0].status, UdpCapabilityStatus::Supported);
        assert_eq!(store.retention_days().expect("retention"), 30);
        for (table, column) in [
            ("outlets", "label"),
            ("probe_samples", "outlet_label"),
            ("state_events", "outlet_label"),
        ] {
            let leaked = store
                .connection
                .query_row(
                    &format!("SELECT COUNT(*) FROM {table} WHERE {column} != '已脱敏出口'"),
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .expect("persisted sanitized labels");
            assert_eq!(leaked, 0, "unsanitized {table}.{column}");
        }
        let route_labels = store
            .connection
            .query_row(
                "SELECT from_label, to_label FROM route_switches",
                [],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .expect("route snapshots");
        assert_eq!(route_labels, ("已脱敏出口".into(), "已脱敏出口".into()));
        let migrated_times = store
            .connection
            .prepare("SELECT observed_at FROM probe_samples ORDER BY id")
            .and_then(|mut statement| {
                statement
                    .query_map([], |row| row.get::<_, String>(0))?
                    .collect::<Result<Vec<_>, _>>()
            })
            .expect("canonical timestamps");
        assert_eq!(
            migrated_times,
            [
                "2026-01-01T00:00:00.000Z",
                "2026-01-01T00:30:00.000Z",
                "2026-01-01T01:00:00.000Z",
            ]
        );
        let boundary = store
            .query_history(
                &HistoryFilter {
                    window: crate::HistoryWindow::OneHour,
                    event_type: Some(HistoryEventType::Probe),
                    ..HistoryFilter::default()
                },
                "2026-01-01T01:00:00+00:00",
            )
            .expect("canonical boundary query");
        assert_eq!(boundary.total_count, 3, "start/end are inclusive");
    }

    #[test]
    fn failed_v2_migration_rolls_back_schema_and_user_version() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("guardian.db");
        {
            let connection = Connection::open(&path).expect("v2 database");
            connection
                .execute_batch(
                    r"
                    CREATE TABLE sentinel(value TEXT NOT NULL);
                    INSERT INTO sentinel VALUES ('preserve-me');
                    CREATE VIEW udp_capability_history AS SELECT value FROM sentinel;
                    PRAGMA user_version=2;
                    ",
                )
                .expect("seed broken v2");
        }
        assert!(matches!(
            GuardianStore::open(&path),
            Err(StoreError::Database(_))
        ));
        let connection = Connection::open(&path).expect("reopen rolled back database");
        assert_eq!(
            connection
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .expect("version"),
            2
        );
        assert_eq!(
            connection
                .query_row("SELECT value FROM sentinel", [], |row| row
                    .get::<_, String>(0))
                .expect("sentinel"),
            "preserve-me"
        );
        let current_exists = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='udp_capability_current')",
                [],
                |row| row.get::<_, bool>(0),
            )
            .expect("schema check");
        assert!(!current_exists);
    }

    #[test]
    fn future_database_version_is_rejected_without_any_mutation() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("guardian.db");
        {
            let connection = Connection::open(&path).expect("future database");
            connection
                .execute_batch(
                    r"
                    CREATE TABLE sentinel(value TEXT NOT NULL);
                    INSERT INTO sentinel VALUES ('future-data');
                    PRAGMA user_version=99;
                    ",
                )
                .expect("seed future database");
        }
        assert!(matches!(
            GuardianStore::open(&path),
            Err(StoreError::UnsupportedDatabaseVersion(99))
        ));
        let connection = Connection::open(&path).expect("reopen future database");
        assert_eq!(
            connection
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .expect("version"),
            99
        );
        assert_eq!(
            connection
                .query_row("SELECT value FROM sentinel", [], |row| row
                    .get::<_, String>(0))
                .expect("sentinel"),
            "future-data"
        );
        let outlets_exists = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='outlets')",
                [],
                |row| row.get::<_, bool>(0),
            )
            .expect("schema check");
        assert!(!outlets_exists);
    }
}
