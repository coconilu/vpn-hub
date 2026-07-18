use std::{fs, path::Path};

use rusqlite::{Connection, OptionalExtension, params};
use thiserror::Error;

use crate::{
    HealthStatus, LatencySample, OutletConfig, OutletSummary, ProbeResult, RouteSwitchEvent,
    StateEvent,
};

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("failed to prepare database directory: {0}")]
    Directory(#[from] std::io::Error),
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("invalid stored status: {0}")]
    InvalidStatus(String),
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

    fn from_connection(connection: Connection) -> Result<Self, StoreError> {
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.execute_batch(
            r"
            CREATE TABLE IF NOT EXISTS outlets (
                id TEXT PRIMARY KEY,
                label TEXT NOT NULL,
                updated_at TEXT NOT NULL
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
                total_targets INTEGER NOT NULL DEFAULT 1
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
                reason TEXT NOT NULL
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
                duration_ms INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_route_switches_time
                ON route_switches(occurred_at DESC);
            ",
        )?;
        ensure_probe_column(&connection, "port_reachable", "INTEGER NOT NULL DEFAULT 0")?;
        ensure_probe_column(&connection, "http_status", "INTEGER")?;
        ensure_probe_column(
            &connection,
            "successful_targets",
            "INTEGER NOT NULL DEFAULT 0",
        )?;
        ensure_probe_column(&connection, "total_targets", "INTEGER NOT NULL DEFAULT 1")?;
        connection.pragma_update(None, "user_version", 2_i64)?;
        Ok(Self { connection })
    }

    /// Persists one sanitized probe and emits a state transition when a
    /// configured failure or recovery threshold is reached.
    ///
    /// # Errors
    ///
    /// Returns an error when the transaction cannot be read or committed.
    pub fn record_probe(
        &mut self,
        outlet: &OutletConfig,
        result: &ProbeResult,
        failure_threshold: u32,
        recovery_threshold: u32,
    ) -> Result<Option<StateEvent>, StoreError> {
        let transaction = self.connection.transaction()?;
        transaction.execute(
            r"INSERT INTO outlets(id, label, updated_at) VALUES (?1, ?2, ?3)
               ON CONFLICT(id) DO UPDATE SET label=excluded.label, updated_at=excluded.updated_at",
            params![outlet.id, outlet.label, result.observed_at],
        )?;
        transaction.execute(
            "INSERT INTO probe_samples(outlet_id, observed_at, port_reachable, status, http_status, latency_ms, error_code, successful_targets, total_targets) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                outlet.id,
                result.observed_at,
                result.port_reachable,
                result.status.as_str(),
                result.http_status,
                result.latency_ms.map(|value| i64::try_from(value).unwrap_or(i64::MAX)),
                result.error_code,
                result.successful_targets,
                result.total_targets
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
            params![outlet.id, next_status.as_str(), successes, failures, result.observed_at],
        )?;

        let event = (previous.status != next_status).then(|| StateEvent {
            outlet_id: outlet.id.clone(),
            occurred_at: result.observed_at.clone(),
            from_status: previous.status,
            to_status: next_status,
            reason: result
                .error_code
                .clone()
                .unwrap_or_else(|| "probe_result".into()),
        });
        if let Some(event) = &event {
            transaction.execute(
                "INSERT INTO state_events(outlet_id, occurred_at, from_status, to_status, reason) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    event.outlet_id,
                    event.occurred_at,
                    event.from_status.as_str(),
                    event.to_status.as_str(),
                    event.reason
                ],
            )?;
        }
        transaction.commit()?;
        Ok(event)
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
        self.connection.execute(
            "INSERT INTO route_switches(occurred_at, from_outlet, to_outlet, mode, reason, duration_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                event.occurred_at,
                event.from_outlet,
                event.to_outlet,
                event.mode,
                event.reason,
                i64::try_from(event.duration_ms).unwrap_or(i64::MAX)
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
}

fn ensure_probe_column(
    connection: &Connection,
    column_name: &str,
    definition: &str,
) -> Result<(), rusqlite::Error> {
    let exists = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('probe_samples') WHERE name=?1)",
        [column_name],
        |row| row.get::<_, bool>(0),
    )?;
    if !exists {
        connection.execute(
            &format!("ALTER TABLE probe_samples ADD COLUMN {column_name} {definition}"),
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

    fn outlet() -> OutletConfig {
        OutletConfig {
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
            to_outlet: "chaoshihui".into(),
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
}
