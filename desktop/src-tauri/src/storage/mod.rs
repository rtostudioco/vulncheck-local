// SENTINEL DESK 1.0 — SQLite storage (app-owned data only)
//
// The database lives in the OS app-data directory (e.g.
// %APPDATA%\com.sentineldesk.app on Windows) and contains ONLY data Sentinel
// Desk itself collected/derived. It never touches Windows event log files
// (.evtx) or system configuration. WAL journaling keeps reads cheap; foreign
// keys are always ON.

use crate::collectors::{SourceStatus, CHANNELS};
use crate::detection::rules;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::path::Path;

pub mod retention;

/// Embedded migration applied at startup.
const MIGRATION_001: &str = include_str!("../../migrations/001_init.sql");

/// Application settings persisted under settings.key = 'app' (JSON).
/// Mirrors the web prototype's SettingsPayload (desktop-relevant subset).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AppSettings {
    pub language: String,
    /// Interval (seconds) the frontend uses between collector_tick calls —
    /// same model as the web prototype (frontend-driven loop).
    pub collector_interval_sec: u64,
    /// Events older than this are purged on every tick (app-owned data only).
    pub retention_days: u64,
    /// Start collecting automatically when the app opens.
    pub collector_auto_start: bool,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            language: "en".to_string(),
            collector_interval_sec: 20,
            retention_days: 7,
            collector_auto_start: false,
        }
    }
}

/// UTC ISO-8601 timestamp used across the schema.
pub fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// New uuid v4 primary key.
pub fn new_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Open (creating if needed) the Sentinel Desk SQLite database.
pub fn open_db(path: &Path) -> Result<Connection, String> {
    let conn = Connection::open(path).map_err(|e| format!("cannot open database: {e}"))?;
    conn.pragma_update(None, "foreign_keys", "ON")
        .map_err(|e| format!("cannot enable foreign_keys: {e}"))?;
    conn.pragma_update(None, "journal_mode", "WAL")
        .map_err(|e| format!("cannot enable WAL mode: {e}"))?;
    conn.pragma_update(None, "synchronous", "NORMAL")
        .map_err(|e| format!("cannot set synchronous mode: {e}"))?;
    Ok(conn)
}

/// Apply embedded migrations (idempotent).
pub fn migrate(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(MIGRATION_001)
        .map_err(|e| format!("migration 001_init failed: {e}"))
}

/// Seed the five authorized event sources. `probe` maps a logical channel to
/// its probed availability; unprobed channels are seeded as unavailable with
/// an explicit note (never silently marked healthy).
pub fn seed_event_sources(
    conn: &Connection,
    probe: &std::collections::HashMap<String, (SourceStatus, Option<String>)>,
) -> Result<(), String> {
    for channel in CHANNELS {
        let (status, note) = match probe.get(channel.logical) {
            Some((s, n)) => (s.as_str().to_string(), n.clone()),
            None => (
                SourceStatus::Unavailable.as_str().to_string(),
                Some("Not probed yet — run a collection tick to refresh source health.".to_string()),
            ),
        };
        conn.execute(
            "INSERT INTO event_sources (id, channel, display_name, description, status, available, requires_admin, note)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(channel) DO NOTHING",
            rusqlite::params![
                new_id(),
                channel.logical,
                channel.display_name,
                channel.description,
                status,
                i64::from(status == "active" || status == "demo"),
                i64::from(channel.requires_admin),
                note,
            ],
        )
        .map_err(|e| format!("cannot seed event source {}: {e}", channel.logical))?;
    }
    Ok(())
}

/// Seed the versioned rule catalog. Toggle state (`enabled`) is preserved on
/// re-seeding; descriptive fields follow the embedded catalog.
pub fn seed_detection_rules(conn: &Connection) -> Result<(), String> {
    for rule in rules() {
        let logic_json = serde_json::to_string(&rule.logic)
            .map_err(|e| format!("cannot serialize logic for {}: {e}", rule.id))?;
        let evidence_fields = serde_json::to_string(&rule.evidence_fields)
            .map_err(|e| format!("cannot serialize evidence fields for {}: {e}", rule.id))?;
        conn.execute(
            "INSERT INTO detection_rules
               (id, name, description, version, author, severity, category, mitre_id, mitre_name,
                enabled, logic, false_positives, limitations, evidence_fields, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 1, ?10, ?11, ?12, ?13, ?14)
             ON CONFLICT(id) DO UPDATE SET
               name = excluded.name,
               description = excluded.description,
               version = excluded.version,
               author = excluded.author,
               severity = excluded.severity,
               category = excluded.category,
               mitre_id = excluded.mitre_id,
               mitre_name = excluded.mitre_name,
               logic = excluded.logic,
               false_positives = excluded.false_positives,
               limitations = excluded.limitations,
               evidence_fields = excluded.evidence_fields",
            rusqlite::params![
                rule.id,
                rule.name,
                rule.description,
                rule.version,
                rule.author,
                rule.severity.as_str(),
                rule.category,
                rule.mitre_id,
                rule.mitre_name,
                logic_json,
                rule.false_positives,
                rule.limitations,
                evidence_fields,
                now_iso(),
            ],
        )
        .map_err(|e| format!("cannot seed rule {}: {e}", rule.id))?;
    }
    Ok(())
}

/// Load settings (defaults when missing/corrupt — never fail the app).
pub fn load_settings(conn: &Connection) -> AppSettings {
    let value: Option<String> = conn
        .query_row("SELECT value FROM settings WHERE key = 'app'", [], |row| row.get(0))
        .ok();
    value
        .and_then(|v| serde_json::from_str(&v).ok())
        .unwrap_or_default()
}

/// Persist settings back to the settings table.
pub fn save_settings(conn: &Connection, settings: &AppSettings) -> Result<(), String> {
    let json = serde_json::to_string(settings).map_err(|e| format!("cannot serialize settings: {e}"))?;
    conn.execute(
        "INSERT INTO settings (key, value) VALUES ('app', ?1)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        rusqlite::params![json],
    )
    .map(|_| ())
    .map_err(|e| format!("cannot save settings: {e}"))
}
