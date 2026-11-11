// SENTINEL DESK 1.0 — Retention policy (§7 stage 6)
//
// Events older than settings.retention_days are purged on each collection
// tick. Only APP-OWNED data is deleted (rows in sentinel.db); nothing outside
// the application data directory is ever modified. alert_events rows cascade
// with their events; alerts themselves are kept (their evidence JSON remains
// as collected, explicitly labeled) so investigation history is preserved
// until the analyst purges data deliberately.

use rusqlite::Connection;

/// Delete events older than `retention_days`. Returns the number purged.
pub fn purge_expired_events(conn: &Connection, retention_days: u64) -> Result<u64, String> {
    let cutoff = (chrono::Utc::now() - chrono::Duration::days(retention_days as i64))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let purged = conn
        .execute("DELETE FROM events WHERE ts < ?1", rusqlite::params![cutoff])
        .map_err(|e| format!("retention purge failed: {e}"))?;
    Ok(purged as u64)
}
