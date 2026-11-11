// SENTINEL DESK 1.0 — Overview command (MODULE 01)
//
// Mirrors the web prototype's GET /api/overview payload.

use crate::storage::now_iso;
use serde_json::{json, Value};
use tauri::State;

use crate::AppState;

#[tauri::command]
pub fn overview_stats(state: State<'_, AppState>) -> Result<Value, String> {
    let conn = state.db.lock().map_err(|_| "database busy".to_string())?;

    let since24 = (chrono::Utc::now() - chrono::Duration::hours(24))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

    let events_24h: i64 = conn
        .query_row("SELECT COUNT(*) FROM events WHERE ts >= ?1", [&since24], |r| r.get(0))
        .unwrap_or(0);
    let events_total: i64 = conn
        .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
        .unwrap_or(0);
    let open_alerts: i64 = conn
        .query_row("SELECT COUNT(*) FROM alerts WHERE status = 'open'", [], |r| r.get(0))
        .unwrap_or(0);
    let active_incidents: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM incidents WHERE status IN ('new','investigating','monitoring')",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    let rules_enabled: i64 = conn
        .query_row("SELECT COUNT(*) FROM detection_rules WHERE enabled = 1", [], |r| r.get(0))
        .unwrap_or(0);
    let rules_total: i64 = conn
        .query_row("SELECT COUNT(*) FROM detection_rules", [], |r| r.get(0))
        .unwrap_or(0);

    let mut by_severity = Vec::new();
    for sev in ["critical", "high", "medium", "low", "info"] {
        let a: i64 = conn
            .query_row("SELECT COUNT(*) FROM alerts WHERE severity = ?1", [sev], |r| r.get(0))
            .unwrap_or(0);
        let i: i64 = conn
            .query_row("SELECT COUNT(*) FROM incidents WHERE severity = ?1", [sev], |r| r.get(0))
            .unwrap_or(0);
        by_severity.push(json!({ "severity": sev, "alerts": a, "incidents": i }));
    }

    // 24h volume buckets (1h), events + alerts
    let mut volume = Vec::new();
    for h in (0..24).rev() {
        let from = (chrono::Utc::now() - chrono::Duration::hours(h + 1))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let to = (chrono::Utc::now() - chrono::Duration::hours(h))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let e: i64 = conn
            .query_row("SELECT COUNT(*) FROM events WHERE ts >= ?1 AND ts < ?2", [&from, &to], |r| r.get(0))
            .unwrap_or(0);
        let a: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM alerts WHERE created_at >= ?1 AND created_at < ?2",
                [&from, &to],
                |r| r.get(0),
            )
            .unwrap_or(0);
        volume.push(json!({ "bucket": from, "events": e, "alerts": a }));
    }

    // Source health
    let mut sources = Vec::new();
    {
        let mut stmt = conn
            .prepare(
                "SELECT channel, display_name, description, status, available, requires_admin, note, last_collect_at, events_collected
                 FROM event_sources ORDER BY channel",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |row| {
                Ok(json!({
                    "channel": row.get::<_, String>(0)?,
                    "displayName": row.get::<_, String>(1)?,
                    "description": row.get::<_, Option<String>>(2)?,
                    "status": row.get::<_, String>(3)?,
                    "available": row.get::<_, i64>(4)? != 0,
                    "requiresAdmin": row.get::<_, i64>(5)? != 0,
                    "note": row.get::<_, Option<String>>(6)?,
                    "lastCollectAt": row.get::<_, Option<String>>(7)?,
                    "eventsCollected": row.get::<_, i64>(8)?,
                }))
            })
            .map_err(|e| e.to_string())?;
        for r in rows.flatten() {
            sources.push(r);
        }
    }

    // Recent alerts + incidents (for the dashboard lists and notification seeding)
    let mut recent_alerts = Vec::new();
    {
        let mut stmt = conn
            .prepare(
                "SELECT id, rule_id, severity, title, summary, created_at FROM alerts
                 ORDER BY created_at DESC LIMIT 8",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |row| {
                Ok(json!({
                    "id": row.get::<_, String>(0)?,
                    "ruleId": row.get::<_, String>(1)?,
                    "severity": row.get::<_, String>(2)?,
                    "title": row.get::<_, String>(3)?,
                    "summary": row.get::<_, String>(4)?,
                    "createdAt": row.get::<_, String>(5)?,
                }))
            })
            .map_err(|e| e.to_string())?;
        for r in rows.flatten() {
            recent_alerts.push(r);
        }
    }

    let mut recent_incidents = Vec::new();
    {
        let mut stmt = conn
            .prepare(
                "SELECT id, code, title, severity, status, created_at FROM incidents
                 ORDER BY created_at DESC LIMIT 8",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |row| {
                Ok(json!({
                    "id": row.get::<_, String>(0)?,
                    "code": row.get::<_, String>(1)?,
                    "title": row.get::<_, String>(2)?,
                    "severity": row.get::<_, String>(3)?,
                    "status": row.get::<_, String>(4)?,
                    "createdAt": row.get::<_, String>(5)?,
                }))
            })
            .map_err(|e| e.to_string())?;
        for r in rows.flatten() {
            recent_incidents.push(r);
        }
    }

    Ok(json!({
        "generatedAt": now_iso(),
        "events24h": events_24h,
        "eventsTotal": events_total,
        "openAlerts": open_alerts,
        "activeIncidents": active_incidents,
        "rulesEnabled": rules_enabled,
        "rulesTotal": rules_total,
        "bySeverity": by_severity,
        "volume24h": volume,
        "sources": sources,
        "recentAlerts": recent_alerts,
        "recentIncidents": recent_incidents,
    }))
}
