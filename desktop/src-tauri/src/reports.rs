// SENTINEL DESK 1.0 — SOC reports (MODULE 10)
//
// JSON report with SHA-256 integrity metadata + CSV exports.
// The report NEVER represents incomplete or demo collection as complete
// coverage: collectionLimitations is always present and names the
// unavailable channels explicitly.

use crate::storage::now_iso;
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;

pub fn csv_escape(v: &str) -> String {
    if v.contains(',') || v.contains('"') || v.contains('\n') {
        format!("\"{}\"", v.replace('"', "\"\""))
    } else {
        v.to_string()
    }
}

/// Build the JSON report for a UTC window [since_iso, now]. Mirrors the web
/// prototype's /api/reports?format=json payload.
pub fn build_json_report(conn: &Connection, since_iso: &str, label: &str) -> Result<serde_json::Value, String> {
    let now = now_iso();

    // Sources with honest availability
    let mut sources = Vec::new();
    {
        let mut stmt = conn
            .prepare("SELECT channel, status, available, requires_admin, events_collected, last_collect_at FROM event_sources ORDER BY channel")
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |row| {
                Ok(serde_json::json!({
                    "channel": row.get::<_, String>(0)?,
                    "status": row.get::<_, String>(1)?,
                    "available": row.get::<_, i64>(2)? != 0,
                    "requiresAdmin": row.get::<_, i64>(3)? != 0,
                    "eventsCollected": row.get::<_, i64>(4)?,
                    "lastCollectAt": row.get::<_, Option<String>>(5)?,
                }))
            })
            .map_err(|e| e.to_string())?;
        for r in rows.flatten() {
            sources.push(r);
        }
    }

    // Rules
    let mut rules = Vec::new();
    {
        let mut stmt = conn
            .prepare("SELECT id, name, version, severity, mitre_id, enabled FROM detection_rules ORDER BY id")
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |row| {
                Ok(serde_json::json!({
                    "id": row.get::<_, String>(0)?,
                    "name": row.get::<_, String>(1)?,
                    "version": row.get::<_, String>(2)?,
                    "severity": row.get::<_, String>(3)?,
                    "mitreId": row.get::<_, Option<String>>(4)?,
                    "enabled": row.get::<_, i64>(5)? != 0,
                }))
            })
            .map_err(|e| e.to_string())?;
        for r in rows.flatten() {
            rules.push(r);
        }
    }

    // Alerts
    let mut alerts = Vec::new();
    {
        let mut stmt = conn
            .prepare(
                "SELECT a.id, a.created_at, a.rule_id, r.name, a.severity, a.confidence, a.status,
                        a.computer, a.user_name, a.mitre_id, a.summary, a.evidence
                 FROM alerts a JOIN detection_rules r ON r.id = a.rule_id
                 WHERE a.created_at >= ?1 ORDER BY a.created_at DESC LIMIT 1000",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([since_iso], |row| {
                Ok(serde_json::json!({
                    "id": row.get::<_, String>(0)?,
                    "createdAt": row.get::<_, String>(1)?,
                    "ruleId": row.get::<_, String>(2)?,
                    "ruleName": row.get::<_, String>(3)?,
                    "severity": row.get::<_, String>(4)?,
                    "confidence": row.get::<_, i64>(5)?,
                    "status": row.get::<_, String>(6)?,
                    "computer": row.get::<_, Option<String>>(7)?,
                    "userName": row.get::<_, Option<String>>(8)?,
                    "mitreId": row.get::<_, Option<String>>(9)?,
                    "summary": row.get::<_, String>(10)?,
                    "evidence": serde_json::from_str::<serde_json::Value>(&row.get::<_, String>(11)?).unwrap_or(serde_json::json!([])),
                }))
            })
            .map_err(|e| e.to_string())?;
        for r in rows.flatten() {
            alerts.push(r);
        }
    }

    // Incidents
    let mut incidents = Vec::new();
    {
        let mut stmt = conn
            .prepare(
                "SELECT id, code, title, severity, status, hypothesis, correlation_meta, created_at, updated_at
                 FROM incidents WHERE created_at >= ?1 ORDER BY created_at DESC LIMIT 200",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([since_iso], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    serde_json::json!({
                        "id": row.get::<_, String>(0)?,
                        "code": row.get::<_, String>(1)?,
                        "title": row.get::<_, String>(2)?,
                        "severity": row.get::<_, String>(3)?,
                        "status": row.get::<_, String>(4)?,
                        "hypothesis": row.get::<_, Option<String>>(5)?,
                        "correlationMeta": row.get::<_, Option<String>>(6)?.and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok()),
                        "createdAt": row.get::<_, String>(7)?,
                        "updatedAt": row.get::<_, String>(8)?,
                    }),
                ))
            })
            .map_err(|e| e.to_string())?;
        for r in rows.flatten() {
            let (id, mut obj) = r;
            // Attach alert digests, notes and AI analyses (AI always flagged)
            let mut alert_list = Vec::new();
            if let Ok(mut st) = conn.prepare(
                "SELECT a.rule_id, a.severity, a.summary FROM alerts a WHERE a.incident_id = ?1",
            ) {
                if let Ok(rows) = st.query_map([&id], |row| {
                    Ok(serde_json::json!({
                        "ruleId": row.get::<_, String>(0)?,
                        "severity": row.get::<_, String>(1)?,
                        "summary": row.get::<_, String>(2)?,
                    }))
                }) {
                    for r in rows.flatten() {
                        alert_list.push(r);
                    }
                }
            }
            let mut notes = Vec::new();
            if let Ok(mut st) = conn
                .prepare("SELECT author, body, created_at FROM incident_notes WHERE incident_id = ?1 ORDER BY created_at")
            {
                if let Ok(rows) = st.query_map([&id], |row| {
                    Ok(serde_json::json!({
                        "author": row.get::<_, String>(0)?,
                        "body": row.get::<_, String>(1)?,
                        "createdAt": row.get::<_, String>(2)?,
                    }))
                }) {
                    for r in rows.flatten() {
                        notes.push(r);
                    }
                }
            }
            let mut ai = Vec::new();
            if let Ok(mut st) = conn.prepare(
                "SELECT provider, model, privacy_mode, prompt_version, created_at, output
                 FROM ai_analyses WHERE incident_id = ?1 ORDER BY created_at DESC",
            ) {
                if let Ok(rows) = st.query_map([&id], |row| {
                    Ok(serde_json::json!({
                        "aiGenerated": true,
                        "provider": row.get::<_, String>(0)?,
                        "model": row.get::<_, String>(1)?,
                        "privacyMode": row.get::<_, String>(2)?,
                        "promptVersion": row.get::<_, String>(3)?,
                        "createdAt": row.get::<_, String>(4)?,
                        "output": row.get::<_, String>(5)?,
                    }))
                }) {
                    for r in rows.flatten() {
                        ai.push(r);
                    }
                }
            }
            obj["alerts"] = serde_json::Value::Array(alert_list);
            obj["notes"] = serde_json::Value::Array(notes);
            obj["aiAnalyses"] = serde_json::Value::Array(ai);
            incidents.push(obj);
        }
    }

    // Summary + bySeverity
    let events_in_report: i64 = conn
        .query_row("SELECT COUNT(*) FROM events WHERE ts >= ?1", [since_iso], |r| r.get(0))
        .unwrap_or(0);
    let mut by_severity = Vec::new();
    for sev in ["critical", "high", "medium", "low", "info"] {
        let a: i64 = alerts
            .iter()
            .filter(|x| x["severity"] == sev)
            .count() as i64;
        let i: i64 = incidents
            .iter()
            .filter(|x| x["severity"] == sev)
            .count() as i64;
        by_severity.push(serde_json::json!({ "severity": sev, "alerts": a, "incidents": i }));
    }

    Ok(serde_json::json!({
        "report": {
            "product": "Sentinel Desk",
            "version": "1.0.0",
            "generatedAt": now,
            "range": { "from": since_iso, "to": now, "label": label },
            "collectionLimitations": {
                "sourceType": if cfg!(windows) { "windows_event_log_readonly" } else { "unavailable_on_this_platform" },
                "statement": "Sentinel Desk reads a limited set of Windows Event Log channels strictly read-only. Channel availability depends on audit policy, permissions and optional components (e.g. Sysmon). Missing telemetry is NOT evidence of absence of threats; incomplete collection is never represented as complete coverage.",
                "adminRequiredChannels": ["Security (depends on audit policy and reader privileges)"],
                "unavailableChannels": ["Sysmon (optional, must not be assumed installed)"],
            },
            "sources": sources,
            "detectionRules": rules,
            "summary": {
                "eventsInReport": events_in_report,
                "alertsInReport": alerts.len(),
                "incidentsInReport": incidents.len(),
                "bySeverity": by_severity,
            },
            "alerts": alerts,
            "incidents": incidents,
        }
    }))
}

/// Attach the integrity digest (SHA-256 over the canonical JSON body).
pub fn with_integrity(mut payload: serde_json::Value) -> serde_json::Value {
    let canonical = payload.to_string();
    let digest = Sha256::digest(canonical.as_bytes());
    let hex: String = digest.iter().fold(String::new(), |mut acc, b| {
        let _ = write!(acc, "{b:02x}");
        acc
    });
    payload["integrity"] = serde_json::json!({
        "algorithm": "SHA-256",
        "digest": hex,
        "covers": "report payload excluding this field",
    });
    payload
}

/// CSV export for events (bounded).
pub fn build_events_csv(conn: &Connection, since_iso: &str) -> Result<String, String> {
    let mut out = String::from("id,ts,channel,provider,eventId,level,computer,userName,targetUserName,processName,commandLine,ipAddress,serviceName,taskName,summary,synthetic,sourceRef\n");
    let mut stmt = conn
        .prepare(
            "SELECT id, ts, channel, provider, event_id, level, computer, user_name, target_user_name,
                    process_name, command_line, ip_address, service_name, task_name, summary, synthetic, source_ref
             FROM events WHERE ts >= ?1 ORDER BY ts DESC LIMIT 5000",
        )
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([since_iso], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, Option<String>>(8)?,
                row.get::<_, Option<String>>(9)?,
                row.get::<_, Option<String>>(10)?,
                row.get::<_, Option<String>>(11)?,
                row.get::<_, Option<String>>(12)?,
                row.get::<_, Option<String>>(13)?,
                row.get::<_, Option<String>>(14)?,
                row.get::<_, i64>(15)?,
                row.get::<_, Option<String>>(16)?,
            ))
        })
        .map_err(|e| e.to_string())?;
    for r in rows.flatten() {
        let _ = writeln!(
            out,
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            csv_escape(&r.0),
            csv_escape(&r.1),
            csv_escape(&r.2),
            csv_escape(&r.3),
            r.4,
            csv_escape(&r.5),
            csv_escape(&r.6),
            csv_escape(&r.7.unwrap_or_default()),
            csv_escape(&r.8.unwrap_or_default()),
            csv_escape(&r.9.unwrap_or_default()),
            csv_escape(&r.10.unwrap_or_default()),
            csv_escape(&r.11.unwrap_or_default()),
            csv_escape(&r.12.unwrap_or_default()),
            csv_escape(&r.13.unwrap_or_default()),
            csv_escape(&r.14.unwrap_or_default()),
            r.15,
            csv_escape(&r.16.unwrap_or_default()),
        );
    }
    Ok(out)
}

/// CSV export for alerts (bounded).
pub fn build_alerts_csv(conn: &Connection, since_iso: &str) -> Result<String, String> {
    let mut out = String::from("id,createdAt,ruleId,ruleName,severity,confidence,status,computer,userName,mitreId,summary\n");
    let mut stmt = conn
        .prepare(
            "SELECT a.id, a.created_at, a.rule_id, r.name, a.severity, a.confidence, a.status,
                    a.computer, a.user_name, a.mitre_id, a.summary
             FROM alerts a JOIN detection_rules r ON r.id = a.rule_id
             WHERE a.created_at >= ?1 ORDER BY a.created_at DESC LIMIT 5000",
        )
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([since_iso], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, Option<String>>(8)?,
                row.get::<_, Option<String>>(9)?,
                row.get::<_, String>(10)?,
            ))
        })
        .map_err(|e| e.to_string())?;
    for r in rows.flatten() {
        let _ = writeln!(
            out,
            "{},{},{},{},{},{},{},{},{},{},{}",
            csv_escape(&r.0),
            csv_escape(&r.1),
            csv_escape(&r.2),
            csv_escape(&r.3),
            csv_escape(&r.4),
            r.5,
            csv_escape(&r.6),
            csv_escape(&r.7.unwrap_or_default()),
            csv_escape(&r.8.unwrap_or_default()),
            csv_escape(&r.9.unwrap_or_default()),
            csv_escape(&r.10),
        );
    }
    Ok(out)
}
