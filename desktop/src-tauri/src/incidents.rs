// SENTINEL DESK 1.0 — Incident engine (§7 stage 5, MODULE 05)
//
// Port of the web prototype's incident clustering (pipeline.ts): alerts
// grouped by host within the 20-minute correlation window, with the same
// creation policy. The hypothesis wording is IDENTICAL to the web build —
// incidents are explicitly hypotheses, never confirmations.

use crate::detection::rules_catalog::Severity;
use crate::storage::{new_id, now_iso};
use rusqlite::Connection;
use serde::Serialize;

pub const INCIDENT_WINDOW_SEC: u64 = 20 * 60;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IncidentCreated {
    pub id: String,
    pub code: String,
    pub title: String,
    pub severity: String,
}

/// Alert row subset used for clustering (already persisted in this tick).
struct ClusterAlert {
    id: String,
    rule_id: String,
    title: String,
    severity: String,
    computer: Option<String>,
    created_at_ms: i64,
}

fn severity_rank(s: &str) -> u8 {
    Severity::parse(s).map(|x| x.rank()).unwrap_or(0)
}

fn next_incident_code(conn: &Connection) -> Result<String, String> {
    let max: Option<String> = conn
        .query_row(
            "SELECT code FROM incidents ORDER BY CAST(SUBSTR(code, 5) AS INTEGER) DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .ok();
    let n = match max {
        Some(code) => code
            .strip_prefix("INC-")
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0),
        None => 0,
    };
    Ok(format!("INC-{:04}", n + 1))
}

/// Cluster `fresh_alert_ids` (alerts created in this tick, still unlinked) by
/// computer within the correlation window and open incidents per policy:
///   * any high/critical alert always opens a case;
///   * medium/low clusters open a case only when ≥ 2 distinct rules converge.
pub fn run_incident_engine(conn: &Connection, fresh_alert_ids: &[String]) -> Result<Vec<IncidentCreated>, String> {
    let mut created = Vec::new();
    if fresh_alert_ids.is_empty() {
        return Ok(created);
    }

    // Load the fresh alerts (created_at parsed once, here)
    let ids_json = serde_json::to_string(fresh_alert_ids).map_err(|e| e.to_string())?;
    let mut stmt = conn
        .prepare(
            "SELECT id, rule_id, title, severity, computer, created_at
             FROM alerts WHERE id IN (SELECT value FROM json_each(?1))",
        )
        .map_err(|e| format!("incident engine: prepare: {e}"))?;
    let rows = stmt
        .query_map(rusqlite::params![ids_json], |row| {
            let created_iso: String = row.get(5)?;
            let created_at_ms = chrono::DateTime::parse_from_rfc3339(&created_iso)
                .map(|d| d.timestamp_millis())
                .unwrap_or(0);
            Ok(ClusterAlert {
                id: row.get(0)?,
                rule_id: row.get(1)?,
                title: row.get(2)?,
                severity: row.get(3)?,
                computer: row.get(4)?,
                created_at_ms,
            })
        })
        .map_err(|e| format!("incident engine: query: {e}"))?;
    let mut alerts: Vec<ClusterAlert> = Vec::new();
    for row in rows {
        alerts.push(row.map_err(|e| format!("incident engine: row: {e}"))?);
    }
    drop(stmt);

    // Group by host
    let mut by_host: std::collections::HashMap<String, Vec<ClusterAlert>> = std::collections::HashMap::new();
    for a in alerts {
        let host = a.computer.clone().unwrap_or_else(|| "unknown".to_string());
        by_host.entry(host).or_default().push(a);
    }

    let window_ms = (INCIDENT_WINDOW_SEC * 1000) as i64;

    for (host, mut list) in by_host {
        list.sort_by_key(|a| a.created_at_ms);
        if list.is_empty() {
            continue;
        }
        // Cluster: all fresh alerts within the window of the earliest one
        // (same semantics as the web prototype's per-host clustering pass).
        let base = list[0].created_at_ms;
        let cluster: Vec<&ClusterAlert> = list
            .iter()
            .filter(|a| a.created_at_ms - base <= window_ms)
            .collect();
        if cluster.is_empty() {
            continue;
        }

        let top_sev = cluster
            .iter()
            .map(|a| a.severity.as_str())
            .max_by_key(|s| severity_rank(s))
            .unwrap_or("info")
            .to_string();

        let mut rule_ids: Vec<&str> = cluster.iter().map(|a| a.rule_id.as_str()).collect();
        rule_ids.sort_unstable();
        rule_ids.dedup();
        let distinct_rules = rule_ids.len();

        // Creation policy (identical to pipeline.ts)
        if severity_rank(&top_sev) < 3 && distinct_rules < 2 {
            continue;
        }

        let anchor = cluster
            .iter()
            .copied()
            .find(|a| severity_rank(&a.severity) == severity_rank(&top_sev))
            .unwrap_or(cluster[0]);
        let code = next_incident_code(conn)?;
        let now = now_iso();
        let title = anchor.title.clone();

        let hypothesis = format!(
            "Correlation hypothesis — NOT a confirmed compromise. {} distinct rule match(es) ({}) on {} grouped within the {}s correlation window. Linked by: computer. A human analyst must verify causation.",
            distinct_rules,
            rule_ids.join(", "),
            host,
            INCIDENT_WINDOW_SEC,
        );
        let correlation_meta = serde_json::json!({
            "fields": ["computer"],
            "windowSec": INCIDENT_WINDOW_SEC,
            "host": host,
            "inferred": true,
        })
        .to_string();

        conn.execute(
            "INSERT INTO incidents (id, code, title, severity, status, hypothesis, correlation_meta, summary, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, 'new', ?5, ?6, NULL, ?7, ?7)",
            rusqlite::params![new_id(), code, title, top_sev, hypothesis, correlation_meta, now],
        )
        .map_err(|e| format!("incident insert failed: {e}"))?;

        let incident_id: String = conn
            .query_row("SELECT id FROM incidents WHERE code = ?1", rusqlite::params![code], |r| r.get(0))
            .map_err(|e| format!("incident reload failed: {e}"))?;

        for a in &cluster {
            conn.execute(
                "UPDATE alerts SET incident_id = ?1, status = 'linked_to_incident' WHERE id = ?2",
                rusqlite::params![incident_id, a.id],
            )
            .map_err(|e| format!("alert link failed: {e}"))?;
        }

        conn.execute(
            "INSERT INTO incident_notes (id, incident_id, author, body, created_at) VALUES (?1, ?2, 'system', ?3, ?4)",
            rusqlite::params![
                new_id(),
                incident_id,
                format!(
                    "Incident opened automatically by the incident engine. {} alert(s) grouped on host {} — linked fields: computer · correlation window: {}s. Review each alert's evidence in the timeline before drawing conclusions.",
                    cluster.len(),
                    host,
                    INCIDENT_WINDOW_SEC
                ),
                now
            ],
        )
        .map_err(|e| format!("incident note failed: {e}"))?;

        conn.execute(
            "INSERT INTO audit_log (id, actor, action, target, detail, created_at) VALUES (?1, 'local-analyst', 'incident.create', ?2, ?3, ?4)",
            rusqlite::params![new_id(), code, format!("{} alerts on {}", cluster.len(), host), now],
        )
        .map_err(|e| format!("incident audit failed: {e}"))?;

        created.push(IncidentCreated {
            id: incident_id,
            code,
            title,
            severity: top_sev,
        });
    }

    Ok(created)
}
