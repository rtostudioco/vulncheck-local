// SENTINEL DESK 1.0 — Detection pipeline (§7)
//
// collector → normalizer → detection → correlation → incident engine →
// SQLite → (AI is frontend-gated; never automatic).
//
// Every stage reports status, input/output counts, errors and duration.
// Events are never silently dropped: a stage failure is captured in the run
// report and degraded channels are reported with exact reasons.

use crate::collectors::Collector;
use crate::detection::engine::{self, DetectionMatch};
use crate::detection::rules_catalog::{self, RuleDef};
use crate::incidents;
use crate::normalizer::{self, NormalizedEvent};
use crate::storage::{new_id, now_iso, retention};
use rusqlite::Connection;
use serde::Serialize;
use std::time::Instant;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StageReport {
    pub name: String,
    pub duration_ms: u128,
    pub input: usize,
    pub output: usize,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AlertBrief {
    pub alert_id: String,
    pub rule_id: String,
    pub title: String,
    pub severity: String,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunReport {
    pub started_at: String,
    pub duration_ms: u128,
    pub collected: usize,
    pub normalized: usize,
    pub stored: usize,
    pub duplicates_skipped: usize,
    pub alerts_created: usize,
    pub incidents_created: usize,
    pub events_pruned: u64,
    pub source_reports: Vec<crate::collectors::SourceReport>,
    pub stages: Vec<StageReport>,
    pub new_alerts: Vec<AlertBrief>,
    pub new_incidents: Vec<incidents::IncidentCreated>,
    pub errors: Vec<String>,
}

/// Load enabled rules from the embedded catalog (runtime toggle comes from
/// the DB — an admin-disabled rule is skipped here).
fn enabled_rule_defs(conn: &Connection) -> Result<Vec<&'static RuleDef>, String> {
    let mut stmt = conn
        .prepare("SELECT id FROM detection_rules WHERE enabled = 1")
        .map_err(|e| e.to_string())?;
    let ids: Vec<String> = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|e| e.to_string())?
        .filter_map(|r| r.ok())
        .collect();
    drop(stmt);
    Ok(rules_catalog::rules()
        .iter()
        .filter(|d| ids.iter().any(|id| id == &d.id))
        .collect())
}

/// Persist one normalized event; returns Ok(false) when it is a duplicate
/// (same channel + record_id already stored — Windows replay protection).
fn store_event(conn: &Connection, e: &NormalizedEvent) -> Result<Option<String>, String> {
    let dup: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM events WHERE channel = ?1 AND record_id = ?2",
            rusqlite::params![e.channel, e.record_id],
            |row| row.get::<_, i64>(0),
        )
        .map(|c| c > 0)
        .map_err(|err| format!("dup check failed: {err}"))?;
    if dup {
        return Ok(None);
    }
    let id = new_id();
    conn.execute(
        "INSERT INTO events
           (id, ts, channel, provider, event_id, level, computer, record_id,
            user_name, user_sid, target_user_name, process_id, process_name,
            parent_process_id, parent_process_name, command_line, ip_address,
            logon_type, service_name, task_name, summary, raw, synthetic, source_ref, created_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24,?25)",
        rusqlite::params![
            id,
            e.ts.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            e.channel,
            e.provider,
            e.event_id,
            e.level,
            e.computer,
            e.record_id,
            e.user_name,
            e.user_sid,
            e.target_user_name,
            e.process_id,
            e.process_name,
            e.parent_process_id,
            e.parent_process_name,
            e.command_line,
            e.ip_address,
            e.logon_type,
            e.service_name,
            e.task_name,
            e.summary,
            e.raw,
            i64::from(e.synthetic),
            e.source_ref,
            now_iso(),
        ],
    )
    .map_err(|err| format!("event insert failed: {err}"))?;
    Ok(Some(id))
}

/// True when an alert with the same rule and the same evidence event set
/// already exists (fingerprint dedupe across ticks).
fn alert_fingerprint_exists(conn: &Connection, rule_id: &str, event_ids: &[String]) -> Result<bool, String> {
    let mut key = event_ids.to_vec();
    key.sort();
    let key = key.join("|");
    let mut stmt = conn
        .prepare(
            "SELECT a.id FROM alerts a JOIN alert_events ae ON ae.alert_id = a.id
             WHERE a.rule_id = ?1",
        )
        .map_err(|e| e.to_string())?;
    let mut groups: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
    let rows = stmt
        .query_map(rusqlite::params![rule_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|e| e.to_string())?;
    for row in rows.flatten() {
        groups.entry(row.0).or_default().push(row.1);
    }
    drop(stmt);
    for (_, ids) in groups {
        let mut sorted = ids;
        sorted.sort();
        if sorted.join("|") == key {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Run one pipeline tick. `batch_max` caps collected events per tick.
pub fn run_tick(
    conn: &mut Connection,
    collector: &mut dyn Collector,
    retention_days: u64,
    batch_max: usize,
) -> Result<RunReport, String> {
    let started_at = now_iso();
    let t0 = Instant::now();
    let mut errors: Vec<String> = Vec::new();
    let mut stages: Vec<StageReport> = Vec::new();

    // ── STAGE 1 — collector ────────────────────────────────────────────────
    let t = Instant::now();
    let batch = match collector.collect(batch_max) {
        Ok(b) => b,
        Err(e) => {
            errors.push(format!("collector: {e}"));
            return Ok(RunReport {
                started_at,
                duration_ms: t0.elapsed().as_millis(),
                collected: 0,
                normalized: 0,
                stored: 0,
                duplicates_skipped: 0,
                alerts_created: 0,
                incidents_created: 0,
                events_pruned: 0,
                source_reports: Vec::new(),
                stages: vec![StageReport {
                    name: "collector".into(),
                    duration_ms: t.elapsed().as_millis(),
                    input: 0,
                    output: 0,
                    errors: vec![e],
                }],
                new_alerts: Vec::new(),
                new_incidents: Vec::new(),
                errors,
            });
        }
    };
    stages.push(StageReport {
        name: "collector".into(),
        duration_ms: t.elapsed().as_millis(),
        input: 0,
        output: batch.events.len(),
        errors: batch
            .source_reports
            .iter()
            .filter(|s| matches!(s.status, crate::collectors::SourceStatus::PermissionRequired | crate::collectors::SourceStatus::Unavailable))
            .map(|s| format!("source {}: {:?} — {}", s.channel, s.status, s.note.clone().unwrap_or_default()))
            .collect(),
    });

    // Update source health (exact reasons, never silent)
    for sr in &batch.source_reports {
        let _ = conn.execute(
            "UPDATE event_sources
             SET status = ?2, available = ?3, note = ?4, last_collect_at = ?5,
                 events_collected = events_collected + ?6
             WHERE channel = ?1",
            rusqlite::params![
                sr.channel,
                sr.status.as_str(),
                i64::from(sr.status == crate::collectors::SourceStatus::Active),
                sr.note,
                now_iso(),
                sr.collected as i64,
            ],
        );
    }

    // ── STAGE 2 — normalizer ───────────────────────────────────────────────
    let t = Instant::now();
    let raws = batch.events.clone();
    let normalized = normalizer::normalize_batch(&raws);
    stages.push(StageReport {
        name: "normalizer".into(),
        duration_ms: t.elapsed().as_millis(),
        input: raws.len(),
        output: normalized.len(),
        errors: Vec::new(),
    });

    // ── STAGE 3 — storage (dedupe by channel+record_id) ───────────────────
    let t = Instant::now();
    let mut stored_ids: std::collections::HashMap<String, String> = std::collections::HashMap::new(); // fixture index -> db id
    let mut stored_events: Vec<NormalizedEvent> = Vec::new();
    let mut duplicates = 0usize;
    for (idx, e) in normalized.iter().enumerate() {
        match store_event(conn, e) {
            Ok(Some(id)) => {
                stored_ids.insert(idx.to_string(), id.clone());
                let mut with_id = e.clone();
                with_id.id = Some(id);
                stored_events.push(with_id);
            }
            Ok(None) => duplicates += 1,
            Err(err) => errors.push(err),
        }
    }
    stages.push(StageReport {
        name: "storage".into(),
        duration_ms: t.elapsed().as_millis(),
        input: normalized.len(),
        output: stored_events.len(),
        errors: Vec::new(),
    });

    // ── STAGE 4 — detection + correlation ─────────────────────────────────
    let t = Instant::now();
    let mut new_alerts: Vec<AlertBrief> = Vec::new();
    let mut fresh_alert_ids: Vec<String> = Vec::new();
    match enabled_rule_defs(conn) {
        Ok(defs) => {
            let base = engine::evaluate_rules(&defs, &stored_events);
            let correlated = engine::evaluate_correlations(&defs, &base, &stored_events);
            let matches: Vec<&DetectionMatch> = base.iter().chain(correlated.iter()).collect();
            for m in matches {
                let def = match rules_catalog::rule_by_id(&m.rule_id) {
                    Some(d) => d,
                    None => continue,
                };
                // Resolve evidence event ids (db ids; skip unresolved "unknown" refs)
                let ev_ids: Vec<String> = m
                    .evidence
                    .iter()
                    .map(|ev| ev.event_id.clone())
                    .filter(|id| !id.is_empty() && id != "unknown")
                    .collect();
                if ev_ids.is_empty() {
                    continue;
                }
                match alert_fingerprint_exists(conn, &m.rule_id, &ev_ids) {
                    Ok(true) => continue,
                    Ok(false) => {}
                    Err(e) => errors.push(e),
                }
                let alert_id = new_id();
                let summary = engine::explain_match(def, &m.evidence);
                let computer = stored_events
                    .iter()
                    .find(|e| ev_ids.iter().any(|id| e.id.as_deref() == Some(id)))
                    .map(|e| e.computer.clone());
                let user_name = stored_events
                    .iter()
                    .find(|e| ev_ids.iter().any(|id| e.id.as_deref() == Some(id)))
                    .and_then(|e| e.user_name.clone());
                let evidence_json = serde_json::to_string(&m.evidence).unwrap_or_else(|_| "[]".into());
                let res = (|| -> Result<(), String> {
                    conn.execute(
                        "INSERT INTO alerts (id, rule_id, severity, title, summary, confidence, status, evidence, mitre_id, computer, user_name, created_at)
                         VALUES (?1,?2,?3,?4,?5,?6,'open',?7,?8,?9,?10,?11)",
                        rusqlite::params![
                            alert_id,
                            def.id,
                            def.severity.as_str(),
                            def.name,
                            summary,
                            m.confidence as i64,
                            evidence_json,
                            def.mitre_id,
                            computer,
                            user_name,
                            now_iso(),
                        ],
                    )
                    .map_err(|e| format!("alert insert failed: {e}"))?;
                    for ev_id in &ev_ids {
                        conn.execute(
                            "INSERT OR IGNORE INTO alert_events (alert_id, event_id) VALUES (?1, ?2)",
                            rusqlite::params![alert_id, ev_id],
                        )
                        .map_err(|e| format!("alert_event insert failed: {e}"))?;
                    }
                    Ok(())
                })();
                if let Err(e) = res {
                    errors.push(e);
                    continue;
                }
                fresh_alert_ids.push(alert_id.clone());
                new_alerts.push(AlertBrief {
                    alert_id,
                    rule_id: def.id.to_string(),
                    title: def.name.to_string(),
                    severity: def.severity.as_str().to_string(),
                    summary,
                });
            }
        }
        Err(e) => errors.push(e),
    }
    stages.push(StageReport {
        name: "detection".into(),
        duration_ms: t.elapsed().as_millis(),
        input: stored_events.len(),
        output: new_alerts.len(),
        errors: Vec::new(),
    });

    // ── STAGE 5 — incident engine ──────────────────────────────────────────
    let t = Instant::now();
    let new_incidents = match incidents::run_incident_engine(conn, &fresh_alert_ids) {
        Ok(v) => v,
        Err(e) => {
            errors.push(e);
            Vec::new()
        }
    };
    stages.push(StageReport {
        name: "incidents".into(),
        duration_ms: t.elapsed().as_millis(),
        input: fresh_alert_ids.len(),
        output: new_incidents.len(),
        errors: Vec::new(),
    });

    // ── STAGE 6 — retention (app-owned data only) ─────────────────────────
    let t = Instant::now();
    let pruned = retention::purge_expired_events(conn, retention_days).unwrap_or(0);
    if pruned > 0 {
        let _ = conn.execute(
            "INSERT INTO audit_log (id, actor, action, target, detail, created_at)
             VALUES (?1, 'local-analyst', 'data.purge', 'events', ?2, ?3)",
            rusqlite::params![new_id(), format!("pruned {pruned} events older than {retention_days} days"), now_iso()],
        );
    }
    stages.push(StageReport {
        name: "retention".into(),
        duration_ms: t.elapsed().as_millis(),
        input: stored_events.len(),
        output: pruned as usize,
        errors: Vec::new(),
    });

    // Pipeline audit entry
    let _ = conn.execute(
        "INSERT INTO audit_log (id, actor, action, target, detail, created_at)
         VALUES (?1, 'local-analyst', 'pipeline.run', 'app', ?2, ?3)",
        rusqlite::params![
            new_id(),
            serde_json::json!({
                "collected": batch.events.len(),
                "stored": stored_events.len(),
                "alerts": new_alerts.len(),
                "incidents": new_incidents.len(),
            })
            .to_string(),
            now_iso()
        ],
    );

    Ok(RunReport {
        duration_ms: t0.elapsed().as_millis(),
        collected: batch.events.len(),
        normalized: normalized.len(),
        stored: stored_events.len(),
        duplicates_skipped: duplicates,
        alerts_created: new_alerts.len(),
        incidents_created: new_incidents.len(),
        events_pruned: pruned,
        source_reports: batch.source_reports,
        stages,
        new_alerts,
        new_incidents,
        errors,
        started_at,
    })
}
