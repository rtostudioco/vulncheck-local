// SENTINEL DESK 1.0 — Rules commands (MODULE 03: Threat Detection Engine)

use serde_json::{json, Value};
use tauri::State;

use crate::collectors::fixtures;
use crate::detection::engine;
use crate::detection::rules_catalog;
use crate::storage::{new_id, now_iso};
use crate::AppState;

#[tauri::command]
pub fn rules_list(state: State<'_, AppState>) -> Result<Value, String> {
    let conn = state.db.lock().map_err(|_| "database busy".to_string())?;
    let mut rules = Vec::new();
    let mut stmt = conn
        .prepare(
            "SELECT r.id, r.name, r.description, r.version, r.author, r.severity, r.category,
                    r.mitre_id, r.mitre_name, r.enabled, r.logic, r.false_positives, r.limitations,
                    r.evidence_fields,
                    (SELECT COUNT(*) FROM alerts a WHERE a.rule_id = r.id) AS alert_count
             FROM detection_rules r ORDER BY r.id",
        )
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([], |row| {
            Ok(json!({
                "id": row.get::<_, String>(0)?,
                "name": row.get::<_, String>(1)?,
                "description": row.get::<_, String>(2)?,
                "version": row.get::<_, String>(3)?,
                "author": row.get::<_, String>(4)?,
                "severity": row.get::<_, String>(5)?,
                "category": row.get::<_, String>(6)?,
                "mitreId": row.get::<_, Option<String>>(7)?,
                "mitreName": row.get::<_, Option<String>>(8)?,
                "enabled": row.get::<_, i64>(9)? != 0,
                "logic": serde_json::from_str::<Value>(&row.get::<_, String>(10)?).unwrap_or(Value::Null),
                "falsePositives": row.get::<_, Option<String>>(11)?,
                "limitations": row.get::<_, Option<String>>(12)?,
                "evidenceFields": serde_json::from_str::<Value>(&row.get::<_, Option<String>>(13)?.unwrap_or_else(|| "[]".into())).unwrap_or(Value::Array(vec![])),
                "alertCount": row.get::<_, i64>(14)?,
            }))
        })
        .map_err(|e| e.to_string())?;
    for r in rows.flatten() {
        rules.push(r);
    }
    Ok(json!({ "rules": rules }))
}

#[tauri::command]
pub fn rule_toggle(state: State<'_, AppState>, id: String, enabled: bool) -> Result<Value, String> {
    let conn = state.db.lock().map_err(|_| "database busy".to_string())?;
    let changed = conn
        .execute("UPDATE detection_rules SET enabled = ?2 WHERE id = ?1", rusqlite::params![id, i64::from(enabled)])
        .map_err(|e| e.to_string())?;
    if changed == 0 {
        return Err("rule_not_found".into());
    }
    conn.execute(
        "INSERT INTO audit_log (id, actor, action, target, detail, created_at)
         VALUES (?1, 'local-analyst', 'rule.toggle', ?2, ?3, ?4)",
        rusqlite::params![new_id(), id, if enabled { "enabled" } else { "disabled" }, now_iso()],
    )
    .map_err(|e| e.to_string())?;
    Ok(json!({ "id": id, "enabled": enabled }))
}

/// Dry-run rule test against its bundled deterministic fixture (same contract
/// as the web prototype's POST /api/rules/[id]/test). Nothing is persisted.
#[tauri::command]
pub fn rule_test(state: State<'_, AppState>, id: String) -> Result<Value, String> {
    let def = rules_catalog::rule_by_id(&id).ok_or("rule_not_found")?;

    // Rule disabled? Report the DB toggle for UI context (test still runs).
    let db_enabled: bool = {
        let conn = state.db.lock().map_err(|_| "database busy".to_string())?;
        conn.query_row("SELECT enabled FROM detection_rules WHERE id = ?1", [&id], |r| {
            r.get::<_, i64>(0)
        })
        .map(|v| v != 0)
        .unwrap_or(true)
    };

    let started = std::time::Instant::now();
    let raws = fixtures::rule_test_fixture(&def.test.fixture)?;
    let mut events = crate::normalizer::normalize_batch(&raws);
    // Fixture-scoped ids so correlation evidence resolves (same fix as web)
    for (i, e) in events.iter_mut().enumerate() {
        e.id = Some(format!("fixture-{i}"));
    }

    let defs: Vec<&rules_catalog::RuleDef> = rules_catalog::rules().iter().collect();
    let base = engine::evaluate_rules(&defs, &events);
    let correlated = engine::evaluate_correlations(&defs, &base, &events);
    let matches: Vec<&engine::DetectionMatch> = base
        .iter()
        .chain(correlated.iter())
        .filter(|m| m.rule_id == id)
        .collect();

    let matched = !matches.is_empty();
    let explanation = if matched {
        engine::explain_match(def, &matches[0].evidence)
    } else {
        "No match on the rule's labeled fixture set — check rule logic and fixture mapping.".to_string()
    };

    Ok(json!({
        "matched": matched,
        "matchCount": matches.len(),
        "fixtureEvents": events.len(),
        "explanation": explanation,
        "evidenceSample": if matched { serde_json::to_value(&matches[0].evidence).unwrap_or(json!([])) } else { json!([]) },
        "fixtureScenario": def.test.fixture,
        "elapsedMs": started.elapsed().as_millis(),
        "ruleEnabledInDb": db_enabled,
    }))
}
