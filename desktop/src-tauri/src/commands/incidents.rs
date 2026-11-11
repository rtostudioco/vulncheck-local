// SENTINEL DESK 1.0 — Incidents commands (MODULE 05: Incident Center)

use serde_json::{json, Value};
use tauri::State;

use crate::security::{clean_text, is_valid_status, page_args, valid_status_transition};
use crate::storage::{new_id, now_iso};
use crate::AppState;

#[tauri::command]
pub fn incidents_list(
    state: State<'_, AppState>,
    status: Option<String>,
    page: Option<i64>,
    page_size: Option<i64>,
) -> Result<Value, String> {
    let conn = state.db.lock().map_err(|_| "database busy".to_string())?;
    let (page, size) = page_args(page.unwrap_or(1), page_size.unwrap_or(50));
    let offset = (page - 1) * size;

    let mut params: Vec<String> = Vec::new();
    let where_sql = match status.as_deref().and_then(|v| clean_text(v, 20)) {
        Some(s) if is_valid_status(&s) => {
            params.push(s);
            format!("WHERE status = ?{}", params.len())
        }
        _ => String::new(),
    };

    let total: i64 = {
        let sql = format!("SELECT COUNT(*) FROM incidents {where_sql}");
        let mut stmt = conn.prepare(&sql).map_err(|e| e.to_string())?;
        stmt.query_row(rusqlite::params_from_iter(params.iter()), |r| r.get(0))
            .map_err(|e| e.to_string())?
    };

    let mut incidents = Vec::new();
    {
        let sql = format!(
            "SELECT id, code, title, severity, status, hypothesis, created_at, updated_at
             FROM incidents {where_sql} ORDER BY updated_at DESC LIMIT {size} OFFSET {offset}"
        );
        let mut stmt = conn.prepare(&sql).map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(rusqlite::params_from_iter(params.iter()), |row| {
                Ok(json!({
                    "id": row.get::<_, String>(0)?,
                    "code": row.get::<_, String>(1)?,
                    "title": row.get::<_, String>(2)?,
                    "severity": row.get::<_, String>(3)?,
                    "status": row.get::<_, String>(4)?,
                    "hypothesis": row.get::<_, Option<String>>(5)?,
                    "createdAt": row.get::<_, String>(6)?,
                    "updatedAt": row.get::<_, String>(7)?,
                }))
            })
            .map_err(|e| e.to_string())?;
        for r in rows.flatten() {
            incidents.push(r);
        }
    }

    Ok(json!({ "incidents": incidents, "total": total, "page": page, "pageSize": size }))
}

#[tauri::command]
pub fn incident_get(state: State<'_, AppState>, id: String) -> Result<Value, String> {
    let conn = state.db.lock().map_err(|_| "database busy".to_string())?;

    let mut incident = conn
        .query_row(
            "SELECT id, code, title, severity, status, hypothesis, correlation_meta, summary, created_at, updated_at
             FROM incidents WHERE id = ?1",
            [&id],
            |row| {
                Ok(json!({
                    "id": row.get::<_, String>(0)?,
                    "code": row.get::<_, String>(1)?,
                    "title": row.get::<_, String>(2)?,
                    "severity": row.get::<_, String>(3)?,
                    "status": row.get::<_, String>(4)?,
                    "hypothesis": row.get::<_, Option<String>>(5)?,
                    "correlationMeta": row.get::<_, Option<String>>(6)?.and_then(|s| serde_json::from_str::<Value>(&s).ok()),
                    "summary": row.get::<_, Option<String>>(7)?,
                    "createdAt": row.get::<_, String>(8)?,
                    "updatedAt": row.get::<_, String>(9)?,
                }))
            },
        )
        .map_err(|_| "incident_not_found".to_string())?;

    // Related alerts
    let mut alerts = Vec::new();
    {
        let mut stmt = conn
            .prepare(
                "SELECT a.id, a.rule_id, r.name, a.severity, a.confidence, a.status, a.summary, a.evidence, a.created_at
                 FROM alerts a JOIN detection_rules r ON r.id = a.rule_id
                 WHERE a.incident_id = ?1 ORDER BY a.created_at",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([&id], |row| {
                Ok(json!({
                    "id": row.get::<_, String>(0)?,
                    "ruleId": row.get::<_, String>(1)?,
                    "ruleName": row.get::<_, String>(2)?,
                    "severity": row.get::<_, String>(3)?,
                    "confidence": row.get::<_, i64>(4)?,
                    "status": row.get::<_, String>(5)?,
                    "summary": row.get::<_, String>(6)?,
                    "evidence": serde_json::from_str::<Value>(&row.get::<_, String>(7)?).unwrap_or(json!([])),
                    "createdAt": row.get::<_, String>(8)?,
                }))
            })
            .map_err(|e| e.to_string())?;
        for r in rows.flatten() {
            alerts.push(r);
        }
    }

    // Notes
    let mut notes = Vec::new();
    {
        let mut stmt = conn
            .prepare("SELECT id, author, body, created_at FROM incident_notes WHERE incident_id = ?1 ORDER BY created_at")
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([&id], |row| {
                Ok(json!({
                    "id": row.get::<_, String>(0)?,
                    "author": row.get::<_, String>(1)?,
                    "body": row.get::<_, String>(2)?,
                    "createdAt": row.get::<_, String>(3)?,
                }))
            })
            .map_err(|e| e.to_string())?;
        for r in rows.flatten() {
            notes.push(r);
        }
    }

    incident["alerts"] = Value::Array(alerts);
    incident["notes"] = Value::Array(notes);
    Ok(incident)
}

#[tauri::command]
pub fn incident_status(state: State<'_, AppState>, id: String, status: String) -> Result<Value, String> {
    if !is_valid_status(&status) {
        return Err("invalid_status".into());
    }
    let conn = state.db.lock().map_err(|_| "database busy".to_string())?;
    let current: String = conn
        .query_row("SELECT status FROM incidents WHERE id = ?1", [&id], |r| r.get(0))
        .map_err(|_| "incident_not_found".to_string())?;
    if !valid_status_transition(&current, &status) {
        return Err(format!("invalid_transition:{current}->{status}"));
    }
    conn.execute(
        "UPDATE incidents SET status = ?2, updated_at = ?3 WHERE id = ?1",
        rusqlite::params![id, status, now_iso()],
    )
    .map_err(|e| e.to_string())?;
    let code: String = conn
        .query_row("SELECT code FROM incidents WHERE id = ?1", [&id], |r| r.get(0))
        .unwrap_or_default();
    conn.execute(
        "INSERT INTO audit_log (id, actor, action, target, detail, created_at)
         VALUES (?1, 'local-analyst', 'incident.status', ?2, ?3, ?4)",
        rusqlite::params![new_id(), code, format!("{current} -> {status}"), now_iso()],
    )
    .map_err(|e| e.to_string())?;
    Ok(json!({ "id": id, "code": code, "status": status }))
}

#[tauri::command]
pub fn incident_note_add(state: State<'_, AppState>, id: String, body: String) -> Result<Value, String> {
    let body = clean_text(&body, 4000).ok_or("note_empty")?;
    let conn = state.db.lock().map_err(|_| "database busy".to_string())?;
    let exists: i64 = conn
        .query_row("SELECT COUNT(*) FROM incidents WHERE id = ?1", [&id], |r| r.get(0))
        .map_err(|e| e.to_string())?;
    if exists == 0 {
        return Err("incident_not_found".into());
    }
    let note_id = new_id();
    let now = now_iso();
    conn.execute(
        "INSERT INTO incident_notes (id, incident_id, author, body, created_at) VALUES (?1, ?2, 'analyst', ?3, ?4)",
        rusqlite::params![note_id, id, body, now],
    )
    .map_err(|e| e.to_string())?;
    conn.execute("UPDATE incidents SET updated_at = ?2 WHERE id = ?1", rusqlite::params![id, now])
        .map_err(|e| e.to_string())?;
    Ok(json!({ "id": note_id, "author": "analyst", "body": body, "createdAt": now }))
}
