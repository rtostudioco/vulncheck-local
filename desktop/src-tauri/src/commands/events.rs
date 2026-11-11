// SENTINEL DESK 1.0 — Events commands (MODULE 02: Live Monitor)

use serde_json::{json, Value};
use tauri::State;

use crate::security::{clean_text, page_args};
use crate::AppState;

#[tauri::command]
pub fn events_query(
    state: State<'_, AppState>,
    channel: Option<String>,
    level: Option<String>,
    computer: Option<String>,
    search: Option<String>,
    page: Option<i64>,
    page_size: Option<i64>,
) -> Result<Value, String> {
    let conn = state.db.lock().map_err(|_| "database busy".to_string())?;
    let (page, size) = page_args(page.unwrap_or(1), page_size.unwrap_or(50));
    let offset = (page - 1) * size;

    let mut where_clauses: Vec<String> = Vec::new();
    let mut params: Vec<String> = Vec::new();

    if let Some(c) = channel.as_deref().and_then(|v| clean_text(v, 80)) {
        params.push(c);
        where_clauses.push(format!("channel = ?{}", params.len()));
    }
    if let Some(l) = level.as_deref().and_then(|v| clean_text(v, 20)) {
        params.push(l);
        where_clauses.push(format!("level = ?{}", params.len()));
    }
    if let Some(c) = computer.as_deref().and_then(|v| clean_text(v, 80)) {
        params.push(c);
        where_clauses.push(format!("computer = ?{}", params.len()));
    }
    if let Some(s) = search.as_deref().and_then(|v| clean_text(v, 120)) {
        params.push(format!("%{s}%"));
        where_clauses.push(format!(
            "(summary LIKE ?{} OR command_line LIKE ?{} OR user_name LIKE ?{} OR computer LIKE ?{})",
            params.len(),
            params.len(),
            params.len(),
            params.len()
        ));
    }
    let where_sql = if where_clauses.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", where_clauses.join(" AND "))
    };

    let total: i64 = {
        let sql = format!("SELECT COUNT(*) FROM events {where_sql}");
        let mut stmt = conn.prepare(&sql).map_err(|e| e.to_string())?;
        stmt.query_row(rusqlite::params_from_iter(params.iter()), |r| r.get(0))
            .map_err(|e| e.to_string())?
    };

    let mut events = Vec::new();
    {
        let sql = format!(
            "SELECT id, ts, channel, provider, event_id, level, computer, user_name, target_user_name,
                    process_name, command_line, ip_address, summary, synthetic, source_ref, record_id
             FROM events {where_sql} ORDER BY ts DESC LIMIT {size} OFFSET {offset}"
        );
        let mut stmt = conn.prepare(&sql).map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(rusqlite::params_from_iter(params.iter()), |row| {
                Ok(json!({
                    "id": row.get::<_, String>(0)?,
                    "ts": row.get::<_, String>(1)?,
                    "channel": row.get::<_, String>(2)?,
                    "provider": row.get::<_, String>(3)?,
                    "eventId": row.get::<_, i64>(4)?,
                    "level": row.get::<_, String>(5)?,
                    "computer": row.get::<_, String>(6)?,
                    "userName": row.get::<_, Option<String>>(7)?,
                    "targetUserName": row.get::<_, Option<String>>(8)?,
                    "processName": row.get::<_, Option<String>>(9)?,
                    "commandLine": row.get::<_, Option<String>>(10)?,
                    "ipAddress": row.get::<_, Option<String>>(11)?,
                    "summary": row.get::<_, Option<String>>(12)?,
                    "synthetic": row.get::<_, i64>(13)? != 0,
                    "sourceRef": row.get::<_, Option<String>>(14)?,
                    "recordId": row.get::<_, Option<String>>(15)?,
                }))
            })
            .map_err(|e| e.to_string())?;
        for r in rows.flatten() {
            events.push(r);
        }
    }

    Ok(json!({ "events": events, "total": total, "page": page, "pageSize": size }))
}

#[tauri::command]
pub fn event_get(state: State<'_, AppState>, id: String) -> Result<Value, String> {
    let conn = state.db.lock().map_err(|_| "database busy".to_string())?;
    conn.query_row(
        "SELECT id, ts, channel, provider, event_id, level, computer, record_id, user_name, user_sid,
                target_user_name, process_id, process_name, parent_process_id, parent_process_name,
                command_line, ip_address, logon_type, service_name, task_name, summary, raw, synthetic, source_ref
         FROM events WHERE id = ?1",
        [&id],
        |row| {
            Ok(json!({
                "id": row.get::<_, String>(0)?,
                "ts": row.get::<_, String>(1)?,
                "channel": row.get::<_, String>(2)?,
                "provider": row.get::<_, String>(3)?,
                "eventId": row.get::<_, i64>(4)?,
                "level": row.get::<_, String>(5)?,
                "computer": row.get::<_, String>(6)?,
                "recordId": row.get::<_, Option<String>>(7)?,
                "userName": row.get::<_, Option<String>>(8)?,
                "userSid": row.get::<_, Option<String>>(9)?,
                "targetUserName": row.get::<_, Option<String>>(10)?,
                "processId": row.get::<_, Option<i64>>(11)?,
                "processName": row.get::<_, Option<String>>(12)?,
                "parentProcessId": row.get::<_, Option<i64>>(13)?,
                "parentProcessName": row.get::<_, Option<String>>(14)?,
                "commandLine": row.get::<_, Option<String>>(15)?,
                "ipAddress": row.get::<_, Option<String>>(16)?,
                "logonType": row.get::<_, Option<i64>>(17)?,
                "serviceName": row.get::<_, Option<String>>(18)?,
                "taskName": row.get::<_, Option<String>>(19)?,
                "summary": row.get::<_, Option<String>>(20)?,
                "raw": row.get::<_, Option<String>>(21)?,
                "synthetic": row.get::<_, i64>(22)? != 0,
                "sourceRef": row.get::<_, Option<String>>(23)?,
            }))
        },
    )
    .map_err(|_| "event_not_found".to_string())
}
