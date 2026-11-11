// SENTINEL DESK 1.0 — Settings + audit commands

use serde_json::{json, Value};
use tauri::State;

use crate::security::clean_text;
use crate::storage::AppSettings;
use crate::AppState;

#[tauri::command]
pub fn settings_get(state: State<'_, AppState>) -> Result<Value, String> {
    let conn = state.db.lock().map_err(|_| "database busy".to_string())?;
    let s = crate::storage::load_settings(&conn);
    Ok(serde_json::to_value(&s).map_err(|e| e.to_string())?)
}

#[tauri::command]
pub fn settings_save(
    state: State<'_, AppState>,
    language: Option<String>,
    collector_interval_sec: Option<u64>,
    retention_days: Option<u64>,
    collector_auto_start: Option<bool>,
) -> Result<Value, String> {
    let conn = state.db.lock().map_err(|_| "database busy".to_string())?;
    let mut s = crate::storage::load_settings(&conn);
    if let Some(l) = language.as_deref().and_then(|v| clean_text(v, 8)) {
        if l == "en" || l == "es" {
            s.language = l;
        }
    }
    if let Some(v) = collector_interval_sec {
        s.collector_interval_sec = v.clamp(5, 3600);
    }
    if let Some(v) = retention_days {
        s.retention_days = v.clamp(1, 365);
    }
    if let Some(v) = collector_auto_start {
        s.collector_auto_start = v;
    }
    crate::storage::save_settings(&conn, &s)?;
    conn.execute(
        "INSERT INTO audit_log (id, actor, action, target, detail, created_at)
         VALUES (?1, 'local-analyst', 'settings.update', 'app', ?2, ?3)",
        rusqlite::params![
            crate::storage::new_id(),
            serde_json::to_string(&s).unwrap_or_default(),
            crate::storage::now_iso()
        ],
    )
    .map_err(|e| e.to_string())?;
    Ok(serde_json::to_value(&s).map_err(|e| e.to_string())?)
}

#[tauri::command]
pub fn audit_list(state: State<'_, AppState>, limit: Option<i64>) -> Result<Value, String> {
    let limit = limit.unwrap_or(100).clamp(1, 500);
    let conn = state.db.lock().map_err(|_| "database busy".to_string())?;
    let mut entries = Vec::new();
    let mut stmt = conn
        .prepare("SELECT actor, action, target, detail, created_at FROM audit_log ORDER BY created_at DESC LIMIT ?1")
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([limit], |row| {
            Ok(json!({
                "actor": row.get::<_, String>(0)?,
                "action": row.get::<_, String>(1)?,
                "target": row.get::<_, Option<String>>(2)?,
                "detail": row.get::<_, Option<String>>(3)?,
                "createdAt": row.get::<_, String>(4)?,
            }))
        })
        .map_err(|e| e.to_string())?;
    for r in rows.flatten() {
        entries.push(r);
    }
    Ok(json!({ "entries": entries }))
}

/// Current settings type is re-exported for the lib state.
pub type SettingsPayload = AppSettings;
