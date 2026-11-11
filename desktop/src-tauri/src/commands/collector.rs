// SENTINEL DESK 1.0 — Collector commands (MODULE 02 pipeline control)
//
// The frontend drives the loop (same model as the web prototype): it calls
// collector_tick on the configured interval. The persisted setting
// collector_auto_start is the single source of truth for "running" state.

use serde_json::{json, Value};
use tauri::State;

use crate::pipeline;
use crate::storage::now_iso;
use crate::AppState;

#[tauri::command]
pub fn collector_status(state: State<'_, AppState>) -> Result<Value, String> {
    let conn = state.db.lock().map_err(|_| "database busy".to_string())?;
    let settings = crate::storage::load_settings(&conn);
    Ok(json!({
        "running": settings.collector_auto_start,
        "intervalSec": settings.collector_interval_sec,
        "retentionDays": settings.retention_days,
        "lastTickAt": state.last_tick_at.lock().map_err(|_| "state busy")?.clone(),
        "collectorName": state.collector.lock().map_err(|_| "collector busy")?.name(),
    }))
}

#[tauri::command]
pub fn collector_start(state: State<'_, AppState>) -> Result<Value, String> {
    {
        let conn = state.db.lock().map_err(|_| "database busy".to_string())?;
        let mut settings = crate::storage::load_settings(&conn);
        settings.collector_auto_start = true;
        crate::storage::save_settings(&conn, &settings)?;
        conn.execute(
            "INSERT INTO audit_log (id, actor, action, target, detail, created_at)
             VALUES (?1, 'local-analyst', 'collector.start', 'pipeline', 'auto', ?2)",
            rusqlite::params![crate::storage::new_id(), now_iso()],
        )
        .map_err(|e| e.to_string())?;
    }
    Ok(json!({ "running": true }))
}

#[tauri::command]
pub fn collector_stop(state: State<'_, AppState>) -> Result<Value, String> {
    {
        let conn = state.db.lock().map_err(|_| "database busy".to_string())?;
        let mut settings = crate::storage::load_settings(&conn);
        settings.collector_auto_start = false;
        crate::storage::save_settings(&conn, &settings)?;
        conn.execute(
            "INSERT INTO audit_log (id, actor, action, target, detail, created_at)
             VALUES (?1, 'local-analyst', 'collector.stop', 'pipeline', 'manual', ?2)",
            rusqlite::params![crate::storage::new_id(), now_iso()],
        )
        .map_err(|e| e.to_string())?;
    }
    Ok(json!({ "running": false }))
}

/// Run one pipeline tick (collect → normalize → store → detect → correlate →
/// incidents → retention). Manual ticks are always allowed; the frontend
/// schedules them on the configured interval when running.
#[tauri::command]
pub fn collector_tick(state: State<'_, AppState>, batch_max: Option<i64>) -> Result<Value, String> {
    let batch_max = batch_max.unwrap_or(200).clamp(10, 2000) as usize;
    let (retention_days, interval_sec) = {
        let conn = state.db.lock().map_err(|_| "database busy".to_string())?;
        let s = crate::storage::load_settings(&conn);
        (s.retention_days, s.collector_interval_sec)
    };
    let mut collector = state.collector.lock().map_err(|_| "collector busy".to_string())?;
    let mut conn = state.db.lock().map_err(|_| "database busy".to_string())?;
    let run = pipeline::run_tick(&mut conn, collector.as_mut(), retention_days, batch_max)?;
    drop(conn);
    drop(collector);
    *state.last_tick_at.lock().map_err(|_| "state busy")? = Some(now_iso());
    Ok(json!({
        "ok": true,
        "intervalSec": interval_sec,
        "run": run,
    }))
}
