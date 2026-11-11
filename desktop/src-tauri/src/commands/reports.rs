// SENTINEL DESK 1.0 — Reports commands (MODULE 10)

use serde_json::Value;
use tauri::State;

use crate::reports;
use crate::AppState;

fn since_iso(range: &str) -> String {
    let days = match range {
        "24h" => 1,
        "30d" => 30,
        "all" => 0, // epoch
        _ => 7,
    };
    if days == 0 {
        "1970-01-01T00:00:00.000Z".to_string()
    } else {
        (chrono::Utc::now() - chrono::Duration::days(days))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
    }
}

#[tauri::command]
pub fn report_json(state: State<'_, AppState>, range: Option<String>) -> Result<Value, String> {
    let range = range.unwrap_or_else(|| "7d".to_string());
    let conn = state.db.lock().map_err(|_| "database busy".to_string())?;
    let payload = reports::build_json_report(&conn, &since_iso(&range), &range)?;
    Ok(reports::with_integrity(payload))
}

#[tauri::command]
pub fn report_csv(state: State<'_, AppState>, scope: Option<String>, range: Option<String>) -> Result<String, String> {
    let scope = scope.unwrap_or_else(|| "events".to_string());
    let range = range.unwrap_or_else(|| "7d".to_string());
    let conn = state.db.lock().map_err(|_| "database busy".to_string())?;
    match scope.as_str() {
        "alerts" => reports::build_alerts_csv(&conn, &since_iso(&range)),
        _ => reports::build_events_csv(&conn, &since_iso(&range)),
    }
}
