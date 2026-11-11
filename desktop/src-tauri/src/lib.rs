// SENTINEL DESK 1.0 — Tauri library entry (desktop shell)
//
// Setup order matters:
//   1. open the app-owned SQLite database (WAL, FK on)
//   2. run embedded migrations
//   3. validate + load the embedded rule catalog (fail loudly)
//   4. seed event sources + rule catalog (idempotent, preserves toggles)
//   5. build the platform collector (read-only Windows collector on Windows)
//
// The pipeline is tick-driven from the frontend (same contract as the web
// prototype) — nothing collects without the operator starting it, and the
// collector is strictly read-only towards the OS.

pub mod collectors;
pub mod commands;
pub mod detection;
pub mod incidents;
pub mod normalizer;
pub mod pipeline;
pub mod reports;
pub mod security;
pub mod storage;

use rusqlite::Connection;
use std::sync::Mutex;
use tauri::Manager;

/// Application state shared with all commands.
pub struct AppState {
    pub db: Mutex<Connection>,
    pub collector: Mutex<Box<dyn collectors::Collector>>,
    pub last_tick_at: Mutex<Option<String>>,
}

pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let data_dir = app
                .path()
                .app_data_dir()
                .map_err(|e| format!("cannot resolve app data dir: {e}"))?;
            std::fs::create_dir_all(&data_dir).map_err(|e| format!("cannot create data dir: {e}"))?;
            let db_path = data_dir.join("sentinel.db");

            let conn = storage::open_db(&db_path)?;
            storage::migrate(&conn)?;
            detection::rules_catalog::init_catalog()?;
            storage::seed_event_sources(&conn, &probe_channels())?;
            storage::seed_detection_rules(&conn)?;

            let collector = collectors::create_collector();

            app.manage(AppState {
                db: Mutex::new(conn),
                collector: Mutex::new(collector),
                last_tick_at: Mutex::new(None),
            });

            log_setup(&db_path);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::overview::overview_stats,
            commands::events::events_query,
            commands::events::event_get,
            commands::rules::rules_list,
            commands::rules::rule_toggle,
            commands::rules::rule_test,
            commands::incidents::incidents_list,
            commands::incidents::incident_get,
            commands::incidents::incident_status,
            commands::incidents::incident_note_add,
            commands::collector::collector_status,
            commands::collector::collector_start,
            commands::collector::collector_stop,
            commands::collector::collector_tick,
            commands::reports::report_json,
            commands::reports::report_csv,
            commands::settings::settings_get,
            commands::settings::settings_save,
            commands::settings::audit_list,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Sentinel Desk");
}

/// Probe each authorized channel WITHOUT collecting: records whether it is
/// readable now, so source health starts honest ("unavailable" until a first
/// tick proves otherwise on this machine).
fn probe_channels() -> std::collections::HashMap<String, (collectors::SourceStatus, Option<String>)> {
    let mut map = std::collections::HashMap::new();
    #[cfg(windows)]
    {
        for def in collectors::CHANNELS {
            if let Some(path) = def.windows_path {
                match collectors::windows_event_log::WindowsCollector::probe_channel(path) {
                    Ok(()) => {
                        map.insert(def.logical.to_string(), (collectors::SourceStatus::Active, None));
                    }
                    Err(e) => {
                        map.insert(def.logical.to_string(), (e.status(), Some(e.note())));
                    }
                }
            }
        }
    }
    #[cfg(not(windows))]
    {
        for def in collectors::CHANNELS {
            map.insert(
                def.logical.to_string(),
                (
                    collectors::SourceStatus::Unavailable,
                    Some("Non-Windows platform — Windows Event Log channels are not readable here.".to_string()),
                ),
            );
        }
    }
    map
}

fn log_setup(db_path: &std::path::Path) {
    #[cfg(debug_assertions)]
    println!("[sentinel-desk] database: {}", db_path.display());
    #[cfg(not(debug_assertions))]
    let _ = db_path;
}
