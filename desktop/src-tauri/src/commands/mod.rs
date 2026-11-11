// SENTINEL DESK 1.0 — Tauri command surface
//
// Every command is validated (security::), parameterized (no string-built
// SQL) and returns Result<_, String>. Commands never execute event content,
// never touch the filesystem beyond the app-owned database, and never
// elevate.

pub mod collector;
pub mod events;
pub mod incidents;
pub mod overview;
pub mod reports;
pub mod rules;
pub mod settings;
