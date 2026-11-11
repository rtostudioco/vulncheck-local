// SENTINEL DESK 1.0 — binary entry
//
// Prevents an extra console window on Windows release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    sentinel_desk_lib::run()
}
