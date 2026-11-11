// SENTINEL DESK 1.0 — Security helpers (§12)
//
// Every Tauri command validates its inputs before touching the database.
// Sentinel Desk never evaluates dynamic content, never executes event data
// and never issues shell commands; these helpers keep that guarantee at the
// command boundary.

/// Cap a free-text input. Returns None for empty-after-trim strings.
pub fn clean_text(v: &str, max_len: usize) -> Option<String> {
    let t = v.trim();
    if t.is_empty() {
        None
    } else {
        Some(t.chars().take(max_len).collect())
    }
}

/// Validate an incident status transition (state machine, § MODULE 05):
///   new → investigating | monitoring | resolved | false_positive
///   investigating → monitoring | resolved | false_positive
///   monitoring → investigating | resolved | false_positive
///   resolved → investigating (reopen) | false_positive
///   false_positive → investigating (reopen)
pub fn valid_status_transition(from: &str, to: &str) -> bool {
    if from == to {
        return false;
    }
    match from {
        "new" => matches!(to, "investigating" | "monitoring" | "resolved" | "false_positive"),
        "investigating" | "monitoring" => {
            matches!(to, "investigating" | "monitoring" | "resolved" | "false_positive")
        }
        "resolved" | "false_positive" => matches!(to, "investigating" | "false_positive"),
        _ => false,
    }
}

pub const INCIDENT_STATUSES: &[&str] = &["new", "investigating", "monitoring", "resolved", "false_positive"];

pub fn is_valid_status(s: &str) -> bool {
    INCIDENT_STATUSES.contains(&s)
}

/// Cap pagination arguments (defensive against absurd queries).
pub fn page_args(page: i64, page_size: i64) -> (i64, i64) {
    let size = page_size.clamp(10, 200);
    let page = page.max(1);
    (page, size)
}
