// SENTINEL DESK 1.0 — Collectors (§7 pipeline stage 1)
//
// The collector is the ONLY component that touches the Windows Event Log and
// it does so STRICTLY READ-ONLY (§3/§12):
//   * no EvtClearLog, no EvtUpdateLog, no log/archive config changes,
//   * no subscription changes, no audit policy changes, no channel config
//     changes, no elevation attempts (never UAC-prompt),
//   * a failing channel is reported in source health with the exact reason
//     and is never silently dropped.
//
// Selection:
//   * `cfg(windows)`                            → WindowsCollector (real, read-only)
//   * `cfg(all(not(windows), feature="demo-fixtures"))` → SyntheticCollector (labeled demo)
//   * otherwise                                  → UnavailableCollector (honest error)
//
// `fixtures` (deterministic scenario builders, ported 1:1 from the web
// prototype's generator.ts) is ALWAYS compiled because rule_test (MODULE 03)
// runs dry-run fixture evaluation on every platform, including Windows.

pub mod fixtures;
pub mod windows_event_log;

use serde::{Deserialize, Serialize};
use serde_json::Map;

/// A raw Windows Event Log record in the identical payload shape produced by
/// the web prototype's synthetic source, so normalizer/detection code ports
/// without semantic changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawWindowsEvent {
    pub channel: String,
    pub provider: String,
    pub event_id: u32,
    pub level: String,
    pub computer: String,
    pub record_id: String,
    /// UTC ISO-8601
    pub time_created: String,
    /// EventData / System fields extracted from the record (name → value).
    #[serde(default)]
    pub raw_data: Map<String, serde_json::Value>,
    /// Full rendered event XML (provenance; empty for the demo fixtures where
    /// provenance is the synthetic sourceRef instead).
    #[serde(default)]
    pub raw_xml: String,
    pub synthetic: bool,
    /// Provenance reference, e.g. "evt:Security#12345" or "fixtures/brute_force.json#3"
    pub source_ref: String,
}

/// Health status of one event source — mirrors the web prototype's
/// SourceStatus union (`active | demo | permission_required | unavailable`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceStatus {
    Active,
    Demo,
    PermissionRequired,
    Unavailable,
}

impl SourceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            SourceStatus::Active => "active",
            SourceStatus::Demo => "demo",
            SourceStatus::PermissionRequired => "permission_required",
            SourceStatus::Unavailable => "unavailable",
        }
    }
}

/// Static definition of one logical event channel. `logical` matches the
/// channel names used by the rule catalog (`rules/windows.json`).
#[derive(Debug, Clone, Copy)]
pub struct ChannelDef {
    pub logical: &'static str,
    pub display_name: &'static str,
    pub description: &'static str,
    /// Real Windows channel path used with EvtQuery (None = not a real channel).
    pub windows_path: Option<&'static str>,
    /// True when the channel typically requires elevated privileges or the
    /// "Event Log Readers" group. The app NEVER elevates by itself (§12).
    pub requires_admin: bool,
}

/// The five channels Sentinel Desk 1.0 is allowed to read (§3 scope).
pub const CHANNELS: &[ChannelDef] = &[
    ChannelDef {
        logical: "Security",
        display_name: "Security",
        description: "Audited logons, process creation, task/service and audit-policy events.",
        windows_path: Some("Security"),
        requires_admin: true,
    },
    ChannelDef {
        logical: "System",
        display_name: "System",
        description: "Service Control Manager installs and system-level events.",
        windows_path: Some("System"),
        requires_admin: false,
    },
    ChannelDef {
        logical: "PowerShell/Operational",
        display_name: "PowerShell (Operational)",
        description: "PowerShell script-block logging (4104).",
        windows_path: Some("Microsoft-Windows-PowerShell/Operational"),
        requires_admin: false,
    },
    ChannelDef {
        logical: "TaskScheduler/Operational",
        display_name: "Task Scheduler (Operational)",
        description: "Scheduled task registration (106) events.",
        windows_path: Some("Microsoft-Windows-TaskScheduler/Operational"),
        requires_admin: false,
    },
    ChannelDef {
        logical: "Sysmon",
        display_name: "Sysmon",
        description: "Optional Sysmon telemetry (process creation, network connections). Inert when Sysmon is not installed.",
        windows_path: Some("Microsoft-Windows-Sysmon/Operational"),
        requires_admin: false,
    },
];

pub fn channel_by_logical(logical: &str) -> Option<&'static ChannelDef> {
    CHANNELS.iter().find(|c| c.logical == logical)
}

/// Per-channel collection report — degradations are always explicit (§12).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceReport {
    pub channel: String,
    pub windows_path: Option<String>,
    pub status: SourceStatus,
    /// Exact reason for a degraded status ("access denied", "channel not found", …).
    pub note: Option<String>,
    pub collected: usize,
}

/// Result of one collect() call.
#[derive(Debug, Default)]
pub struct CollectBatch {
    pub events: Vec<RawWindowsEvent>,
    pub source_reports: Vec<SourceReport>,
}

/// Collector contract (§7 stage 1). Implementations must be read-only and
/// must degrade per channel — never abort a whole batch because one channel
/// failed.
pub trait Collector: Send {
    fn name(&self) -> &'static str;
    /// Pull at most `batch_max` events (total across channels), newest first.
    fn collect(&mut self, batch_max: usize) -> Result<CollectBatch, String>;
}

/// Build the collector appropriate for this build/platform.
pub fn create_collector() -> Box<dyn Collector> {
    #[cfg(windows)]
    let collector: Box<dyn Collector> = Box::new(windows_event_log::WindowsCollector::new());
    #[cfg(all(not(windows), feature = "demo-fixtures"))]
    let collector: Box<dyn Collector> = Box::new(fixtures::SyntheticCollector::new());
    #[cfg(all(not(windows), not(feature = "demo-fixtures")))]
    let collector: Box<dyn Collector> = Box::new(windows_event_log::UnavailableCollector);
    collector
}

/// Helper shared by collectors: cap the per-channel share of a batch.
pub fn per_channel_cap(batch_max: usize, channels: usize) -> usize {
    if channels == 0 {
        batch_max
    } else {
        std::cmp::max(1, batch_max / channels)
    }
}
