// SENTINEL DESK 1.0 — Event Normalizer (§7 stage 2)
//
// Port of the verified web prototype's `src/lib/engine/normalizer.ts`.
// Converts raw Windows Event Log records (XML-data shape) into the common
// normalized schema. The mapping logic is identical to the web prototype: the
// same field extraction from the EventData map, the same LOGIN_TYPES table and
// the same buildSummary cases, so both editions produce byte-comparable
// summaries for the same underlying record.

use crate::collectors::RawWindowsEvent;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Normalized, searchable event record (serde payload = camelCase, matching
/// the web prototype's JSON contract).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NormalizedEvent {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub ts: DateTime<Utc>,
    pub channel: String,
    pub provider: String,
    pub event_id: u32,
    pub level: String,
    pub computer: String,
    pub record_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_sid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_user_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_id: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_process_id: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_process_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_line: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logon_type: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_name: Option<String>,
    pub summary: String,
    pub raw: String,
    pub synthetic: bool,
    pub source_ref: String,
}

/// Same semantics as the prototype's `str()`: empty / em-dash / dash → None.
fn clean_str(v: Option<&Value>) -> Option<String> {
    let v = v?;
    let s = match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        _ => return None,
    };
    let t = s.trim();
    if t.is_empty() || t == "—" || t == "-" {
        None
    } else {
        Some(t.to_string())
    }
}

/// Same semantics as the prototype's `int()`: decimal or 0x-prefixed hex.
fn clean_int(v: Option<&Value>) -> Option<i64> {
    let s = clean_str(v)?;
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return i64::from_str_radix(hex, 16).ok();
    }
    s.parse::<i64>().ok()
}

pub const LOGIN_TYPES: [(i64, &str); 10] = [
    (2, "Interactive"),
    (3, "Network"),
    (4, "Batch"),
    (5, "Service"),
    (7, "Unlock"),
    (8, "NetworkCleartext"),
    (9, "NewCredentials"),
    (10, "RemoteInteractive"),
    (11, "CachedInteractive"),
    (0, "logon"),
];

fn login_type_name(t: Option<i64>) -> &'static str {
    let t = t.unwrap_or(0);
    LOGIN_TYPES
        .iter()
        .find(|(k, _)| *k == t)
        .map(|(_, name)| *name)
        .unwrap_or("logon")
}

fn opt_or<'a>(a: Option<&'a Value>, b: Option<&'a Value>) -> Option<&'a Value> {
    a.or(b)
}

/// Build a one-line human summary used for search and display.
/// Cases are ported verbatim from the prototype's `buildSummary`.
pub fn build_summary(e: &NormalizedEvent, raw: &RawWindowsEvent) -> String {
    let r = &raw.raw_data;
    match raw.event_id {
        4624 => format!(
            "Successful {} — {} from {}",
            login_type_name(e.logon_type),
            e.target_user_name.as_deref().unwrap_or("unknown"),
            e.ip_address.as_deref().unwrap_or("local"),
        ),
        4625 => {
            let status = match r.get("Status") {
                Some(Value::String(s)) => s.clone(),
                Some(other) => other.to_string(),
                None => String::new(),
            };
            format!(
                "Failed logon ({status}) — {} from {}",
                e.target_user_name.as_deref().unwrap_or("unknown"),
                e.ip_address.as_deref().unwrap_or("local"),
            )
        }
        4688 | 1 => match e.command_line.as_deref() {
            Some(cmd) => format!("Process created: {} — {cmd}", e.process_name.as_deref().unwrap_or("unknown")),
            None => format!("Process created: {}", e.process_name.as_deref().unwrap_or("unknown")),
        },
        4698 | 106 => match e.command_line.as_deref() {
            Some(cmd) => format!("Scheduled task created: {} — {cmd}", e.task_name.as_deref().unwrap_or("unknown")),
            None => format!("Scheduled task created: {}", e.task_name.as_deref().unwrap_or("unknown")),
        },
        4702 => format!("Scheduled task updated: {}", e.task_name.as_deref().unwrap_or("unknown")),
        7045 => format!(
            "Service installed: {} ({})",
            e.service_name.as_deref().unwrap_or("unknown"),
            e.command_line.as_deref().unwrap_or(""),
        ),
        4104 => {
            let script = match r.get("ScriptBlockText") {
                Some(Value::String(s)) => s.clone(),
                _ => String::new(),
            };
            let cut = script.char_indices().nth(160).map(|(i, _)| i).unwrap_or(script.len());
            format!("PowerShell script block: {}", &script[..cut])
        }
        4719 => {
            let changes = match r.get("AuditPolicyChanges") {
                Some(Value::Array(items)) => {
                    let parts: Vec<String> = items
                        .iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect();
                    if parts.is_empty() {
                        "policy modified".to_string()
                    } else {
                        parts.join("; ")
                    }
                }
                _ => "policy modified".to_string(),
            };
            format!("Audit policy changed by {}: {changes}", e.user_name.as_deref().unwrap_or("unknown"))
        }
        1102 => format!("Security log cleared by {}", e.user_name.as_deref().unwrap_or("unknown")),
        104 => {
            let channel = match r.get("Channel") {
                Some(Value::String(s)) => s.clone(),
                _ => "System".to_string(),
            };
            format!("System log cleared ({channel})")
        }
        3 => format!(
            "Network connection: {} → {}",
            e.process_name.as_deref().unwrap_or("unknown"),
            e.ip_address.as_deref().unwrap_or("unknown"),
        ),
        4720 => format!("User account created: {}", e.target_user_name.as_deref().unwrap_or("unknown")),
        4738 => format!("User account changed: {}", e.target_user_name.as_deref().unwrap_or("unknown")),
        _ => format!("{} EID {}", raw.provider, raw.event_id),
    }
}

/// Convert one raw record into the normalized schema (port of `normalize`).
pub fn normalize(raw: &RawWindowsEvent) -> NormalizedEvent {
    let r = &raw.raw_data;

    let mut command_line = clean_str(r.get("CommandLine"));

    // Service installation: ImagePath is the command line
    if raw.event_id == 7045 && command_line.is_none() {
        command_line = clean_str(r.get("ImagePath"));
    }
    // TaskScheduler/Security task content carries the command inside TaskContent
    if raw.event_id == 4698 && command_line.is_none() {
        if let Some(Value::String(task_content)) = r.get("TaskContent") {
            if let Some(start) = task_content.find("<Command>") {
                if let Some(end) = task_content[start..].find("</Command>") {
                    let inner = &task_content[start + "<Command>".len()..start + end];
                    command_line = Some(inner.to_string());
                }
            }
        }
    }
    if raw.event_id == 4104 && command_line.is_none() {
        command_line = clean_str(r.get("ScriptBlockText"));
    }

    let ts = DateTime::parse_from_rfc3339(&raw.time_created)
        .map(|t| t.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now());

    let mut ev = NormalizedEvent {
        id: None,
        ts,
        channel: raw.channel.clone(),
        provider: raw.provider.clone(),
        event_id: raw.event_id,
        level: raw.level.clone(),
        computer: raw.computer.clone(),
        record_id: raw.record_id.clone(),
        user_name: clean_str(opt_or(r.get("SubjectUserName"), r.get("User"))),
        user_sid: clean_str(r.get("UserId")),
        target_user_name: clean_str(r.get("TargetUserName")),
        process_id: clean_int(opt_or(opt_or(r.get("ProcessId"), r.get("NewProcessId")), r.get("ClientProcessId"))),
        process_name: clean_str(opt_or(r.get("NewProcessName"), r.get("Image"))),
        parent_process_id: clean_int(r.get("ParentProcessId")),
        parent_process_name: clean_str(opt_or(r.get("ParentProcessName"), r.get("ParentImage"))),
        command_line,
        ip_address: clean_str(opt_or(r.get("IpAddress"), r.get("DestinationIp"))),
        logon_type: clean_int(r.get("LogonType")),
        service_name: clean_str(r.get("ServiceName")),
        task_name: clean_str(r.get("TaskName")),
        summary: String::new(),
        raw: serde_json::to_string(raw).unwrap_or_else(|_| "{}".to_string()),
        synthetic: raw.synthetic,
        source_ref: raw.source_ref.clone(),
    };

    ev.summary = build_summary(&ev, raw);
    ev
}

/// Normalize a batch (port of `normalizeBatch`).
pub fn normalize_batch(raws: &[RawWindowsEvent]) -> Vec<NormalizedEvent> {
    raws.iter().map(normalize).collect()
}
