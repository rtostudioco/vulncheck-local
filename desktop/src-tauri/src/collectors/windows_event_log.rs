// SENTINEL DESK 1.0 — REAL Windows Event Log collector (read-only)
//
// ┌─────────────────────────────────────────────────────────────────────────┐
// │ READ-ONLY GUARANTEE (§3, §12)                                           │
// │                                                                         │
// │ This module uses the Windows Event Log API (wevtapi.dll) exclusively    │
// │ for QUERIES: EvtQuery → EvtNext → EvtRender → EvtClose.                 │
// │                                                                         │
// │ It NEVER:                                                               │
// │   * calls EvtClearLog / EvtUpdateLog (no log clearing or modification), │
// │   * changes channel configuration, log paths or sizes,                  │
// │   * touches audit policy (no AuditPol, no registry, no wevtutil),       │
// │   * creates subscriptions or bookmarks that alter channel state,        │
// │   * elevates privileges — access problems are REPORTED, never worked    │
// │     around with UAC prompts or token manipulation (§12).                │
// └─────────────────────────────────────────────────────────────────────────┘
//
// Channels are attempted independently. A failing channel produces an explicit
// SourceReport with the exact reason ("access denied" / "channel not found")
// and is never silently dropped.
//
// NOTE (TODO-verify on first Windows build): signatures were verified against
// windows v0.58.0 generated bindings (EvtQuery(session, path, query, flags: u32)
// -> Result<EVT_HANDLE>; EvtNext(resultset, &mut [isize], timeout, flags,
// returned) -> Result<()>; EvtRender(context, fragment, flags: u32, buffersize,
// buffer: Option<*mut c_void>, …) -> Result<()>; EvtClose(object) -> Result<()>).
// If the `windows` crate version in Cargo.toml is changed, re-verify these call
// shapes against that version's bindings.

use super::{per_channel_cap, CollectBatch, Collector, RawWindowsEvent, SourceReport, SourceStatus, CHANNELS};
use serde_json::{Map, Value};

/// Maximum records pulled per EvtNext call.
const EVT_NEXT_BATCH: usize = 32;
/// EvtNext timeout in milliseconds.
const EVT_NEXT_TIMEOUT_MS: u32 = 1000;

// ─────────────────────────────────────────────────────────────────────────────
// Pure XML parsing (compiles on every platform; unit-testable off-Windows).
// The real collector renders events as XML (EvtRenderEventXml) and we extract
// System + EventData fields with bounded regular expressions — no dynamic
// evaluation anywhere (§12).
// ─────────────────────────────────────────────────────────────────────────────

/// Map a Windows event `Level` number to the prototype's level vocabulary.
fn level_name(level: u32) -> &'static str {
    match level {
        1 => "Critical",
        2 => "Error",
        3 => "Warning",
        // 0 = LogAlways, 4 = Information, 5 = Verbose → Information
        _ => "Information",
    }
}

fn decode_entities(input: &str) -> String {
    if !input.contains('&') {
        return input.to_string();
    }
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'&' {
            if let Some(rel) = input[i..].find(';') {
                let entity = &input[i + 1..i + rel];
                let replacement = match entity {
                    "lt" => Some('<'),
                    "gt" => Some('>'),
                    "amp" => Some('&'),
                    "quot" => Some('"'),
                    "apos" => Some('\''),
                    _ => {
                        if let Some(hex) = entity.strip_prefix("#x").or_else(|| entity.strip_prefix("#X")) {
                            u32::from_str_radix(hex, 16).ok().and_then(char::from_u32)
                        } else if let Some(dec) = entity.strip_prefix('#') {
                            dec.parse::<u32>().ok().and_then(char::from_u32)
                        } else {
                            None
                        }
                    }
                };
                if let Some(ch) = replacement {
                    out.push(ch);
                    i += rel + 1;
                    continue;
                }
            }
        }
        // safe: ASCII '&' check + char boundaries preserved via char_indices logic below
        let ch_len = input[i..].chars().next().map(char::len_utf8).unwrap_or(1);
        out.push_str(&input[i..i + ch_len]);
        i += ch_len;
    }
    out
}

/// Parse one rendered event XML into a `RawWindowsEvent`.
///
/// `logical_channel` is the rule-catalog channel name ("Security",
/// "PowerShell/Operational", …) assigned by the caller that issued the query;
/// the raw XML's own `<Channel>` (the Windows path) is preserved inside
/// `raw_data` as `__channelPath` for provenance.
pub fn parse_event_xml(xml: &str, logical_channel: &str) -> Option<RawWindowsEvent> {
    use regex::Regex;

    if xml.is_empty() {
        return None;
    }

    let re_event_id = Regex::new(r"<EventID[^>]*>(\d+)</EventID>").ok()?;
    let re_level = Regex::new(r"<Level>(\d+)</Level>").ok();
    let re_time = Regex::new(r#"<TimeCreated[^>]*SystemTime="([^"]+)""#).ok();
    let re_computer = Regex::new(r"<Computer>([^<]*)</Computer>").ok();
    let re_provider = Regex::new(r#"<Provider[^>]*Name="([^"]*)""#).ok();
    let re_record = Regex::new(r"<EventRecordID>(\d+)</EventRecordID>").ok();
    let re_sec_user = Regex::new(r#"<Security[^>]*UserID="([^"]+)""#).ok();
    let re_channel_path = Regex::new(r#"<Channel>([^<]*)</Channel>"#).ok();
    let re_named = Regex::new(r#"(?s)<Data\s+Name="([^"]*)">(.*?)</Data>"#).ok();
    let re_unnamed = Regex::new(r"(?s)<Data>(.*?)</Data>").ok();

    let event_id: u32 = re_event_id
        .captures(xml)
        .and_then(|c| c.get(1))
        .and_then(|m| m.as_str().parse().ok())?;

    let mut raw_data: Map<String, Value> = Map::new();

    if let Some(re) = re_channel_path.as_ref() {
        if let Some(c) = re.captures(xml).and_then(|c| c.get(1)) {
            raw_data.insert("__channelPath".into(), Value::String(c.as_str().to_string()));
        }
    }
    if let Some(re) = re_sec_user.as_ref() {
        if let Some(c) = re.captures(xml).and_then(|c| c.get(1)) {
            raw_data.insert("UserId".into(), Value::String(c.as_str().to_string()));
        }
    }
    // EventData: named pairs first, then unnamed values as Value0..ValueN.
    let mut unnamed_idx = 0usize;
    if let Some(re) = re_named.as_ref() {
        for cap in re.captures_iter(xml) {
            let name = cap.get(1).map(|m| m.as_str()).unwrap_or_default().to_string();
            let value = decode_entities(cap.get(2).map(|m| m.as_str()).unwrap_or_default());
            raw_data.insert(name, Value::String(value));
        }
    }
    if let Some(re) = re_unnamed.as_ref() {
        for cap in re.captures_iter(xml) {
            let value = decode_entities(cap.get(1).map(|m| m.as_str()).unwrap_or_default());
            raw_data.insert(format!("Value{unnamed_idx}"), Value::String(value));
            unnamed_idx += 1;
        }
    }

    let level = re_level
        .as_ref()
        .and_then(|re| re.captures(xml))
        .and_then(|c| c.get(1))
        .and_then(|m| m.as_str().parse::<u32>().ok())
        .map(level_name)
        .unwrap_or("Information")
        .to_string();

    let time_created = re_time
        .as_ref()
        .and_then(|re| re.captures(xml))
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
        .unwrap_or_default();

    let computer = re_computer
        .as_ref()
        .and_then(|re| re.captures(xml))
        .and_then(|c| c.get(1))
        .map(|m| decode_entities(m.as_str()))
        .unwrap_or_default();

    let provider = re_provider
        .as_ref()
        .and_then(|re| re.captures(xml))
        .and_then(|c| c.get(1))
        .map(|m| decode_entities(m.as_str()))
        .unwrap_or_else(|| "unknown".to_string());

    let record_id = re_record
        .as_ref()
        .and_then(|re| re.captures(xml))
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
        .unwrap_or_default();

    if computer.is_empty() || time_created.is_empty() {
        // A record without computer/time cannot be provenanced — skip it.
        return None;
    }

    let source_ref = format!("evt:{logical_channel}#{record_id}");

    Some(RawWindowsEvent {
        channel: logical_channel.to_string(),
        provider,
        event_id,
        level,
        computer,
        record_id,
        time_created,
        raw_data,
        raw_xml: xml.to_string(),
        synthetic: false,
        source_ref,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Channel availability classification — exact reasons, never silent.
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum ChannelError {
    /// Access denied — read permission missing (Security channel typically
    /// needs elevated context or "Event Log Readers" membership).
    PermissionDenied,
    /// Channel not present on this machine (e.g. Sysmon not installed).
    NotFound,
    /// Anything else, with the raw error text preserved.
    Other(String),
}

impl ChannelError {
    pub fn status(&self) -> SourceStatus {
        match self {
            ChannelError::PermissionDenied => SourceStatus::PermissionRequired,
            ChannelError::NotFound | ChannelError::Other(_) => SourceStatus::Unavailable,
        }
    }
    pub fn note(&self) -> String {
        match self {
            ChannelError::PermissionDenied => {
                "Access denied. Grant this account read access (e.g. 'Event Log Readers' group) and restart the app. Sentinel Desk never elevates or changes audit policy by itself.".to_string()
            }
            ChannelError::NotFound => {
                "Channel not found on this machine. For Sysmon this means Sysmon is not installed — the source is inert, not failed.".to_string()
            }
            ChannelError::Other(msg) => format!("Channel query failed: {msg}"),
        }
    }
}

/// Map a windows-core error to a channel failure class via its HRESULT.
/// 0x80070005 ACCESS_DENIED · 0x80070002 FILE_NOT_FOUND · 0x80070490 NOT_FOUND
/// · 0x80073A9F ERROR_EVT_CHANNEL_NOT_FOUND (15007).
#[cfg(windows)]
fn classify(err: &windows::core::Error) -> ChannelError {
    let code = err.code().0 as u32; // TODO-verify: Error::code() -> HRESULT(pub i32)
    match code {
        0x8007_0005 => ChannelError::PermissionDenied,
        0x8007_0002 | 0x8007_0490 | 0x8007_3A9F => ChannelError::NotFound,
        _ => ChannelError::Other(err.to_string()),
    }
}

/// EvtNext signals exhaustion with ERROR_NO_MORE_ITEMS (259 → 0x80070103).
#[cfg(windows)]
fn is_no_more_items(err: &windows::core::Error) -> bool {
    err.code().0 as u32 == 0x8007_0103
}

#[cfg(windows)]
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Real collector (Windows only)
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(windows)]
pub struct WindowsCollector;

#[cfg(windows)]
impl Default for WindowsCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(windows)]
impl WindowsCollector {
    pub fn new() -> Self {
        Self
    }

    /// Lightweight availability probe used at startup to seed source health.
    /// Opens and immediately closes a query — strictly read-only.
    pub fn probe_channel(path: &str) -> Result<(), ChannelError> {
        let path_wide = to_wide(path);
        let query_wide = to_wide("*");
        let handle = unsafe {
            windows::Win32::System::EventLog::EvtQuery(
                windows::Win32::System::EventLog::EVT_HANDLE::default(),
                windows::core::PCWSTR(path_wide.as_ptr()),
                windows::core::PCWSTR(query_wide.as_ptr()),
                windows::Win32::System::EventLog::EvtQueryChannelPath.0,
            )
            .map_err(|e| classify(&e))?
        };
        let _ = unsafe { windows::Win32::System::EventLog::EvtClose(handle) };
        Ok(())
    }

    /// Read up to `cap` newest events from one channel. Read-only.
    fn collect_channel(path: &str, cap: usize) -> Result<Vec<RawWindowsEvent>, ChannelError> {
        use windows::core::PCWSTR;
        use windows::Win32::System::EventLog::{
            EvtClose, EvtNext, EvtQuery, EvtQueryChannelPath, EvtQueryReverseDirection, EVT_HANDLE,
        };

        let path_wide = to_wide(path);
        let query_wide = to_wide("*"); // all events; filtering happens downstream

        // EvtQuery with a channel path + reverse direction → newest records first.
        // TODO-verify: `flags` is a plain u32 in windows 0.58 — the typed
        // EVT_QUERY_FLAGS constants are passed via `.0`.
        let query: EVT_HANDLE = unsafe {
            EvtQuery(
                EVT_HANDLE::default(), // local machine session (null)
                PCWSTR(path_wide.as_ptr()),
                PCWSTR(query_wide.as_ptr()),
                EvtQueryChannelPath.0 | EvtQueryReverseDirection.0,
            )
            .map_err(|e| classify(&e))?
        };

        let mut out: Vec<RawWindowsEvent> = Vec::new();
        {
            let mut handles = [0isize; EVT_NEXT_BATCH];
            loop {
                let mut returned: u32 = 0;
                let next_result = unsafe {
                    EvtNext(query, &mut handles, EVT_NEXT_TIMEOUT_MS, 0, &mut returned)
                };
                if let Err(e) = next_result {
                    if is_no_more_items(&e) {
                        break;
                    }
                    let _ = unsafe { EvtClose(query) };
                    return Err(ChannelError::Other(format!("EvtNext failed: {e}")));
                }
                if returned == 0 {
                    break;
                }
                for &h in handles.iter().take(returned as usize) {
                    let event = EVT_HANDLE(h);
                    match unsafe { render_event_xml(event) } {
                        Ok(xml) => {
                            if let Some(raw) = parse_event_xml(&xml, "") {
                                out.push(raw);
                            }
                        }
                        Err(msg) => {
                            // A single unrenderable record never aborts the batch;
                            // the failure is recorded and collection continues.
                            eprintln!("sentinel-desk: EvtRender failed on one record: {msg}");
                        }
                    }
                    // ALWAYS close per-record handles.
                    let _ = unsafe { EvtClose(event) };
                    if out.len() >= cap {
                        break;
                    }
                }
                if out.len() >= cap {
                    break;
                }
            }
        }
        let _ = unsafe { EvtClose(query) };
        Ok(out)
    }
}

#[cfg(windows)]
/// Two-call EvtRender to fetch the event XML string.
/// TODO-verify: buffer param is `Option<*mut core::ffi::c_void>` in 0.58.
unsafe fn render_event_xml(event: windows::Win32::System::EventLog::EVT_HANDLE) -> Result<String, String> {
    use windows::Win32::System::EventLog::{EvtRender, EvtRenderEventXml, EVT_HANDLE};

    let mut used: u32 = 0;
    let mut props: u32 = 0;
    EvtRender(
        EVT_HANDLE::default(), // no render context → full event XML
        event,
        EvtRenderEventXml.0,
        0,
        None,
        &mut used,
        &mut props,
    )
    .map_err(|e| format!("EvtRender(size): {e}"))?;

    if used == 0 {
        return Ok(String::new());
    }

    let mut buf = vec![0u16; (used as usize / 2) + 1];
    let mut used2: u32 = 0;
    EvtRender(
        EVT_HANDLE::default(),
        event,
        EvtRenderEventXml.0,
        used,
        Some(buf.as_mut_ptr().cast::<core::ffi::c_void>()),
        &mut used2,
        &mut props,
    )
    .map_err(|e| format!("EvtRender: {e}"))?;

    let len = (used2 as usize).min(buf.len());
    buf.truncate(len);
    Ok(String::from_utf16_lossy(&buf))
}

#[cfg(windows)]
impl Collector for WindowsCollector {
    fn name(&self) -> &'static str {
        "windows-event-log (read-only)"
    }

    fn collect(&mut self, batch_max: usize) -> Result<CollectBatch, String> {
        let mut batch = CollectBatch::default();
        let cap = per_channel_cap(batch_max, CHANNELS.len());

        for channel in CHANNELS {
            let Some(path) = channel.windows_path else { continue };
            let report = match Self::collect_channel(path, cap) {
                Ok(mut events) => {
                    let count = events.len();
                    for e in events.iter_mut() {
                        e.channel = channel.logical.to_string();
                        e.source_ref = format!("evt:{}#{}", channel.logical, e.record_id);
                    }
                    batch.events.extend(events);
                    SourceReport {
                        channel: channel.logical.to_string(),
                        windows_path: Some(path.to_string()),
                        status: SourceStatus::Active,
                        note: None,
                        collected: count,
                    }
                }
                Err(err) => SourceReport {
                    channel: channel.logical.to_string(),
                    windows_path: Some(path.to_string()),
                    status: err.status(),
                    note: Some(err.note()),
                    collected: 0,
                },
            };
            batch.source_reports.push(report);
        }

        // Respect the overall batch cap (channels were capped individually).
        if batch_max > 0 && batch.events.len() > batch_max {
            batch.events.truncate(batch_max);
        }
        Ok(batch)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Non-Windows stub: compiles everywhere, honestly reports unavailability.
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(not(windows))]
pub struct UnavailableCollector;

#[cfg(not(windows))]
impl Collector for UnavailableCollector {
    fn name(&self) -> &'static str {
        "unavailable"
    }

    fn collect(&mut self, _batch_max: usize) -> Result<CollectBatch, String> {
        let mut batch = CollectBatch::default();
        for channel in CHANNELS {
            batch.source_reports.push(SourceReport {
                channel: channel.logical.to_string(),
                windows_path: channel.windows_path.map(str::to_string),
                status: SourceStatus::Unavailable,
                note: Some(
                    "The real Windows Event Log collector requires a Windows host. This build was started on a non-Windows platform without the demo-fixtures feature.".to_string(),
                ),
                collected: 0,
            });
        }
        Ok(batch)
    }
}

/// Hostname helper (used by the overview "machine" badge).
pub fn machine_name() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "UNKNOWN-HOST".to_string())
}
