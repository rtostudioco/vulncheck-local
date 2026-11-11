// SENTINEL DESK 1.0 — Detection Engine (§7 stage 3)
//
// Port of the verified web prototype's `src/lib/engine/detection.ts`.
// Evaluates normalized events against the versioned rule catalog. Three kinds:
//   single      — per-event condition matchers (AND across conditions)
//   threshold   — grouped sliding-window count (e.g. 5× 4625 / 5 min / host)
//   correlation — combinations of prior rule alerts (+ optional direct event
//                 conditions) within a window, linked by shared identifiers
//
// Every match returns its matched evidence (event ids + which fields matched
// with which operator) so the UI can explain WHY a rule fired (§8, §9).

use super::rules_catalog::{Condition, FieldOp, RuleDef, RuleLogic};
use crate::normalizer::NormalizedEvent;
use serde::Serialize;
use serde_json::{Map, Value};
use std::collections::{HashMap, HashSet};

// ─── Evidence types (identical JSON shape to the web prototype) ────────────

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct EvidenceMatch {
    pub field: String,
    pub value: String,
    pub op: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct EvidenceRef {
    pub event_id: String,
    pub matched: Vec<EvidenceMatch>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DetectionMatch {
    pub rule_id: String,
    pub evidence: Vec<EvidenceRef>,
    pub confidence: u8,
}

/// Field bag exposed to condition matchers — identical fields to the
/// prototype's `fieldBag`.
fn field_bag(e: &NormalizedEvent) -> Map<String, Value> {
    let mut bag = Map::new();
    bag.insert("ts".into(), Value::String(e.ts.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)));
    bag.insert("channel".into(), Value::String(e.channel.clone()));
    bag.insert("eventId".into(), Value::Number(e.event_id.into()));
    bag.insert("level".into(), Value::String(e.level.clone()));
    bag.insert("computer".into(), Value::String(e.computer.clone()));
    if let Some(v) = &e.user_name {
        bag.insert("userName".into(), Value::String(v.clone()));
    }
    if let Some(v) = &e.user_sid {
        bag.insert("userSid".into(), Value::String(v.clone()));
    }
    if let Some(v) = &e.target_user_name {
        bag.insert("targetUserName".into(), Value::String(v.clone()));
    }
    if let Some(v) = e.process_id {
        bag.insert("processId".into(), Value::Number(v.into()));
    }
    if let Some(v) = &e.process_name {
        bag.insert("processName".into(), Value::String(v.clone()));
    }
    if let Some(v) = &e.parent_process_name {
        bag.insert("parentProcessName".into(), Value::String(v.clone()));
    }
    if let Some(v) = &e.command_line {
        bag.insert("commandLine".into(), Value::String(v.clone()));
    }
    if let Some(v) = &e.ip_address {
        bag.insert("ipAddress".into(), Value::String(v.clone()));
    }
    if let Some(v) = e.logon_type {
        bag.insert("logonType".into(), Value::Number(v.into()));
    }
    if let Some(v) = &e.service_name {
        bag.insert("serviceName".into(), Value::String(v.clone()));
    }
    if let Some(v) = &e.task_name {
        bag.insert("taskName".into(), Value::String(v.clone()));
    }
    bag.insert("summary".into(), Value::String(e.summary.clone()));
    bag
}

/// `safeRegex` port: fancy-regex adds lookarounds/backreferences on top of the
/// standard `regex` crate, which keeps rule SD-008's verbatim negative-lookahead
/// IP pattern working. Unsupported patterns fail CLOSED (no match), mirroring
/// the prototype's try/catch behavior.
fn safe_regex(pattern: &str, value: &str) -> bool {
    match fancy_regex::Regex::new(pattern) {
        Ok(re) => re.is_match(value).unwrap_or(false),
        Err(_) => false,
    }
}

fn as_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// Evaluate one condition against the field bag (port of `checkCondition`).
/// Missing fields never match.
fn check_condition(cond: &Condition, bag: &Map<String, Value>) -> Option<EvidenceMatch> {
    let value = bag.get(&cond.field)?;
    let vs = as_string(value);
    let ok = match cond.op {
        FieldOp::Eq => vs == as_string(&cond.value),
        FieldOp::Neq => vs != as_string(&cond.value),
        FieldOp::In => cond
            .value
            .as_array()
            .map(|arr| arr.iter().any(|v| as_string(v) == vs))
            .unwrap_or(false),
        FieldOp::Contains => vs.to_lowercase().contains(&as_string(&cond.value).to_lowercase()),
        FieldOp::StartsWith => vs.to_lowercase().starts_with(&as_string(&cond.value).to_lowercase()),
        FieldOp::Regex => safe_regex(&as_string(&cond.value), &vs),
        FieldOp::Gt => num_cmp(value, &cond.value, |ord| ord == std::cmp::Ordering::Greater),
        FieldOp::Lt => num_cmp(value, &cond.value, |ord| ord == std::cmp::Ordering::Less),
    };
    let cut = vs.char_indices().nth(300).map(|(i, _)| i).unwrap_or(vs.len());
    ok.then(|| EvidenceMatch {
        field: cond.field.clone(),
        value: vs[..cut].to_string(),
        op: op_as_str(&cond.op),
    })
}

fn op_as_str(op: &FieldOp) -> String {
    match op {
        FieldOp::Eq => "eq".into(),
        FieldOp::In => "in".into(),
        FieldOp::Neq => "neq".into(),
        FieldOp::Contains => "contains".into(),
        FieldOp::Regex => "regex".into(),
        FieldOp::StartsWith => "startsWith".into(),
        FieldOp::Gt => "gt".into(),
        FieldOp::Lt => "lt".into(),
    }
}

/// Numeric comparison with JS semantics: NaN comparisons are simply false.
fn num_cmp(a: &Value, b: &Value, pred: fn(std::cmp::Ordering) -> bool) -> bool {
    let (Some(av), Some(bv)) = (as_f64(a), as_f64(b)) else { return false };
    av.partial_cmp(&bv).map(pred).unwrap_or(false)
}

fn as_f64(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.trim().parse::<f64>().ok(),
        _ => None,
    }
}

/// Evaluate the per-event filters (eventIds / channel / conditions) of a rule
/// against a single event. Port of `checkEvent`.
fn check_event(logic: &RuleLogic, e: &NormalizedEvent) -> Option<EvidenceRef> {
    let common = logic.common();
    if !common.matches_event_id(e.event_id) {
        return None;
    }
    if !common.matches_channel(&e.channel) {
        return None;
    }
    let bag = field_bag(e);
    let mut matched = Vec::new();
    for cond in &common.conditions {
        match check_condition(cond, &bag) {
            Some(m) => matched.push(m),
            // all conditions must match (AND)
            None => return None,
        }
    }
    Some(EvidenceRef {
        event_id: e.id.clone().unwrap_or_else(|| "unknown".to_string()),
        matched,
    })
}

/// Evaluate "single" and "threshold" rules over a window of events.
/// `events` should be pre-filtered to a reasonable evaluation window.
pub fn evaluate_rules(defs: &[&RuleDef], events: &[NormalizedEvent]) -> Vec<DetectionMatch> {
    let mut matches: Vec<DetectionMatch> = Vec::new();

    for def in defs {
        let Ok(logic) = def.try_logic() else { continue };
        match &logic {
            RuleLogic::Correlation(_) => continue, // handled by correlation stage
            RuleLogic::Single(_) => {
                for e in events {
                    if let Some(ev) = check_event(&logic, e) {
                        matches.push(DetectionMatch {
                            rule_id: def.id.clone(),
                            evidence: vec![ev],
                            confidence: def.confidence,
                        });
                    }
                }
            }
            RuleLogic::Threshold(l) => {
                let spec = &l.spec;
                // group events by the groupBy fields
                let mut groups: Vec<(String, Vec<&NormalizedEvent>)> = Vec::new();
                let mut group_index: HashMap<String, usize> = HashMap::new();
                for e in events {
                    if check_event(&logic, e).is_none() {
                        continue;
                    }
                    let bag = field_bag(e);
                    let key = spec
                        .group_by
                        .iter()
                        .map(|f| bag.get(f).map(as_string).unwrap_or_default())
                        .collect::<Vec<_>>()
                        .join("|");
                    let idx = *group_index.entry(key.clone()).or_insert_with(|| {
                        groups.push((key.clone(), Vec::new()));
                        groups.len() - 1
                    });
                    groups[idx].1.push(e);
                }
                for (_, group) in &groups {
                    // sliding-window count within the group
                    let mut sorted: Vec<&NormalizedEvent> = group.clone();
                    sorted.sort_by_key(|e| e.ts);
                    'anchors: for anchor in &sorted {
                        let start = anchor.ts;
                        let end = anchor.ts + chrono::Duration::seconds(spec.window_sec as i64);
                        let in_window: Vec<&&NormalizedEvent> =
                            sorted.iter().filter(|x| x.ts >= start && x.ts <= end).collect();
                        if in_window.len() >= spec.count as usize {
                            let evidence: Vec<EvidenceRef> = in_window
                                .iter()
                                .map(|e| {
                                    let mut matched = vec![
                                        EvidenceMatch {
                                            field: "eventId".into(),
                                            value: e.event_id.to_string(),
                                            op: "eq".into(),
                                        },
                                        EvidenceMatch {
                                            field: "computer".into(),
                                            value: e.computer.clone(),
                                            op: "eq".into(),
                                        },
                                    ];
                                    if let Some(t) = &e.target_user_name {
                                        matched.push(EvidenceMatch {
                                            field: "targetUserName".into(),
                                            value: t.clone(),
                                            op: "in".into(),
                                        });
                                    }
                                    if let Some(ip) = &e.ip_address {
                                        matched.push(EvidenceMatch {
                                            field: "ipAddress".into(),
                                            value: ip.clone(),
                                            op: "eq".into(),
                                        });
                                    }
                                    EvidenceRef {
                                        event_id: e.id.clone().unwrap_or_else(|| "unknown".to_string()),
                                        matched,
                                    }
                                })
                                .collect();
                            let bonus = in_window.len() as i64 - spec.count as i64;
                            let confidence = ((i64::from(def.confidence) + bonus).min(95)).max(0) as u8;
                            matches.push(DetectionMatch {
                                rule_id: def.id.clone(),
                                evidence,
                                confidence,
                            });
                            break 'anchors; // one match per group
                        }
                    }
                }
            }
        }
    }

    matches
}

/// Correlation stage: combine prior alerts (from signal rules) and, for rules
/// with direct event conditions, matching events — all linked by shared fields
/// within a time window. Port of `evaluateCorrelations`.
pub fn evaluate_correlations(
    defs: &[&RuleDef],
    prior_matches: &[DetectionMatch],
    events: &[NormalizedEvent],
) -> Vec<DetectionMatch> {
    let mut matches: Vec<DetectionMatch> = Vec::new();

    let mut match_by_rule: HashMap<&str, Vec<&DetectionMatch>> = HashMap::new();
    for m in prior_matches {
        match_by_rule.entry(m.rule_id.as_str()).or_default().push(m);
    }

    for def in defs {
        let Ok(RuleLogic::Correlation(cl)) = def.try_logic() else { continue };
        // Validated above; rebind once for the direct-condition matcher below.
        let Ok(logic) = def.try_logic() else { continue };
        let window_ms = cl.window_sec * 1000;

        let events_by_id: HashMap<&str, &NormalizedEvent> = events
            .iter()
            .filter_map(|e| e.id.as_deref().map(|id| (id, e)))
            .collect();

        // Which prior matches fall on each host inside a window (per rule)?
        let prior_in_window = |anchor_start: i64, anchor_end: i64, host: &str| -> HashMap<String, Vec<&DetectionMatch>> {
            let mut per_rule: HashMap<String, Vec<&DetectionMatch>> = HashMap::new();
            for m in prior_matches {
                if m.rule_id == def.id {
                    continue;
                }
                let in_window = m.evidence.iter().any(|ev| {
                    events_by_id
                        .get(ev.event_id.as_str())
                        .map(|e| {
                            e.computer == host
                                && e.ts.timestamp_millis() >= anchor_start - window_ms as i64
                                && e.ts.timestamp_millis() <= anchor_end + window_ms as i64
                        })
                        .unwrap_or(false)
                });
                if in_window {
                    per_rule.entry(m.rule_id.clone()).or_default().push(m);
                }
            }
            per_rule
        };

        let mut produced: HashSet<String> = HashSet::new();

        // Anchors: any signal-rule match can anchor a candidate correlation.
        let wildcard = cl.signals.iter().find(|s| s.rule_id == "*");
        let explicit: Vec<&super::rules_catalog::SignalSpec> =
            cl.signals.iter().filter(|s| s.rule_id != "*").collect();
        let anchor_matches: Vec<&DetectionMatch> = match wildcard {
            Some(_) => prior_matches.iter().collect(),
            None => explicit
                .iter()
                .flat_map(|s| match_by_rule.get(s.rule_id.as_str()).cloned().unwrap_or_default())
                .collect(),
        };

        for anchor in anchor_matches {
            let anchor_events: Vec<&NormalizedEvent> = events
                .iter()
                .filter(|e| anchor.evidence.iter().any(|ev| ev.event_id == e.id.clone().unwrap_or_default()))
                .collect();
            if anchor_events.is_empty() {
                continue;
            }
            let anchor_start = anchor_events.iter().map(|e| e.ts.timestamp_millis()).min().unwrap_or(0);
            let anchor_end = anchor_events.iter().map(|e| e.ts.timestamp_millis()).max().unwrap_or(0);
            let Some(anchor_host) = anchor_events.first().map(|e| e.computer.clone()) else { continue };

            let window_events: Vec<&NormalizedEvent> = events
                .iter()
                .filter(|e| {
                    e.computer == anchor_host
                        && e.ts.timestamp_millis() >= anchor_start - window_ms as i64
                        && e.ts.timestamp_millis() <= anchor_end + window_ms as i64
                })
                .collect();

            // Which signal rules have at least one match inside the window?
            let per_rule = prior_in_window(anchor_start, anchor_end, &anchor_host);

            // Direct event conditions on this correlation rule itself (SD-002's 4624).
            let mut direct_evidence: Vec<EvidenceRef> = Vec::new();
            if !cl.common.event_ids.is_empty() {
                for e in &window_events {
                    if let Some(ev) = check_event(&logic, e) {
                        direct_evidence.push(ev);
                    }
                }
            }

            let satisfied = if let Some(w) = wildcard {
                per_rule.len() >= w.min_count.unwrap_or(1) as usize
            } else {
                let all = explicit.iter().all(|s| {
                    per_rule
                        .get(&s.rule_id)
                        .map(|list| list.len() >= s.min_count.unwrap_or(1) as usize)
                        .unwrap_or(false)
                });
                if all && !cl.common.event_ids.is_empty() && direct_evidence.is_empty() {
                    false
                } else {
                    all
                }
            };
            if !satisfied {
                continue;
            }

            // Merge evidence by eventId, preserving insertion order (parity
            // with the prototype's Map-based merge).
            let mut merged: Vec<(String, EvidenceRef)> = Vec::new();
            let mut merged_index: HashMap<String, usize> = HashMap::new();
            let collected = anchor
                .evidence
                .iter()
                .chain(per_rule.values().flat_map(|list| list.iter().flat_map(|m| m.evidence.iter())))
                .chain(direct_evidence.iter())
                .cloned();
            for ev in collected {
                match merged_index.get(&ev.event_id) {
                    Some(&idx) => {
                        let existing = &mut merged[idx].1;
                        for m in ev.matched {
                            if !existing.matched.iter().any(|x| x.field == m.field) {
                                existing.matched.push(m);
                            }
                        }
                    }
                    None => {
                        merged_index.insert(ev.event_id.clone(), merged.len());
                        merged.push((ev.event_id.clone(), ev));
                    }
                }
            }

            // Avoid emitting duplicate matches from different anchors covering
            // the same evidence set.
            let mut fingerprint_keys: Vec<&String> = merged_index.keys().collect();
            fingerprint_keys.sort();
            let fingerprint = fingerprint_keys
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join("|");
            if produced.contains(&fingerprint) {
                continue;
            }
            produced.insert(fingerprint);

            matches.push(DetectionMatch {
                rule_id: def.id.clone(),
                evidence: merged.into_iter().map(|(_, ev)| ev).collect(),
                confidence: def.confidence,
            });
        }
    }

    matches
}

/// Fingerprint used to dedupe alert drafts (rule + sorted evidence set).
pub fn evidence_fingerprint(m: &DetectionMatch) -> String {
    let mut ids: Vec<&str> = m.evidence.iter().map(|e| e.event_id.as_str()).collect();
    ids.sort_unstable();
    ids.dedup();
    ids.join(",")
}

/// Human-readable explanation of why a rule matched (for alerts/UI).
/// Port of `explainMatch`.
pub fn explain_match(def: &RuleDef, evidence: &[EvidenceRef]) -> String {
    let Ok(logic) = def.try_logic() else { return "rule logic unavailable".to_string() };
    let n = evidence.len();
    let link = match &logic {
        RuleLogic::Correlation(l) => {
            if l.link_by.is_empty() { "time".to_string() } else { l.link_by.join(", ") }
        }
        RuleLogic::Threshold(l) => l.spec.group_by.join(", "),
        _ => "time".to_string(),
    };
    match &logic {
        RuleLogic::Correlation(l) => {
            let signals = l
                .signals
                .iter()
                .map(|s| if s.rule_id == "*" { "any rule".to_string() } else { s.rule_id.clone() })
                .collect::<Vec<_>>()
                .join(" + ");
            format!(
                "{n} evidence event(s) linked by {link} within {}s — signals: {signals}",
                l.window_sec
            )
        }
        RuleLogic::Threshold(l) => format!(
            "{n} matching event(s) ≥ threshold {} in {}s grouped by {link}",
            l.spec.count, l.spec.window_sec
        ),
        RuleLogic::Single(l) => {
            let mut fields: Vec<String> = evidence
                .iter()
                .flat_map(|e| e.matched.iter().map(|m| m.field.clone()))
                .collect();
            fields.sort();
            fields.dedup();
            if fields.is_empty() {
                let ids = if l.common.event_ids.is_empty() {
                    "any".to_string()
                } else {
                    l.common.event_ids.iter().map(|i| i.to_string()).collect::<Vec<_>>().join("/")
                };
                let channels = if !l.common.channels.is_empty() {
                    l.common.channels.join(", ")
                } else {
                    l.common.channel.clone().unwrap_or_else(|| "any channel".to_string())
                };
                format!("Event ID {ids} observed on channel: {channels}")
            } else {
                format!("Event matched conditions on: {}", fields.join(", "))
            }
        }
    }
}
