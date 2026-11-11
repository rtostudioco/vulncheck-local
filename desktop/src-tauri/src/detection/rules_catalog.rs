// SENTINEL DESK 1.0 — Rule catalog loader (MODULE 03)
//
// Embeds `rules/windows.json` at compile time (include_str!) and exposes the
// typed catalog. The JSON `logic` objects keep the EXACT RuleLogic shape used
// by the web prototype (src/lib/engine/rules.ts) so a future shared-tooling
// sync is trivial; this module only adds validation + typed accessors.

use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

/// Embedded catalog (single source of truth: rules/windows.json).
const RULES_JSON: &str = include_str!("../../../rules/windows.json");

// ─── Severity ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
    pub fn rank(self) -> u8 {
        match self {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "info" => Severity::Info,
            "low" => Severity::Low,
            "medium" => Severity::Medium,
            "high" => Severity::High,
            "critical" => Severity::Critical,
            _ => return None,
        })
    }
}

// ─── Logic shapes (serde mirrors the JSON exactly) ─────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum FieldOp {
    Eq,
    In,
    Neq,
    Contains,
    Regex,
    StartsWith,
    Gt,
    Lt,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Condition {
    pub field: String,
    pub op: FieldOp,
    pub value: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ThresholdSpec {
    pub count: u32,
    pub window_sec: u64,
    /// Event fields defining the group (e.g. ["computer"]).
    pub group_by: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SignalSpec {
    /// Rule id, or "*" for the wildcard "any rule" signal (SD-010).
    pub rule_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_count: Option<u32>,
}

/// Raw logic object as parsed from JSON (all optional fields preserved).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RuleLogicRaw {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channels: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_ids: Option<Vec<u32>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold: Option<ThresholdSpec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signals: Option<Vec<SignalSpec>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_window_sec: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_by: Option<Vec<String>>,
}

/// Fields shared by all logic kinds (event filters applied before conditions).
#[derive(Debug, Clone, PartialEq)]
pub struct CommonLogic {
    pub channel: Option<String>,
    pub channels: Vec<String>,
    pub event_ids: Vec<u32>,
    pub conditions: Vec<Condition>,
}

impl CommonLogic {
    pub fn matches_channel(&self, channel: &str) -> bool {
        if let Some(c) = &self.channel {
            return c == channel;
        }
        if self.channels.is_empty() {
            return true;
        }
        self.channels.iter().any(|c| c == channel)
    }
    pub fn matches_event_id(&self, event_id: u32) -> bool {
        self.event_ids.is_empty() || self.event_ids.contains(&event_id)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SingleLogic {
    pub common: CommonLogic,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ThresholdLogic {
    pub common: CommonLogic,
    pub spec: ThresholdSpec,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CorrelationLogic {
    pub common: CommonLogic,
    pub signals: Vec<SignalSpec>,
    pub window_sec: u64,
    pub link_by: Vec<String>,
}

/// Typed rule logic (validated at catalog load time).
#[derive(Debug, Clone, PartialEq)]
pub enum RuleLogic {
    Single(SingleLogic),
    Threshold(ThresholdLogic),
    Correlation(CorrelationLogic),
}

impl RuleLogic {
    pub fn kind(&self) -> &'static str {
        match self {
            RuleLogic::Single(_) => "single",
            RuleLogic::Threshold(_) => "threshold",
            RuleLogic::Correlation(_) => "correlation",
        }
    }
    pub fn common(&self) -> &CommonLogic {
        match self {
            RuleLogic::Single(l) => &l.common,
            RuleLogic::Threshold(l) => &l.common,
            RuleLogic::Correlation(l) => &l.common,
        }
    }
    pub fn as_raw(&self) -> RuleLogicRaw {
        // Reconstruct the raw JSON shape (used when persisting `logic`).
        let common = self.common();
        let (threshold, signals, window_sec, link_by) = match self {
            RuleLogic::Threshold(l) => (Some(l.spec.clone()), None, None, None),
            RuleLogic::Correlation(l) => (
                None,
                Some(l.signals.clone()),
                Some(l.window_sec),
                Some(l.link_by.clone()),
            ),
            RuleLogic::Single(_) => (None, None, None, None),
        };
        RuleLogicRaw {
            kind: self.kind().to_string(),
            channel: common.channel.clone(),
            channels: if common.channels.is_empty() { None } else { Some(common.channels.clone()) },
            event_ids: if common.event_ids.is_empty() { None } else { Some(common.event_ids.clone()) },
            conditions: if common.conditions.is_empty() { None } else { Some(common.conditions.clone()) },
            threshold,
            signals,
            correlation_window_sec: window_sec,
            link_by,
        }
    }

    fn from_raw(raw: RuleLogicRaw) -> Result<Self, String> {
        let common = CommonLogic {
            channel: raw.channel.clone(),
            channels: raw.channels.clone().unwrap_or_default(),
            event_ids: raw.event_ids.clone().unwrap_or_default(),
            conditions: raw.conditions.clone().unwrap_or_default(),
        };
        // Sanity: single + channel together (parity with the web RuleLogic union).
        if raw.channel.is_some() && !common.channels.is_empty() {
            return Err(format!("rule logic mixes `channel` and `channels`"));
        }
        match raw.kind.as_str() {
            "single" => Ok(RuleLogic::Single(SingleLogic { common })),
            "threshold" => {
                let spec = raw.threshold.clone().ok_or_else(|| "threshold logic requires `threshold`".to_string())?;
                Ok(RuleLogic::Threshold(ThresholdLogic { common, spec }))
            }
            "correlation" => Ok(RuleLogic::Correlation(CorrelationLogic {
                common,
                signals: raw.signals.clone().unwrap_or_default(),
                window_sec: raw.correlation_window_sec.unwrap_or(900),
                link_by: raw.link_by.clone().unwrap_or_default(),
            })),
            other => Err(format!("unknown rule logic kind '{other}'")),
        }
    }
}

// ─── Rule definition ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleTest {
    /// Fixture scenario key bundled with the app (collectors::fixtures).
    pub fixture: String,
    pub expect_match: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleDef {
    pub id: String,
    pub name: String,
    pub description: String,
    pub version: String,
    pub author: String,
    pub severity: Severity,
    pub category: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mitre_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mitre_name: Option<String>,
    pub confidence: u8,
    pub logic: RuleLogicRaw,
    pub evidence_fields: Vec<String>,
    pub false_positives: String,
    pub limitations: String,
    pub test: RuleTest,
}

impl RuleDef {
    /// Validated typed logic (fallible — the catalog is validated at startup,
    /// so runtime callers get an error instead of a panic if anything drifts).
    pub fn try_logic(&self) -> Result<RuleLogic, String> {
        RuleLogic::from_raw(self.logic.clone())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleCatalog {
    #[allow(dead_code)]
    pub product: String,
    #[allow(dead_code)]
    pub catalog_version: String,
    #[allow(dead_code)]
    #[serde(default)]
    pub comment: Vec<String>,
    pub rules: Vec<RuleDef>,
}

static CATALOG: OnceLock<RuleCatalog> = OnceLock::new();

/// Parse + validate the embedded catalog. Called during app setup so a broken
/// catalog fails startup loudly instead of misfiring later.
pub fn init_catalog() -> Result<(), String> {
    let parsed: RuleCatalog =
        serde_json::from_str(RULES_JSON).map_err(|e| format!("rules/windows.json is not valid: {e}"))?;
    let mut ids = std::collections::HashSet::new();
    for rule in &parsed.rules {
        if !ids.insert(rule.id.clone()) {
            return Err(format!("duplicate rule id {}", rule.id));
        }
        RuleLogic::from_raw(rule.logic.clone())
            .map_err(|e| format!("rule {}: {e}", rule.id))?;
        if rule.confidence > 100 {
            return Err(format!("rule {}: confidence > 100", rule.id));
        }
        if !rule.test.expect_match {
            return Err(format!(
                "rule {}: bundled tests must expect a match (rule_test is a sanity harness)",
                rule.id
            ));
        }
    }
    let _ = CATALOG.set(parsed);
    Ok(())
}

/// Process-wide catalog. Panics only if setup skipped init (programmer error).
pub fn catalog() -> &'static RuleCatalog {
    CATALOG.get().expect("rule catalog not initialized — call init_catalog() at setup")
}

pub fn rules() -> &'static [RuleDef] {
    &catalog().rules
}

pub fn rule_by_id(id: &str) -> Option<&'static RuleDef> {
    rules().iter().find(|r| r.id == id)
}
