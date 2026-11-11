// SENTINEL DESK 1.0 — Detection engine module (§7 stage 3 + MODULE 03)

pub mod engine;
pub mod rules_catalog;

pub use engine::{evidence_fingerprint, explain_match, evaluate_correlations, evaluate_rules, DetectionMatch, EvidenceMatch, EvidenceRef};
pub use rules_catalog::{init_catalog, rule_by_id, rules, Severity};
