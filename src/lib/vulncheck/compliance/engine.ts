/**
 * MODULE I — Compliance engine.
 * Runs every versioned rule in the registry against an EvidenceBundle and
 * produces findings. Rules targeting another OS are reported as
 * NOT_APPLICABLE for this host (visible, never hidden, never counted secure).
 */

import type {
  CheckStatus,
  EvidenceBundle,
  FindingDTO,
  RuleDefinition,
  Severity,
} from '../core/types';
import { ALL_RULES } from './rules';

export interface EvaluatedRule {
  rule: RuleDefinition;
  status: CheckStatus;
  severity: Severity;
  evidence: string;
}

export function evaluateRules(bundle: EvidenceBundle): EvaluatedRule[] {
  const results: EvaluatedRule[] = [];

  for (const rule of ALL_RULES) {
    try {
      // OS targeting: a rule for another platform is NOT_APPLICABLE here.
      if (rule.osTarget !== 'both' && rule.osTarget !== bundle.platform) {
        results.push({
          rule,
          status: 'NOT_APPLICABLE',
          severity: rule.severityIfFail,
          evidence:
            `Rule targets ${rule.osTarget} hosts; this audit ran on ${bundle.platform}. ` +
            `The rule activates automatically when VulnCheck Local runs on ${rule.osTarget}.`,
        });
        continue;
      }

      const res = rule.evaluate(bundle);
      results.push({
        rule,
        status: res.status,
        severity: res.severity ?? rule.severityIfFail,
        evidence: res.note ? `${res.evidence}\n  note: ${res.note}` : res.evidence,
      });
    } catch (err) {
      // A rule crash must never be reported as PASS.
      results.push({
        rule,
        status: 'ERROR',
        severity: rule.severityIfFail,
        evidence: `Rule evaluation error: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }

  return results;
}

export function toFindings(results: EvaluatedRule[]): Omit<FindingDTO, 'id'>[] {
  return results.map(({ rule, status, severity, evidence }) => ({
    ruleId: rule.id,
    ruleVersion: rule.version,
    category: rule.category,
    title: rule.title,
    description: rule.description,
    severity,
    status,
    evidence,
    riskExplanation: rule.guide.impact,
    remediation: rule.guide.solution,
    verification: rule.guide.verification,
    osTarget: rule.osTarget,
    aiExplanation: null,
  }));
}
