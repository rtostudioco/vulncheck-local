/**
 * VulnCheck Local — compliance rule registry (MODULE I)
 * -------------------------------------------------------
 * Single registry that aggregates all versioned rules. Every rule evaluates
 * the full EvidenceBundle defensively: unavailable inspections yield
 * NOT_ASSESSED, inapplicable checks yield NOT_APPLICABLE — never a guess.
 */

import type { RuleDefinition } from '../../core/types';
import { LINUX_RULES } from './linux-rules';
import { WINDOWS_RULES } from './windows-rules';

export const ALL_RULES: RuleDefinition[] = [...LINUX_RULES, ...WINDOWS_RULES];

export const RULE_COUNT = ALL_RULES.length;

/// Rules that apply to a given platform ('both' rules always included).
export function rulesForPlatform(platform: 'linux' | 'windows'): RuleDefinition[] {
  return ALL_RULES.filter((r) => r.osTarget === 'both' || r.osTarget === platform);
}
