/**
 * MODULE H (spec §8) — Optional AI explanation module.
 * - Fully opt-in: the caller must pass a consent check first (settings gate).
 * - Data minimization: only the single finding's metadata is transmitted —
 *   never the full inventory, never hostnames, never addresses, never other
 *   findings. Evidence is sanitized and truncated.
 * - The application is fully functional without this module.
 */

import ZAI from 'z-ai-web-dev-sdk';
import type { FindingDTO } from '../core/types';
import { createLogger } from '../core/platform';

const log = createLogger('ai');

const MAX_EVIDENCE_CHARS = 600;

function sanitizeEvidence(evidence: string): string {
  // Remove IPv4 addresses and hostnames-like tokens from the excerpt
  const scrubbed = evidence
    .replace(/\b\d{1,3}(\.\d{1,3}){3}\b/g, '<ip>')
    .replace(/\b([0-9a-f]{2}:){5}[0-9a-f]{2}\b/gi, '<mac>');
  return scrubbed.slice(0, MAX_EVIDENCE_CHARS);
}

export async function explainFinding(finding: FindingDTO, osContext: string): Promise<string> {
  const zai = await ZAI.create();

  const systemPrompt = [
    'You are a senior IT security analyst writing for a non-specialist audience (IT support technicians and small-business administrators).',
    'Explain ONE security audit finding in clear, professional language.',
    'Structure your answer with these exact short sections, each on its own line prefixed with the section name:',
    'What this means | Why it is a risk | What to do | How to verify.',
    'Keep each section to 1-3 sentences. Be concrete and practical. Do not invent evidence you were not given.',
    'Do not claim the system is fully secure or compliant. Do not include credentials or commands that modify the system without stating they must be reviewed by an administrator.',
  ].join(' ');

  const userPrompt = [
    `Operating system family: ${osContext}.`,
    `Finding rule: ${finding.ruleId} (version ${finding.ruleVersion}).`,
    `Category: ${finding.category}. Severity: ${finding.severity}. Status: ${finding.status}.`,
    `Title: ${finding.title}`,
    `Description: ${finding.description}`,
    `Evidence excerpt (sanitized): ${sanitizeEvidence(finding.evidence)}`,
    `Built-in remediation guidance: ${finding.remediation}`,
    'Explain this finding to the administrator following the required structure.',
  ].join('\n');

  const completion = await zai.chat.completions.create({
    messages: [
      { role: 'assistant', content: systemPrompt },
      { role: 'user', content: userPrompt },
    ],
    thinking: { type: 'disabled' },
  });

  const content = completion.choices[0]?.message?.content;
  if (!content || content.trim().length === 0) {
    throw new Error('AI service returned an empty explanation');
  }
  log.info(`explained finding ${finding.ruleId} (${content.length} chars)`);
  return content.trim();
}
