/**
 * VulnCheck Local — shared PowerShell result helpers (Windows collectors)
 * ------------------------------------------------------------------------
 * Defensive parsing of allowlisted PowerShell output. Everything here is
 * fail-soft: malformed/missing data yields null/empty — NEVER a guess — so
 * collectors can degrade to UNAVAILABLE/PARTIAL with honest notes.
 */

import type { CmdResult } from '../../core/runner';
import { runPowerShellCommand, type PsCommandId } from '../../core/runner';
import type { ExecLogEntry } from '../../core/types';

/** Run an allowlisted PowerShell command and record it in the shared exec log. */
export async function runPs(id: PsCommandId, execLog: ExecLogEntry[]): Promise<CmdResult> {
  return runPowerShellCommand(id, execLog);
}

/** Human-readable one-line note for a failed/skipped command. */
export function failureNote(res: CmdResult, what: string): string {
  const reason = res.error ? ` (${res.error})` : '';
  const stderr = res.stderr.split('\n')[0]?.trim();
  return `${what} failed${reason}${stderr ? `: ${stderr.slice(0, 160)}` : ''}`;
}

type JsonObj = Record<string, unknown>;

/// Parse stdout as a JSON object (PS 5.1 can emit a BOM; ignore non-objects).
export function parseJsonObject(stdout: string): JsonObj | null {
  try {
    const text = stdout.replace(/^\uFEFF/, '').trim();
    if (!text) return null;
    const parsed: unknown = JSON.parse(text);
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      return parsed as JsonObj;
    }
    return null;
  } catch {
    return null;
  }
}

/// Parse stdout as an array of JSON objects. PS emits a bare object when the
/// pipeline yields a single element; normalize it into a one-element array.
export function parseJsonArray(stdout: string): JsonObj[] {
  try {
    const text = stdout.replace(/^\uFEFF/, '').trim();
    if (!text) return [];
    const parsed: unknown = JSON.parse(text);
    if (Array.isArray(parsed)) {
      return parsed.filter((x): x is JsonObj => Boolean(x) && typeof x === 'object' && !Array.isArray(x));
    }
    if (parsed && typeof parsed === 'object') return [parsed as JsonObj];
    return [];
  } catch {
    return [];
  }
}

/// Normalize an already-parsed JSON value into an array of objects (fail-soft).
export function asJsonArray(v: unknown): JsonObj[] {
  if (Array.isArray(v)) {
    return v.filter((x): x is JsonObj => Boolean(x) && typeof x === 'object' && !Array.isArray(x));
  }
  if (v && typeof v === 'object') return [v as JsonObj];
  return [];
}

export function asString(v: unknown): string | null {
  if (typeof v === 'string') {
    const s = v.trim();
    return s.length > 0 ? s : null;
  }
  if (typeof v === 'number' || typeof v === 'boolean') return String(v);
  // PS 5.1 serializes some primitives (e.g. SIDs, GUIDs) as { Value: '...' }
  if (v && typeof v === 'object' && typeof (v as JsonObj).Value === 'string') {
    const s = ((v as JsonObj).Value as string).trim();
    return s.length > 0 ? s : null;
  }
  return null;
}

export function asNumber(v: unknown): number | null {
  if (typeof v === 'number') return Number.isFinite(v) ? v : null;
  if (typeof v === 'string') {
    const n = Number(v.trim());
    return Number.isFinite(n) ? n : null;
  }
  if (typeof v === 'boolean') return v ? 1 : 0;
  return null;
}

export function asBool(v: unknown): boolean | null {
  if (typeof v === 'boolean') return v;
  if (typeof v === 'number') return v !== 0;
  if (typeof v === 'string') {
    const s = v.trim().toLowerCase();
    if (s === 'true' || s === '1') return true;
    if (s === 'false' || s === '0') return false;
  }
  return null;
}

/**
 * Normalize the many DateTime serializations PowerShell may emit:
 *  - PS 5.1:  '/Date(1735689600000)/'
 *  - PS 7+:   ISO 8601 strings
 *  - raw CIM: '20250102130450.123456+060'
 * Returns an ISO-8601 UTC string or null (never guesses).
 */
export function asDateIso(v: unknown): string | null {
  if (v === null || v === undefined) return null;
  if (typeof v === 'number') {
    const d = new Date(v);
    return Number.isNaN(d.getTime()) ? null : d.toISOString();
  }
  if (typeof v !== 'string') return null;
  const s = v.trim();
  if (!s) return null;

  const msMatch = /^\/Date\((-?\d+)(?:[-+]\d{4})?\)\/$/.exec(s);
  if (msMatch) {
    const d = new Date(Number(msMatch[1]));
    return Number.isNaN(d.getTime()) ? null : d.toISOString();
  }
  const cimMatch = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.\d+)?([+-]\d{3})?$/.exec(s);
  if (cimMatch) {
    const [, y, mo, d, h, mi, sec, off] = cimMatch;
    const offsetMin = off ? Number(`${off.slice(0, 3)}${off.slice(3)}`) * -1 : 0;
    const dt = new Date(
      Date.UTC(Number(y), Number(mo) - 1, Number(d), Number(h), Number(mi), Number(sec)) +
        offsetMin * 60_000,
    );
    return Number.isNaN(dt.getTime()) ? null : dt.toISOString();
  }
  const parsed = Date.parse(s);
  return Number.isNaN(parsed) ? null : new Date(parsed).toISOString();
}

/** Days since the given ISO date, or null. */
export function daysSince(iso: string | null): number | null {
  if (!iso) return null;
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return null;
  return Math.floor((Date.now() - t) / 86_400_000);
}

/** Extract the RID (last segment) from a Windows SID string. */
export function ridFromSid(sid: string | null): number | null {
  if (!sid) return null;
  const parts = sid.split('-');
  const rid = Number(parts[parts.length - 1]);
  return Number.isFinite(rid) ? rid : null;
}
