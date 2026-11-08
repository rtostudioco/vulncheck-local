/**
 * VulnCheck Local — Module C: User & Access Auditor collector (Windows)
 * ----------------------------------------------------------------------
 * Read-only. Sources: allowlisted PowerShell queries — Get-LocalUser
 * (account METADATA only: names, SIDs, enabled state, password timestamps),
 * Get-LocalGroupMember -SID S-1-5-32-544 (Administrators) and `net accounts`
 * (password/lockout policy).
 * SECURITY: no credentials, password hashes or tokens are ever collected —
 * only the SHAPE of password state (set/empty/unknown) and timestamps.
 */

import {
  asBool,
  asDateIso,
  asNumber,
  asString,
  daysSince,
  failureNote,
  parseJsonArray,
  ridFromSid,
  runPs,
} from './ps';
import type {
  AccountsEvidence,
  ExecLogEntry,
  PasswordPolicyInfo,
  UserInfo,
} from '../../core/types';

const MAX_USERS = 500;

export function unavailableAccounts(notes: string[]): AccountsEvidence {
  return {
    available: false,
    source: 'n/a',
    notes: [...notes],
    users: [],
    adminGroups: {},
    passwordPolicy: {
      maxDays: null,
      minDays: null,
      minLength: null,
      warnDays: null,
      source: 'unavailable',
    },
    ssh: {
      available: false,
      permitRootLogin: null,
      passwordAuthentication: null,
      port: null,
      serviceRunning: null,
      files: [],
    },
    shadowReadable: false,
  };
}

interface LocalUserRow {
  name: string;
  enabled: boolean | null;
  sid: string | null;
  lastLogon: string | null;
  passwordLastSet: string | null;
  passwordRequired: boolean | null;
}

function parseLocalUsers(stdout: string): LocalUserRow[] {
  return parseJsonArray(stdout)
    .map((r) => ({
      name: asString(r.Name),
      enabled: asBool(r.Enabled),
      sid: asString(r.SID),
      lastLogon: asDateIso(r.LastLogon),
      passwordLastSet: asDateIso(r.PasswordLastSet),
      passwordRequired: asBool(r.PasswordRequired),
    }))
    .filter((u): u is LocalUserRow => u.name !== null);
}

function toUserInfo(row: LocalUserRow, admins: Set<string>): UserInfo {
  // Windows password-status SHAPE (no credential content):
  //  'locked'  → account disabled (Enabled = False)
  //  'set'     → a password has been assigned (PasswordLastSet present)
  //  'empty'   → password not required (PasswordRequired = False) — possible blank password
  //  'unknown' → metadata unavailable
  let passwordStatus: UserInfo['passwordStatus'];
  if (row.enabled === false) passwordStatus = 'locked';
  else if (row.passwordLastSet !== null) passwordStatus = 'set';
  else if (row.passwordRequired === false) passwordStatus = 'empty';
  else passwordStatus = 'unknown';

  const admin = admins.has(row.name.toLowerCase());
  return {
    name: row.name,
    uid: ridFromSid(row.sid) ?? 0,
    gid: 0, // Windows has no primary-group concept equivalent to POSIX GID
    home: '', // profile paths not collected by the read-only allowlist
    shell: '', // not applicable on Windows
    interactive: row.enabled === true,
    admin: admin || ridFromSid(row.sid) === 500,
    passwordStatus,
    lastChangeDays: daysSince(row.passwordLastSet),
  };
}

function parseAdmins(stdout: string): { names: string[]; members: string[] } {
  const names: string[] = [];
  const members: string[] = [];
  for (const row of parseJsonArray(stdout)) {
    const name = asString(row.Name);
    if (!name) continue;
    members.push(name);
    // Local members appear as 'HOSTNAME\\username' — keep the account part.
    const local = name.includes('\\') ? (name.split('\\').pop() ?? name) : name;
    names.push(local.toLowerCase());
  }
  return { names, members };
}

function parseNetAccounts(stdout: string): PasswordPolicyInfo {
  const num = (label: string): number | null => {
    const re = new RegExp(`${label}\\s*:\\s*(\\d+)`, 'i');
    const m = re.exec(stdout);
    return m ? Number(m[1]) : null;
  };
  const maxDays = num('Maximum password age');
  const minDays = num('Minimum password age');
  const minLength = num('Minimum password length');
  const any = maxDays !== null || minDays !== null || minLength !== null;
  return {
    maxDays,
    minDays,
    minLength,
    warnDays: null, // not exposed by `net accounts`
    source: any ? 'net accounts' : 'unavailable — net accounts output not parseable (localized system?)',
  };
}

/** Module C collector (Windows). Never throws; never reads credential material. */
export async function collectAccounts(execLog: ExecLogEntry[]): Promise<AccountsEvidence> {
  const notes: string[] = [];
  try {
    // ------------------------------------------------ local users (metadata only)
    let rows: LocalUserRow[] = [];
    const usersRes = await runPs('PS_LOCAL_USERS', execLog);
    if (usersRes.ok) {
      rows = parseLocalUsers(usersRes.stdout);
      if (rows.length === 0) notes.push('Get-LocalUser returned no accounts — account inventory empty');
      if (rows.length > MAX_USERS) {
        notes.push(`account list truncated to ${MAX_USERS} entries`);
        rows = rows.slice(0, MAX_USERS);
      }
    } else {
      notes.push(failureNote(usersRes, 'Get-LocalUser query'));
    }

    // ------------------------------------------------ Administrators group
    let adminNames = new Set<string>();
    let adminMembers: string[] = [];
    const adminsRes = await runPs('PS_ADMINS', execLog);
    if (adminsRes.ok) {
      const parsed = parseAdmins(adminsRes.stdout);
      adminNames = new Set(parsed.names);
      adminMembers = parsed.members;
      if (adminMembers.length === 0) notes.push('Administrators group membership query returned no members');
    } else {
      notes.push(failureNote(adminsRes, 'Administrators group query'));
    }

    if (rows.length === 0 && adminMembers.length === 0) {
      notes.push('local account evidence unavailable — accounts module degraded');
      return { ...unavailableAccounts(notes), notes };
    }

    const users = rows.map((r) => toUserInfo(r, adminNames));
    const emptyCount = users.filter((u) => u.passwordStatus === 'empty').length;
    if (emptyCount > 0) notes.push(`${emptyCount} account(s) report PasswordRequired=False (possible blank password)`);
    const domainAdmins = parseJsonArray(adminsRes.stdout).filter(
      (r) => asString(r.PrincipalSource) && asString(r.PrincipalSource) !== 'Local',
    ).length;
    if (domainAdmins > 0) notes.push(`${domainAdmins} Administrators member(s) sourced from a domain/Azure AD directory`);

    // ------------------------------------------------ password/lockout policy
    let passwordPolicy: PasswordPolicyInfo = {
      maxDays: null,
      minDays: null,
      minLength: null,
      warnDays: null,
      source: 'unavailable',
    };
    const policyRes = await runPs('PS_PASSWORD_POLICY', execLog);
    if (policyRes.ok) {
      passwordPolicy = parseNetAccounts(policyRes.stdout);
      if (passwordPolicy.maxDays === null && passwordPolicy.minLength === null) {
        notes.push('net accounts output could not be parsed (non-English locale?) — password aging policy unknown');
      }
    } else {
      notes.push(failureNote(policyRes, 'net accounts policy query'));
    }

    notes.push('no shadow file on Windows — password-status shape derived from Get-LocalUser metadata only');
    notes.push('OpenSSH Server is not probed by the Windows read-only allowlist — remote SSH hardening not assessed (RDP is covered by the firewall module)');

    return {
      available: users.length > 0,
      source: 'Get-LocalUser + Get-LocalGroupMember (S-1-5-32-544) + net accounts',
      notes,
      users,
      adminGroups: adminMembers.length > 0 ? { Administrators: adminMembers } : {},
      passwordPolicy,
      ssh: {
        available: false,
        permitRootLogin: null,
        passwordAuthentication: null,
        port: null,
        serviceRunning: null,
        files: [],
      },
      shadowReadable: false,
    };
  } catch (err) {
    return unavailableAccounts([`Collection error: ${err instanceof Error ? err.message : String(err)}`, ...notes]);
  }
}
