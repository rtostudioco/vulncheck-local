/**
 * VulnCheck Local — Module C: User & Access Auditor collector (Linux)
 * --------------------------------------------------------------------
 * Read-only. Sources: /etc/passwd, /etc/group, /etc/shadow (shape only —
 * never stores hash content, only a per-user boolean password status),
 * /etc/login.defs, /etc/ssh/sshd_config (+ sshd_config.d includes),
 * allowlisted `systemctl is-active sshd|ssh`.
 * Collectors never throw; unreadable sources produce honest unavailable states.
 */

import fs from 'fs/promises';
import { loggedRun, readFileSafe } from '../../core/platform';
import type {
  AccountsEvidence,
  ExecLogEntry,
  PasswordPolicyInfo,
  SshConfigInfo,
  UserInfo,
} from '../../core/types';

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

/// Probe a systemd unit's active state via the allowlisted is-active query.
/// true = active, false = unit exists but inactive/failed/missing,
/// null = systemctl itself could not be used (no bus, no binary, ...).
async function probeUnitActive(execLog: ExecLogEntry[], unit: string): Promise<boolean | null> {
  const res = await loggedRun('SYSTEMCTL_IS_ACTIVE', ['is-active', unit], execLog);
  const out = res.stdout.trim();
  if (out === 'active') return true;
  if (out === 'inactive' || out === 'failed') return false;
  const text = `${res.stderr}\n${res.stdout}`;
  if (
    /system has not been booted with systemd|failed to connect to (system scope )?bus|ENOENT|EACCES|permission denied/i.test(
      text,
    )
  ) {
    return null; // systemctl itself failed
  }
  if (/could not be found|not found|not loaded/i.test(text)) return false; // unit missing
  return null; // unknown — honest null
}

function parsePasswd(text: string, adminMembers: Set<string>): UserInfo[] {
  const users: UserInfo[] = [];
  for (const line of text.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const f = trimmed.split(':');
    if (f.length < 7) continue;
    const uid = Number(f[2]);
    const gid = Number(f[3]);
    if (!Number.isFinite(uid) || !Number.isFinite(gid)) continue;
    const shell = f[6] ?? '';
    const name = f[0];
    users.push({
      name,
      uid,
      gid,
      home: f[5] ?? '',
      shell,
      interactive: uid === 0 || (uid >= 1000 && !/nologin$|false$/.test(shell)),
      admin: uid === 0 || adminMembers.has(name),
      passwordStatus: 'unreadable',
      lastChangeDays: null,
    });
  }
  return users;
}

function parseAdminGroups(text: string): { groups: Record<string, string[]>; members: Set<string> } {
  const groups: Record<string, string[]> = {};
  const members = new Set<string>();
  for (const line of text.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const f = trimmed.split(':');
    if (f.length < 4) continue;
    const groupName = f[0];
    if (!['sudo', 'wheel', 'admin', 'root'].includes(groupName)) continue;
    const membersList = (f[3] ?? '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    groups[groupName] = membersList;
    if (groupName !== 'root') for (const m of membersList) members.add(m);
  }
  return { groups, members };
}

function parseLoginDefs(text: string | null): PasswordPolicyInfo {
  if (!text) {
    return {
      maxDays: null,
      minDays: null,
      minLength: null,
      warnDays: null,
      source: 'unavailable — /etc/login.defs not readable',
    };
  }
  const num = (key: string): number | null => {
    const m = new RegExp(`^\\s*${key}\\s+(-?\\d+)\\s*$`, 'm').exec(text);
    return m ? Number(m[1]) : null;
  };
  return {
    maxDays: num('PASS_MAX_DAYS'),
    minDays: num('PASS_MIN_DAYS'),
    warnDays: num('PASS_WARN_AGE'),
    minLength: num('PASS_MIN_LEN'),
    source: '/etc/login.defs',
  };
}

function parseShadow(text: string, users: UserInfo[]): string[] {
  const notes: string[] = [];
  const byName = new Map<string, { status: UserInfo['passwordStatus']; lastChangeDays: number | null }>();
  for (const line of text.split('\n')) {
    const f = line.split(':');
    if (!f[0]) continue;
    const field2 = f[1] ?? '';
    let status: UserInfo['passwordStatus'];
    if (field2 === '') status = 'empty';
    else if (field2.startsWith('!') || field2.startsWith('*')) status = 'locked';
    else status = 'set';
    let lastChangeDays: number | null = null;
    const dayStr = f[2] ?? '';
    if (dayStr !== '') {
      const day = Number(dayStr);
      if (Number.isFinite(day)) {
        lastChangeDays = Math.floor((Date.now() - day * 86_400_000) / 86_400_000);
      }
    }
    byName.set(f[0], { status, lastChangeDays });
  }
  let emptyCount = 0;
  for (const u of users) {
    const s = byName.get(u.name);
    if (s) {
      u.passwordStatus = s.status;
      u.lastChangeDays = s.lastChangeDays;
      if (s.status === 'empty') emptyCount += 1;
    } else {
      u.passwordStatus = 'unknown';
    }
  }
  if (emptyCount > 0) notes.push(`${emptyCount} account(s) have an EMPTY password field`);
  return notes;
}

async function readSshIncludes(execLog: ExecLogEntry[]): Promise<{ path: string; text: string }[]> {
  void execLog;
  const includes: { path: string; text: string }[] = [];
  try {
    const entries = await fs.readdir('/etc/ssh/sshd_config.d');
    for (const name of entries.filter((e) => e.endsWith('.conf')).sort()) {
      const text = await readFileSafe(`/etc/ssh/sshd_config.d/${name}`);
      if (text !== null) includes.push({ path: `/etc/ssh/sshd_config.d/${name}`, text });
    }
  } catch {
    /* include directory absent or unreadable */
  }
  return includes;
}

async function collectSsh(execLog: ExecLogEntry[]): Promise<SshConfigInfo> {
  const info: SshConfigInfo = {
    available: false,
    permitRootLogin: null,
    passwordAuthentication: null,
    port: null,
    serviceRunning: null,
    files: [],
  };
  try {
    const baseText = await readFileSafe('/etc/ssh/sshd_config');
    const files: string[] = [];
    let combined = '';
    if (baseText !== null) {
      files.push('/etc/ssh/sshd_config');
      combined = baseText;
    }
    // Include directives: read /etc/ssh/sshd_config.d/*.conf (only .conf files)
    const baseHasInclude = baseText !== null && /^Include\s+/im.test(baseText);
    if (baseHasInclude) {
      const includeFiles = await readSshIncludes(execLog);
      for (const inc of includeFiles) files.push(inc.path);
      combined = [baseText ?? '', ...includeFiles.map((i) => i.text)].join('\n');
    }
    if (files.length > 0) {
      info.available = true;
      info.files = files;
      // Effective values: LAST occurrence across base + includes wins (spec contract)
      for (const line of combined.split('\n')) {
        const m = /^\s*([A-Za-z]+)\s+([^\s#]+)/.exec(line);
        if (!m) continue;
        const key = m[1].toLowerCase();
        const val = m[2].toLowerCase();
        if (key === 'permitrootlogin') info.permitRootLogin = val;
        else if (key === 'passwordauthentication') info.passwordAuthentication = val;
        else if (key === 'port' && info.port === null) {
          const p = Number(val);
          if (Number.isFinite(p) && p > 0 && p <= 65535) info.port = p;
        }
      }
    }
    const sshd = await probeUnitActive(execLog, 'sshd');
    if (sshd === true) {
      info.serviceRunning = true;
    } else {
      const ssh = await probeUnitActive(execLog, 'ssh');
      info.serviceRunning = ssh === true ? true : sshd === false || ssh === false ? false : null;
    }
  } catch {
    /* keep honest unavailable state */
  }
  return info;
}

/** Module C collector. Never throws; never reads or stores password hash content. */
export async function collectAccounts(execLog: ExecLogEntry[]): Promise<AccountsEvidence> {
  const notes: string[] = [];
  try {
    let users: UserInfo[] = [];
    let adminGroups: Record<string, string[]> = {};
    let passwdReadable = false;
    try {
      const passwd = await readFileSafe('/etc/passwd');
      if (passwd !== null) {
        passwdReadable = true;
        const group = await readFileSafe('/etc/group');
        if (group !== null) {
          const parsed = parseAdminGroups(group);
          adminGroups = parsed.groups;
          users = parsePasswd(passwd, parsed.members);
        } else {
          users = parsePasswd(passwd, new Set());
          notes.push('/etc/group not readable — group-based admin detection skipped');
        }
      }
    } catch {
      /* passwd unreadable */
    }
    if (!passwdReadable) {
      notes.push('/etc/passwd not readable — account inventory unavailable');
      return { ...unavailableAccounts(notes), notes };
    }

    // Shadow inspection: only password-field SHAPE (empty vs locked vs set) is recorded.
    let shadowReadable = false;
    try {
      const shadow = await readFileSafe('/etc/shadow');
      if (shadow !== null) {
        shadowReadable = true;
        const shadowNotes = parseShadow(shadow, users);
        notes.push(...shadowNotes);
      }
    } catch {
      /* fall through to unreadable handling */
    }
    if (!shadowReadable) {
      notes.push('Shadow file not readable without elevated privileges — empty-password check cannot be verified');
      for (const u of users) u.passwordStatus = 'unreadable';
    }

    const passwordPolicy = await (async () => {
      try {
        return parseLoginDefs(await readFileSafe('/etc/login.defs'));
      } catch {
        return parseLoginDefs(null);
      }
    })();
    if (passwordPolicy.maxDays === null && passwordPolicy.source.startsWith('unavailable')) {
      notes.push('/etc/login.defs not readable — password aging policy unknown');
    }

    const ssh = await collectSsh(execLog);
    if (!ssh.available) {
      notes.push('/etc/ssh/sshd_config not found or unreadable — SSH hardening could not be assessed');
    }
    if (ssh.serviceRunning === null) {
      notes.push('SSH service state could not be determined (systemd unavailable or unit probe failed)');
    }

    return {
      available: true,
      source: '/etc/passwd + /etc/group + /etc/shadow + /etc/login.defs + sshd_config',
      notes,
      users,
      adminGroups,
      passwordPolicy,
      ssh,
      shadowReadable,
    };
  } catch (err) {
    return unavailableAccounts([`Collection error: ${err instanceof Error ? err.message : String(err)}`, ...notes]);
  }
}
