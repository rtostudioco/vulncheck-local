/**
 * VulnCheck Local — Module B: Firewall Auditor collector (Linux)
 * ----------------------------------------------------------------
 * Read-only. Sources: binary probe (ufw / firewall-cmd / nft / iptables),
 * /etc/ufw/ufw.conf, /etc/default/ufw, allowlisted status queries.
 * Honesty rules: an unverifiable firewall state is reported as active:null —
 * never assumed secure.
 */

import { loggedRun, readFileSafe } from '../../core/platform';
import type { ExecLogEntry, FirewallEvidence, FirewallRuleInfo } from '../../core/types';

/// Probe one binary via the allowlisted WHICH command and record it in execLog.
async function probeBinary(binary: string, execLog: ExecLogEntry[]): Promise<string | null> {
  const res = await loggedRun('WHICH', [binary], execLog);
  if (!res.ok) return null;
  const p = res.stdout.trim().split('\n')[0]?.trim();
  return p && p.startsWith('/') ? p : null;
}

export function unavailableFirewall(notes: string[]): FirewallEvidence {
  return {
    available: false,
    source: 'n/a',
    notes: [...notes],
    product: null,
    active: null,
    defaultIncoming: null,
    defaultOutgoing: null,
    profiles: [],
    rules: [],
  };
}

interface UfwConfState {
  enabled: boolean | null;
  defaultInput: string | null;
  defaultOutput: string | null;
}

async function readUfwConfFiles(): Promise<UfwConfState> {
  const state: UfwConfState = { enabled: null, defaultInput: null, defaultOutput: null };
  try {
    const ufwConf = await readFileSafe('/etc/ufw/ufw.conf');
    if (ufwConf) {
      const m = /^ENABLED=(\S+)\s*$/im.exec(ufwConf);
      if (m) state.enabled = m[1].toLowerCase() === 'yes';
    }
  } catch {
    /* unreadable */
  }
  try {
    const defaults = await readFileSafe('/etc/default/ufw');
    if (defaults) {
      const inM = /^DEFAULT_INPUT_POLICY=(\S+)\s*$/im.exec(defaults);
      const outM = /^DEFAULT_OUTPUT_POLICY=(\S+)\s*$/im.exec(defaults);
      if (inM) state.defaultInput = inM[1].toLowerCase();
      if (outM) state.defaultOutput = outM[1].toLowerCase();
    }
  } catch {
    /* unreadable */
  }
  return state;
}

interface UfwVerboseParse {
  active: boolean | null;
  defaultIncoming: string | null;
  defaultOutgoing: string | null;
  logging: string | null;
  rules: FirewallRuleInfo[];
}

function parseUfwVerbose(stdout: string): UfwVerboseParse {
  const result: UfwVerboseParse = {
    active: null,
    defaultIncoming: null,
    defaultOutgoing: null,
    logging: null,
    rules: [],
  };
  let inRules = false;
  for (const rawLine of stdout.split('\n')) {
    const line = rawLine.trimEnd();
    const trimmed = line.trim();
    if (!trimmed) continue;

    const statusM = /^Status:\s*(\S+)/i.exec(trimmed);
    if (statusM) {
      result.active = statusM[1].toLowerCase() === 'active';
      inRules = false;
      continue;
    }
    if (/^Logging:/i.test(trimmed)) {
      result.logging = trimmed.replace(/^Logging:\s*/i, '').trim();
      continue;
    }
    const defaultM = /^Default:\s*(\S+)\s*\(incoming\),\s*(\S+)\s*\(outgoing\)/i.exec(trimmed);
    if (defaultM) {
      result.defaultIncoming = defaultM[1].toLowerCase();
      result.defaultOutgoing = defaultM[2].toLowerCase();
      continue;
    }
    if (/^To\s+Action\s+From/i.test(trimmed) || /^New profiles/i.test(trimmed)) continue;
    if (/^-{2,}/.test(trimmed)) {
      inRules = true;
      continue;
    }
    if (!inRules) continue;

    // Rule rows: columns separated by 2+ spaces, e.g. "80/tcp   ALLOW IN   Anywhere"
    const parts = trimmed.split(/\s{2,}/);
    if (parts.length < 3) continue;
    const action = parts[1].trim().toUpperCase();
    if (!/^(ALLOW|DENY|LIMIT|REJECT)\b/.test(action)) continue;
    const target = parts[0].replace(/\s*\(v6\)\s*$/i, '').trim();
    const from = parts.slice(2).join(' ').replace(/\s*\(v6\)\s*$/i, '').trim();

    let port: string | null = null;
    let proto: string | null = null;
    const portM = /^(\d+(?::\d+)*(?:,\d+(?::\d+)*)*)\/(tcp6?|udp6?)$/i.exec(target);
    if (portM) {
      port = portM[1];
      proto = portM[2].toLowerCase().replace('6', '');
    }
    result.rules.push({ raw: trimmed, action: action.split(/\s+/)[0], target, port, proto, from });
  }
  return result;
}

function parseFirewalldZones(stdout: string): string[] {
  const zones: string[] = [];
  for (const line of stdout.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    // zone header lines are not indented; "interfaces: ..." lines are indented
    if (line.startsWith(' ') || /^\s*interfaces:/i.test(trimmed)) continue;
    zones.push(trimmed.split(/\s+/)[0]);
  }
  return [...new Set(zones)];
}

/** Module B collector. Never throws. */
export async function collectFirewall(execLog: ExecLogEntry[]): Promise<FirewallEvidence> {
  const notes: string[] = [];
  try {
    const ufwBin = await probeBinary('ufw', execLog);
    const fcmdBin = await probeBinary('firewall-cmd', execLog);
    const nftBin = await probeBinary('nft', execLog);
    const iptBin = await probeBinary('iptables', execLog);

    const ufwConf = await readUfwConfFiles();

    // ------------------------------------------------------------------ UFW
    if (ufwBin) {
      const evidence: FirewallEvidence = {
        available: true,
        source: 'which probe + /etc/ufw/*.conf + ufw status',
        notes,
        product: 'ufw',
        active: null,
        defaultIncoming: null,
        defaultOutgoing: null,
        profiles: ['default'],
        rules: [],
      };

      let parsed: UfwVerboseParse | null = null;
      const sudoRes = await loggedRun('SUDO_UFW_STATUS', ['-n', 'ufw', 'status', 'verbose'], execLog);
      let liveRes = sudoRes;
      if (!sudoRes.ok) {
        liveRes = await loggedRun('UFW_STATUS', ['status', 'verbose'], execLog);
      }
      if (liveRes.ok && liveRes.stdout.trim()) {
        parsed = parseUfwVerbose(liveRes.stdout);
        if (parsed.active !== null) evidence.active = parsed.active;
        if (parsed.defaultIncoming) evidence.defaultIncoming = parsed.defaultIncoming;
        if (parsed.defaultOutgoing) evidence.defaultOutgoing = parsed.defaultOutgoing;
        evidence.rules = parsed.rules;
        if (parsed.logging) notes.push(`UFW logging: ${parsed.logging}`);
      } else if (ufwConf.enabled !== null || ufwConf.defaultInput) {
        // live query unavailable — derive honest state from configuration files
        evidence.active = ufwConf.enabled;
        evidence.defaultIncoming = ufwConf.defaultInput;
        evidence.defaultOutgoing = ufwConf.defaultOutput;
        notes.push('state from config files; live query unavailable');
      } else {
        notes.push(
          `ufw binary present at ${ufwBin} but status query failed${
            liveRes.stderr ? `: ${liveRes.stderr.split('\n')[0]}` : ''
          }`,
        );
      }
      // conf-file fallbacks for directives the live output did not contain
      if (evidence.defaultIncoming === null && ufwConf.defaultInput) evidence.defaultIncoming = ufwConf.defaultInput;
      if (evidence.defaultOutgoing === null && ufwConf.defaultOutput) evidence.defaultOutgoing = ufwConf.defaultOutput;
      if (evidence.active === null && ufwConf.enabled !== null && !liveRes.ok) {
        evidence.active = ufwConf.enabled;
        notes.push('state from config files; live query unavailable');
      }
      if (sudoRes.ok && liveRes === sudoRes) {
        notes.push('ufw status retrieved via non-interactive sudo');
      } else if (liveRes.ok && liveRes !== sudoRes) {
        notes.push('ufw status retrieved unprivileged');
      }
      return evidence;
    }

    // -------------------------------------------------------------- firewalld
    if (fcmdBin) {
      const evidence: FirewallEvidence = {
        available: true,
        source: 'which probe + firewall-cmd --state/--get-active-zones',
        notes,
        product: 'firewalld',
        active: null,
        defaultIncoming: null,
        defaultOutgoing: null,
        profiles: [],
        rules: [],
      };
      const stateRes = await loggedRun('FIREWALL_STATE', ['--state'], execLog);
      if (stateRes.ok) {
        evidence.active = stateRes.stdout.trim().toLowerCase() === 'running';
      } else {
        notes.push(
          `firewalld state query failed${
            stateRes.error ? ` (${stateRes.error})` : ''
          } — active state could not be verified`,
        );
      }
      const zonesRes = await loggedRun('FIREWALL_STATE', ['--get-active-zones'], execLog);
      if (zonesRes.ok) evidence.profiles = parseFirewalldZones(zonesRes.stdout);
      notes.push(
        'firewalld manages per-zone/per-interface policies; a single default incoming policy is not derivable from read-only probes',
      );
      return evidence;
    }

    // --------------------------------------------------- nftables / iptables
    if (nftBin || iptBin) {
      const evidence: FirewallEvidence = {
        available: true,
        source: 'which probe + nft/iptables list queries',
        notes,
        product: 'nftables/iptables (userspace present)',
        active: null,
        defaultIncoming: null,
        defaultOutgoing: null,
        profiles: [],
        rules: [],
      };
      let queried = false;
      if (nftBin) {
        const nftRes = await loggedRun('NFT_LIST', ['list', 'ruleset'], execLog);
        queried = true;
        if (nftRes.ok) {
          evidence.product = 'nftables';
          evidence.active = true;
          notes.push('nftables ruleset retrieved successfully; structured rule parsing not performed');
        }
      }
      if (iptBin && evidence.active === null) {
        const iptRes = await loggedRun('IPTABLES_LIST', ['-L', '-n'], execLog);
        if (iptRes.ok) {
          evidence.product = 'iptables';
          evidence.active = true;
          notes.push('iptables rules retrieved successfully; structured rule parsing not performed');
        }
      }
      if (evidence.active === null) {
        notes.push(
          'ruleset query requires elevated privileges — status could not be verified',
        );
      }
      return evidence;
    }

    // -------------------------------------------------------- nothing found
    if (ufwConf.enabled !== null || ufwConf.defaultInput) {
      notes.push(
        'UFW configuration files present but the ufw binary was not found — firewall state assessed from files only',
      );
    }
    return {
      available: true,
      source: 'which probe (ufw/firewall-cmd/nft/iptables)',
      notes: [
        'No firewall product (ufw/firewalld/nftables/iptables) detected via binary probe or configuration files',
        ...notes,
      ],
      product: 'none-detected',
      active: false,
      defaultIncoming: null,
      defaultOutgoing: null,
      profiles: [],
      rules: [],
    };
  } catch (err) {
    return unavailableFirewall([`Collection error: ${err instanceof Error ? err.message : String(err)}`]);
  }
}
