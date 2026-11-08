/**
 * VulnCheck Local — Module B: Firewall Auditor collector (Windows)
 * ------------------------------------------------------------------
 * Read-only. Sources: allowlisted PowerShell queries — Get-NetFirewallProfile
 * (Domain/Private/Public), plus registry/CIM reads for Remote Desktop
 * (fDenyTSConnections, NLA), SMBv1 and User Account Control.
 * Honesty rules: an unverifiable state is reported as null — never assumed
 * secure. Hardening results are carried in `windowsHardening` (types.ts).
 */

import {
  asBool,
  asNumber,
  asString,
  failureNote,
  parseJsonArray,
  parseJsonObject,
  runPs,
} from './ps';
import type {
  ExecLogEntry,
  FirewallEvidence,
  WindowsHardeningEvidence,
} from '../../core/types';

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

interface ProfileRow {
  name: string;
  enabled: boolean | null;
  inbound: string | null;
  outbound: string | null;
}

function parseProfiles(stdout: string): { rows: ProfileRow[]; ok: boolean } {
  const rows = parseJsonArray(stdout)
    .map((r) => ({
      name: asString(r.Name) ?? 'Unknown',
      enabled: asBool(r.Enabled),
      inbound: asString(r.DefaultInboundAction)?.toLowerCase() ?? null,
      outbound: asString(r.DefaultOutboundAction)?.toLowerCase() ?? null,
    }));
  return { rows, ok: rows.length > 0 };
}

function sharedOrNull(values: (string | null)[]): string | null {
  const defined = values.filter((v): v is string => v !== null);
  if (defined.length === 0) return null;
  return defined.every((v) => v === defined[0]) ? defined[0] : null;
}

function parseRdp(stdout: string): { denyTSConnections: boolean | null; nlaEnforced: boolean | null; source: string } {
  const obj = parseJsonObject(stdout);
  const deny = obj ? asNumber(obj.fDenyTSConnections) : null;
  const nla = obj ? asNumber(obj.userAuthentication) : null;
  return {
    denyTSConnections: deny === null ? null : deny !== 0,
    nlaEnforced: nla === null ? null : nla === 1,
    source: 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server (+ RDP-Tcp\\UserAuthentication)',
  };
}

function parseUac(stdout: string): {
  enableLua: boolean | null;
  consentPromptBehaviorAdmin: number | null;
  promptOnSecureDesktop: boolean | null;
  source: string;
} {
  const obj = parseJsonObject(stdout);
  return {
    enableLua: obj ? asBool(obj.EnableLUA) : null,
    consentPromptBehaviorAdmin: obj ? asNumber(obj.ConsentPromptBehaviorAdmin) : null,
    promptOnSecureDesktop: obj ? asBool(obj.PromptOnSecureDesktop) : null,
    source: 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System',
  };
}

function parseSmb1(stdout: string): {
  serverEnabled: boolean | null;
  featureState: string | null;
  source: string;
} {
  const obj = parseJsonObject(stdout);
  if (!obj) return { serverEnabled: null, featureState: null, source: 'unavailable' };
  const serverNum = asNumber(obj.serverSmb1);
  const source = asString(obj.source) ?? 'unknown';
  return {
    serverEnabled: serverNum === null ? null : serverNum !== 0,
    featureState: asString(obj.featureState),
    source,
  };
}

/** Module B collector (Windows). Never throws. */
export async function collectFirewall(execLog: ExecLogEntry[]): Promise<FirewallEvidence> {
  const notes: string[] = [];
  try {
    // ------------------------------------------------ Defender Firewall profiles
    let profileRows: ProfileRow[] = [];
    const fwRes = await runPs('PS_FW_PROFILES', execLog);
    if (fwRes.ok) {
      const parsed = parseProfiles(fwRes.stdout);
      profileRows = parsed.rows;
      if (!parsed.ok) notes.push('Get-NetFirewallProfile returned no profiles — firewall state could not be verified');
    } else {
      notes.push(failureNote(fwRes, 'Get-NetFirewallProfile query'));
    }

    const evidence: FirewallEvidence = {
      available: false,
      source: 'Get-NetFirewallProfile + registry reads (RDP/UAC/SMB1)',
      notes,
      product: profileRows.length > 0 ? 'windows-defender' : null,
      active: null,
      defaultIncoming: null,
      defaultOutgoing: null,
      profiles: profileRows.map((p) => p.name),
      rules: [],
      windowsHardening: undefined,
    };

    if (profileRows.length > 0) {
      const enabledStates = profileRows.map((p) => p.enabled);
      if (enabledStates.every((e) => e === true)) {
        evidence.active = true;
      } else if (enabledStates.every((e) => e === false)) {
        evidence.active = false;
      } else {
        evidence.active = null;
        notes.push('firewall profiles are in a mixed enabled/disabled state — overall active state reported as unknown');
      }
      for (const p of profileRows) {
        notes.push(
          `profile ${p.name}: ${p.enabled === null ? 'enabled=unknown' : p.enabled ? 'enabled' : 'DISABLED'}` +
            `, inbound=${p.inbound ?? 'unknown'}, outbound=${p.outbound ?? 'unknown'}`,
        );
      }
      evidence.defaultIncoming = sharedOrNull(profileRows.map((p) => p.inbound));
      evidence.defaultOutgoing = sharedOrNull(profileRows.map((p) => p.outbound));
      if (evidence.defaultIncoming === null && profileRows.length > 0) {
        notes.push('profiles use differing default inbound actions — no single default derivable');
      }
      notes.push('per-rule firewall exception enumeration is not part of the read-only allowlist; profile defaults are assessed instead');
    }

    // ------------------------------------------------ RDP / NLA hardening
    const rdpRes = await runPs('PS_RDP', execLog);
    const rdp = rdpRes.ok ? parseRdp(rdpRes.stdout) : { denyTSConnections: null, nlaEnforced: null, source: 'unavailable' };
    if (!rdpRes.ok) notes.push(failureNote(rdpRes, 'Remote Desktop registry query'));

    // ------------------------------------------------ UAC hardening
    const uacRes = await runPs('PS_UAC', execLog);
    const uac = uacRes.ok
      ? parseUac(uacRes.stdout)
      : { enableLua: null, consentPromptBehaviorAdmin: null, promptOnSecureDesktop: null, source: 'unavailable' };
    if (!uacRes.ok) notes.push(failureNote(uacRes, 'User Account Control registry query'));

    // ------------------------------------------------ SMBv1 hardening
    const smbRes = await runPs('PS_SMB1', execLog);
    const smb1 = smbRes.ok ? parseSmb1(smbRes.stdout) : { serverEnabled: null, featureState: null, source: 'unavailable' };
    if (!smbRes.ok) notes.push(failureNote(smbRes, 'SMBv1 configuration query'));
    else if (smb1.serverEnabled === null && smb1.featureState === null) {
      notes.push('SMBv1 state could not be read (Get-SmbServerConfiguration/registry/optional-feature all unavailable)');
    }

    const hardening: WindowsHardeningEvidence = {
      available:
        rdp.denyTSConnections !== null ||
        uac.enableLua !== null ||
        smb1.serverEnabled !== null ||
        smb1.featureState !== null,
      uac,
      rdp,
      smb1,
    };
    evidence.windowsHardening = hardening;
    evidence.available = profileRows.length > 0 || hardening.available;

    if (!evidence.available) {
      notes.push('no firewall or hardening evidence could be collected on this host');
    }
    return evidence;
  } catch (err) {
    return unavailableFirewall([`Collection error: ${err instanceof Error ? err.message : String(err)}`]);
  }
}
