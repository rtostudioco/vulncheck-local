/**
 * VulnCheck Local — Windows compliance rule registry (6 rules)
 * --------------------------------------------------------------
 * These rules target Windows hosts and are evaluated from PowerShell
 * read-only collector evidence (see src/lib/vulncheck/collectors/windows/).
 * Every evaluation is wrapped in try/catch: a missing or unreadable evidence
 * source yields NOT_ASSESSED with an explanatory note — never a fabricated
 * result and never a guess reported as secure.
 */

import type { EvidenceBundle, RuleDefinition, RuleGuide, RuleResult } from '../../core/types';

interface WindowsRuleSpec {
  id: string;
  category: RuleDefinition['category'];
  title: string;
  description: string;
  severityIfFail: RuleDefinition['severityIfFail'];
  reference: string | null;
  guide: RuleGuide;
  evaluate: (ev: EvidenceBundle) => RuleResult;
}

const WINDOWS_NOT_ASSESSED_EVIDENCE =
  'Windows evidence could not be collected (PowerShell read-only collectors unavailable on this host). The check is reported as NOT_ASSESSED — never as secure.';

// ---------------------------------------------------------------------------
// small text helpers (mirror the Linux rule registry style)
// ---------------------------------------------------------------------------

function joinLines(...parts: (string | null | undefined | false)[]): string {
  return parts.filter((p): p is string => typeof p === 'string' && p.length > 0).join('\n');
}

function na(evidence: string, note?: string): RuleResult {
  return { status: 'NOT_ASSESSED', evidence, ...(note ? { note } : {}) };
}

function boolText(v: boolean | null): string {
  return v === null ? 'unknown' : v ? 'True' : 'False';
}

function defWindowsRule(spec: WindowsRuleSpec): RuleDefinition {
  return {
    ...spec,
    version: '1.0.0',
    osTarget: 'windows',
    evaluate(ev: EvidenceBundle): RuleResult {
      try {
        return spec.evaluate(ev);
      } catch (err) {
        return {
          status: 'ERROR',
          evidence: `Rule evaluation error: ${err instanceof Error ? err.message : String(err)}`,
        };
      }
    },
  };
}

export const WINDOWS_RULES: RuleDefinition[] = [
  defWindowsRule({
    id: 'VC-WIN-001',
    category: 'ENDPOINT',
    title: 'Microsoft Defender real-time protection enabled',
    description:
      'Verifies that Microsoft Defender Antivirus real-time protection is active on the Windows host: AMRunningMode is Normal (or Sideloaded/Passive only when intentionally documented) and RealTimeProtectionEnabled is True.',
    severityIfFail: 'HIGH',
    reference: 'CIS benchmark concept: ensure antivirus real-time protection is enabled',
    guide: {
      problem:
        'Defender real-time protection may be disabled by tampering, misapplied policy, or a third-party AV that deregistered without restoring Defender.',
      impact:
        'Without on-access scanning, malware executes freely between scheduled scans; ransomware and fileless threats are not intercepted at execution time.',
      solution:
        'Re-enable real-time protection: `Set-MpPreference -DisableRealTimeMonitoring $false`. If a third-party AV is intended, confirm it registers with Windows Security Center and shows an active AMRunningMode.',
      verification:
        'Run `Get-MpComputerStatus | Select-Object AMRunningMode, RealTimeProtectionEnabled, AntivirusEnabled` — expect AMRunningMode Normal and both booleans True. Cross-check registry: HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableRealtimeMonitoring must be 0.',
    },
    evaluate: (ev) => {
      const ep = ev.endpoint;
      if (!ep.available) {
        return na(joinLines('Endpoint protection evidence could not be collected on this host.', ...ep.notes), 'Endpoint collector did not run successfully.');
      }
      // productName is set ONLY when Get-MpComputerStatus produced usable fields.
      if (ep.productName !== 'Microsoft Defender Antivirus') {
        return na(
          joinLines(
            'Microsoft Defender status could not be read (Get-MpComputerStatus returned no usable data).',
            'Defender may be absent on this SKU or deregistered by a third-party antivirus.',
            ...ep.notes,
          ),
          'Defender status unreadable — protection state unknown.',
        );
      }
      const details = joinLines(
        `Product: ${ep.productName}`,
        `AM service (MsMpEng): ${boolText(ep.daemonRunning)}`,
        `Real-time protection verified: ${ep.verifiedActive ? 'Yes' : 'NO'}`,
        `Signature database last updated: ${ep.signatureDb.lastUpdated ?? 'unknown'}`,
        ...ep.notes,
      );
      if (ep.verifiedActive) {
        return { status: 'PASS', evidence: details };
      }
      return {
        status: 'FAIL',
        evidence: joinLines(
          'Microsoft Defender is present but real-time protection could NOT be verified as enabled.',
          details,
        ),
      };
    },
  }),
  defWindowsRule({
    id: 'VC-WIN-002',
    category: 'ENDPOINT',
    title: 'Defender security intelligence up to date',
    description:
      'Verifies that Microsoft Defender security intelligence (antivirus/antispyware signatures and engine) is current — signature age should be at most 1 day old.',
    severityIfFail: 'MEDIUM',
    reference: 'CIS benchmark concept: ensure antivirus signatures are up to date',
    guide: {
      problem:
        'Defender signature or engine updates are stale because automatic updates are broken, WSUS deferrals are too aggressive, or the host has been offline.',
      impact: 'Newly released malware families and exploit variants are missed by stale detection signatures.',
      solution:
        'Trigger a manual update: `Update-MpSignature -UpdateSource MicrosoftUpdateServer`. Then repair the schedule (`sc.exe qc wuauserv`, MMPC definitions task `\\Microsoft\\Windows\\Windows Defender\\CacheBuilder` / signature update tasks) so daily updates resume.',
      verification:
        'Run `Get-MpComputerStatus | Select-Object AntivirusSignatureLastUpdated, AntivirusSignatureVersion, AntispywareSignatureLastUpdated, AntivirusEngineVersion` — signature age ≤ 1 day.',
    },
    evaluate: (ev) => {
      const ep = ev.endpoint;
      if (!ep.available || ep.productName !== 'Microsoft Defender Antivirus') {
        return na(
          joinLines('Microsoft Defender status could not be read — signature freshness could not be assessed.', ...ep.notes),
          'Defender status unreadable — signature age unknown.',
        );
      }
      if (!ep.signatureDb.present || ep.signatureDb.lastUpdated === null) {
        return na(
          joinLines(
            'Defender is present but the security intelligence timestamp was not reported.',
            ...ep.notes,
          ),
          'Signature timestamp unavailable — signature age unknown.',
        );
      }
      const ageDays = Math.floor((Date.now() - Date.parse(ep.signatureDb.lastUpdated)) / 86_400_000);
      if (!Number.isFinite(ageDays)) {
        return na('Signature timestamp could not be parsed — signature age unknown.', 'Unparseable timestamp.');
      }
      const details = joinLines(
        `Security intelligence last updated: ${ep.signatureDb.lastUpdated} (age: ${ageDays} day(s))`,
        ...ep.notes,
      );
      if (ageDays <= 1) {
        return { status: 'PASS', evidence: details };
      }
      return {
        status: 'FAIL',
        evidence: joinLines(`Defender security intelligence is STALE: ${ageDays} day(s) old (expected ≤ 1 day).`, details),
      };
    },
  }),
  defWindowsRule({
    id: 'VC-WIN-003',
    category: 'ACCOUNTS',
    title: 'User Account Control (UAC) enabled',
    description:
      'Verifies that User Account Control is enabled with secure admin approval prompts: EnableLUA = 1 and ConsentPromptBehaviorAdmin set to prompt on the secure desktop (2 = "Prompt for consent on the secure desktop" or 1 = elevation with credentials).',
    severityIfFail: 'HIGH',
    reference: 'CIS benchmark concept: ensure User Account Control is enabled',
    guide: {
      problem:
        'UAC may be disabled (EnableLUA = 0) or configured to auto-elevate without prompting, removing the approval gate between interactive users and administrative rights.',
      impact:
        'Malware running in a user session gains silent administrative elevation, enabling persistence, credential theft (LSASS access) and system-wide changes without user awareness.',
      solution:
        'Ensure EnableLUA=1, ConsentPromptBehaviorAdmin=2, PromptOnSecureDesktop=1 under HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System (GPO: Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options).',
      verification:
        'Run `Get-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" | Select-Object EnableLUA, ConsentPromptBehaviorAdmin, PromptOnSecureDesktop`.',
    },
    evaluate: (ev) => {
      const hard = ev.firewall.windowsHardening;
      const uac = hard?.uac;
      if (!uac || !hard?.available) {
        return na(
          joinLines('UAC registry evidence could not be collected on this host.', ...ev.firewall.notes),
          'UAC evidence unavailable — policy state unknown.',
        );
      }
      if (uac.enableLua === null) {
        return na(
          joinLines('UAC registry values could not be read.', ...ev.firewall.notes),
          'EnableLUA unreadable — UAC state unknown.',
        );
      }
      const consent = uac.consentPromptBehaviorAdmin;
      const prompt = uac.promptOnSecureDesktop;
      const details = joinLines(
        `EnableLUA=${boolText(uac.enableLua)} (registry)`,
        `ConsentPromptBehaviorAdmin=${consent ?? 'not present (Windows default: 5)'}`,
        `PromptOnSecureDesktop=${prompt === null ? 'not present (Windows default: 1)' : boolText(prompt)}`,
        `Source: ${uac.source}`,
      );
      if (!uac.enableLua) {
        return {
          status: 'FAIL',
          evidence: joinLines('User Account Control is DISABLED (EnableLUA=0) — elevation gate removed.', details),
        };
      }
      // EnableLUA=1 — evaluate the elevation prompt behavior.
      if (consent === 0 || consent === 3 || consent === 4) {
        return {
          status: 'FAIL',
          evidence: joinLines(
            `UAC is enabled but admin elevation does not prompt for consent (ConsentPromptBehaviorAdmin=${consent}).`,
            details,
          ),
        };
      }
      if (consent === 5) {
        return {
          status: 'WARNING',
          evidence: joinLines(
            'UAC is enabled but ConsentPromptBehaviorAdmin=5 (prompt only for non-Windows binaries). CIS expects 2 (secure-desktop consent).',
            details,
          ),
        };
      }
      if (consent === null) {
        return {
          status: 'WARNING',
          evidence: joinLines(
            'UAC is enabled but ConsentPromptBehaviorAdmin was not present in the registry (clean-install default 5 — prompt for non-Windows binaries only).',
            details,
          ),
        };
      }
      // consent === 1 or 2 → acceptable per rule description
      const notes: string[] = [];
      if (consent === 1) notes.push('ConsentPromptBehaviorAdmin=1 (credential prompt); CIS prefers 2 (secure-desktop consent).');
      if (prompt === false) notes.push('PromptOnSecureDesktop=0 — prompts do not switch to the secure desktop.');
      return {
        status: notes.length > 0 ? 'WARNING' : 'PASS',
        evidence: joinLines(
          'User Account Control is enabled with an admin approval prompt.',
          ...(notes.length > 0 ? notes : ['ConsentPromptBehaviorAdmin=2, secure desktop enforced.']),
          details,
        ),
      };
    },
  }),
  defWindowsRule({
    id: 'VC-WIN-004',
    category: 'NETWORK',
    title: 'RDP restricted and NLA enforced',
    description:
      'Verifies that if Remote Desktop is enabled (fDenyTSConnections = 0), Network Level Authentication is enforced (UserAuthentication = 1) and RDP exposure is restricted to required hosts/networks via firewall scope.',
    severityIfFail: 'HIGH',
    reference: 'CIS benchmark concept: ensure RDP is restricted with NLA enforced',
    guide: {
      problem:
        'RDP is exposed without Network Level Authentication, or is reachable from broad network scopes, enabling pre-authentication attacks against the terminal service.',
      impact:
        'Unauthenticated RDP exposure is a target for brute force, BlueKeep-class pre-auth RCE exploits, and ransomware lateral-movement chains.',
      solution:
        'Enforce NLA: `Set-ItemProperty "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" -Name UserAuthentication -Value 1`. Restrict firewall scope: `Set-NetFirewallRule -DisplayGroup "Remote Desktop" -RemoteAddress <admin-CIDRs>`; disable RDP entirely when unused (`fDenyTSConnections = 1`).',
      verification:
        'Run `Get-ItemProperty "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" -Name fDenyTSConnections` and `Get-ItemProperty "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" -Name UserAuthentication`.',
    },
    evaluate: (ev) => {
      const hard = ev.firewall.windowsHardening;
      const rdp = hard?.rdp;
      if (!rdp || !hard?.available) {
        return na(
          joinLines('Remote Desktop registry evidence could not be collected on this host.', ...ev.firewall.notes),
          'RDP evidence unavailable — remote-access exposure unknown.',
        );
      }
      if (rdp.denyTSConnections === null) {
        return na(
          joinLines('fDenyTSConnections could not be read.', ...ev.firewall.notes),
          'RDP enablement state unknown.',
        );
      }
      const details = joinLines(
        `fDenyTSConnections=${rdp.denyTSConnections ? 1 : 0} (RDP ${rdp.denyTSConnections ? 'disabled' : 'ENABLED'})`,
        `UserAuthentication (NLA)=${rdp.nlaEnforced === null ? 'not readable' : rdp.nlaEnforced ? 1 : 0}`,
        `Source: ${rdp.source}`,
      );
      if (rdp.denyTSConnections) {
        return {
          status: 'PASS',
          evidence: joinLines('Remote Desktop is disabled (fDenyTSConnections=1).', details),
        };
      }
      if (rdp.nlaEnforced === null) {
        return {
          status: 'WARNING',
          evidence: joinLines(
            'Remote Desktop is ENABLED but the Network Level Authentication value could not be read — NLA state unknown.',
            details,
          ),
        };
      }
      if (!rdp.nlaEnforced) {
        return {
          status: 'FAIL',
          evidence: joinLines(
            'Remote Desktop is ENABLED without Network Level Authentication (UserAuthentication=0) — pre-authentication attack surface exposed.',
            details,
          ),
        };
      }
      return {
        status: 'PASS',
        evidence: joinLines(
          'Remote Desktop is enabled with Network Level Authentication enforced (UserAuthentication=1).',
          'note: firewall-scope restriction of the Remote Desktop rule group could not be verified (rule enumeration is not part of the read-only allowlist) — confirm RDP is reachable only from required hosts.',
          details,
        ),
      };
    },
  }),
  defWindowsRule({
    id: 'VC-WIN-005',
    category: 'NETWORK',
    title: 'SMBv1 protocol disabled',
    description:
      'Verifies that the legacy SMBv1 protocol is disabled on both server and client components. SMBv1 lacks integrity protection and is the transport of WannaCry/NotPetya-class worms.',
    severityIfFail: 'HIGH',
    reference: 'CIS benchmark concept: ensure SMBv1 is disabled',
    guide: {
      problem: 'The SMBv1 protocol is still enabled on the server and/or client SMB stack.',
      impact:
        'SMBv1 is unauthenticated-friendly, lacks signing/integrity, and carries EternalBlue-class RCE exposure — a primary ransomware propagation vector.',
      solution:
        'Disable the protocol: `Set-SmbServerConfiguration -EnableSMB1Protocol $false` and `Set-SmbClientConfiguration -EnableSMB1Protocol $false` (Windows 8.1/2012 R2+), and remove the optional feature: `Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol`.',
      verification:
        'Run `Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol` (expect False) and `Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol` (expect Disabled).',
    },
    evaluate: (ev) => {
      const hard = ev.firewall.windowsHardening;
      const smb1 = hard?.smb1;
      if (!smb1 || !hard?.available) {
        return na(
          joinLines('SMBv1 evidence could not be collected on this host.', ...ev.firewall.notes),
          'SMBv1 evidence unavailable — legacy protocol exposure unknown.',
        );
      }
      const details = joinLines(
        `SMBv1 server protocol enabled: ${boolText(smb1.serverEnabled)}`,
        `SMB1Protocol optional feature state: ${smb1.featureState ?? 'could not be read'}`,
        `Source: ${smb1.source}`,
      );
      if (smb1.serverEnabled === true || smb1.featureState === 'Enabled') {
        return {
          status: 'FAIL',
          evidence: joinLines('SMBv1 is ENABLED on this host — WannaCry/NotPetya-class worm transport available.', details),
        };
      }
      if (smb1.serverEnabled === false) {
        return {
          status: 'PASS',
          evidence: joinLines(
            `SMBv1 server protocol is disabled.${smb1.featureState ? ` Optional feature state: ${smb1.featureState}.` : ''}`,
            details,
          ),
        };
      }
      if (smb1.featureState === 'Disabled') {
        return {
          status: 'PASS',
          evidence: joinLines(
            'SMBv1 server configuration value was not readable, but the SMB1Protocol optional feature is Disabled.',
            details,
          ),
        };
      }
      return na(
        joinLines(
          'SMBv1 state could not be determined (Get-SmbServerConfiguration/registry/optional-feature all unavailable — often requires an elevated session).',
          details,
        ),
        'SMBv1 state unknown.',
      );
    },
  }),
  defWindowsRule({
    id: 'VC-WIN-006',
    category: 'UPDATES',
    title: 'Windows Update service operational',
    description:
      'Verifies that the Windows Update stack (wuauserv, UsoSvc, BITS) is not disabled and no policy blocks automatic updates (NoAutoUpdate), so security patches continue to arrive.',
    severityIfFail: 'MEDIUM',
    reference: 'CIS benchmark concept: ensure Windows Update service is operational',
    guide: {
      problem:
        'The Windows Update service or its dependencies are disabled/stopped, or a policy (NoAutoUpdate) has turned off automatic updates.',
      impact: 'The host stops receiving security patches and silently falls behind on CVE remediation.',
      solution:
        'Re-enable the service: `Set-Service wuauserv -StartupType Manual` then `Start-Service wuauserv`; ensure BITS and UsoSvc are not disabled; remove or review the NoAutoUpdate policy under HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU.',
      verification:
        'Run `Get-Service wuauserv, UsoSvc, bits | Select-Object Name, Status, StartType` and `Get-ItemProperty "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU" -ErrorAction SilentlyContinue`.',
    },
    evaluate: (ev) => {
      const svc = ev.services;
      const upd = ev.updates;
      if (!svc.available && !upd.available) {
        return na(
          joinLines(
            'Windows Update stack evidence could not be collected on this host.',
            ...svc.notes,
            ...upd.notes,
          ),
          'Service/update evidence unavailable — update pipeline state unknown.',
        );
      }
      const stackDetails = svc.notes.filter((n) => /^(wuauserv|usosvc|bits):/i.test(n) || /^(wuauserv|usosvc|bits): not present/i.test(n));
      const details = joinLines(
        stackDetails.length > 0 ? stackDetails.join('\n') : 'Windows Update stack service states not collected.',
        ...upd.notes,
      );

      // 1) Disabled stack services → FAIL
      const disabled = svc.riskyServices.filter(
        (r) => ['wuauserv', 'usosvc', 'bits'].includes(r.name.toLowerCase()) && r.reason.includes('Disabled'),
      );
      if (disabled.length > 0) {
        return {
          status: 'FAIL',
          evidence: joinLines(
            `Windows Update stack service(s) DISABLED: ${disabled.map((d) => d.name).join(', ')}.`,
            details,
          ),
        };
      }

      // 2) Policy blocks automatic updates → FAIL
      if (upd.available && upd.autoUpdatesEnabled === false) {
        return {
          status: 'FAIL',
          evidence: joinLines(
            'A NoAutoUpdate policy blocks automatic updates — the host will not patch itself.',
            details,
          ),
        };
      }

      // 3) A successful read-only Windows Update COM search proves the stack is operational.
      if (upd.available && upd.pendingUpdates !== null) {
        return {
          status: 'PASS',
          evidence: joinLines(
            `Windows Update search completed successfully (read-only COM session): ${upd.pendingUpdates} pending update(s), ${upd.pendingSecurityUpdates ?? 'unknown'} security-flagged.`,
            'No stack service is disabled and no NoAutoUpdate policy was found.',
            details,
          ),
        };
      }

      return na(
        joinLines(
          'Could not verify the Windows Update pipeline: no disabled stack services were detected, but neither a service-state query nor an update search succeeded.',
          details,
        ),
        'Update pipeline state could not be verified.',
      );
    },
  }),
];
