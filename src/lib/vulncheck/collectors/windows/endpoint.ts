/**
 * VulnCheck Local — Module F: Antivirus & Protection collector (Windows)
 * ------------------------------------------------------------------------
 * Read-only. Sources: allowlisted PowerShell queries — Get-MpComputerStatus
 * and Get-MpPreference (Microsoft Defender), Get-BitLockerVolume (disk
 * encryption context).
 * Protection is NEVER claimed active unless it could actually be verified
 * (RealTimeProtectionEnabled = True).
 */

import { asBool, asDateIso, asNumber, asString, failureNote, parseJsonArray, parseJsonObject, runPs } from './ps';
import type { EndpointEvidence, ExecLogEntry } from '../../core/types';

export function unavailableEndpoint(notes: string[]): EndpointEvidence {
  return {
    available: false,
    source: 'n/a',
    notes: [...notes],
    productName: null,
    binaryPresent: false,
    daemonRunning: null,
    signatureDb: { present: false, path: null, lastUpdated: null },
    verifiedActive: false,
  };
}

/** Module F collector (Windows). Never throws. */
export async function collectEndpoint(execLog: ExecLogEntry[]): Promise<EndpointEvidence> {
  const notes: string[] = [];
  try {
    // ------------------------------------------------------ Defender status
    let statusOk = false;
    let productName: string | null = null;
    let amServiceEnabled: boolean | null = null;
    let rtpEnabled: boolean | null = null;
    let antivirusEnabled: boolean | null = null;
    let signatureLastUpdated: string | null = null;
    let signaturePresent = false;

    const statusRes = await runPs('PS_DEFENDER_STATUS', execLog);
    const status = statusRes.ok ? parseJsonObject(statusRes.stdout) : null;
    if (status) {
      // Get-MpComputerStatus succeeded → Defender platform binaries are present.
      amServiceEnabled = asBool(status.AMServiceEnabled);
      rtpEnabled = asBool(status.RealTimeProtectionEnabled);
      antivirusEnabled = asBool(status.AntivirusEnabled);
      signatureLastUpdated = asDateIso(status.AntivirusSignatureLastUpdated);
      const signatureVersion = asString(status.AntivirusSignatureVersion);
      signaturePresent = signatureVersion !== null || signatureLastUpdated !== null;
      const anyField =
        amServiceEnabled !== null || rtpEnabled !== null || antivirusEnabled !== null || signatureVersion !== null;
      if (!anyField) {
        notes.push('Get-MpComputerStatus returned no usable fields — Microsoft Defender status unknown');
      } else {
        statusOk = true;
        productName = 'Microsoft Defender Antivirus';
        const runningMode = asString(status.AMRunningMode);
        if (runningMode) notes.push(`AMRunningMode=${runningMode}`);
        if (rtpEnabled === false) {
          notes.push('RealTimeProtectionEnabled=False — real-time protection is NOT active');
        }
        if (antivirusEnabled === false) {
          notes.push('AntivirusEnabled=False — the Defender antivirus engine is disabled');
        }
        if (signaturePresent && signatureLastUpdated === null) {
          notes.push('signature version present but its last-update timestamp was not reported');
        }
      }
    } else if (!statusRes.ok) {
      notes.push(failureNote(statusRes, 'Get-MpComputerStatus query'));
    } else {
      notes.push('Get-MpComputerStatus returned no data — Microsoft Defender may be absent, deregistered by a third-party AV, or running on an unsupported SKU');
    }

    // ------------------------------------------------------ Defender preferences
    let prefsOk = false;
    const prefRes = await runPs('PS_DEFENDER_PREFS', execLog);
    const prefs = prefRes.ok ? parseJsonObject(prefRes.stdout) : null;
    if (prefs) {
      const disableRtp = asBool(prefs.DisableRealtimeMonitoring);
      if (disableRtp !== null) {
        prefsOk = true;
        notes.push(
          `DisableRealtimeMonitoring (preference)=${disableRtp ? 'True — real-time monitoring disabled by configuration' : 'False'}`,
        );
      }
      const pua = asNumber(prefs.PUAProtection);
      if (pua !== null) notes.push(`PUAProtection=${pua} (0=disabled, 1=enabled, 2=audit)`);
    } else if (!prefRes.ok) {
      notes.push(failureNote(prefRes, 'Get-MpPreference query'));
    }

    // ------------------------------------------------------ BitLocker context
    let bitlockerOk = false;
    const blRes = await runPs('PS_BITLOCKER', execLog);
    if (blRes.ok) {
      const volumes = parseJsonArray(blRes.stdout);
      if (volumes.length > 0) {
        bitlockerOk = true;
        for (const v of volumes.slice(0, 10)) {
          const mount = asString(v.MountPoint) ?? '?';
          const prot = asString(v.ProtectionStatus) ?? 'unknown';
          const volStatus = asString(v.VolumeStatus) ?? 'unknown';
          const pct = asNumber(v.EncryptionPercentage);
          notes.push(`BitLocker ${mount}: ProtectionStatus=${prot}, VolumeStatus=${volStatus}${pct !== null ? `, ${pct}% encrypted` : ''}`);
        }
      } else {
        notes.push('Get-BitLockerVolume returned no volumes — disk encryption state unknown');
      }
    } else {
      notes.push(failureNote(blRes, 'Get-BitLockerVolume query') + ' — typically requires an elevated session; disk encryption state unknown');
    }

    const available = statusOk || prefsOk || bitlockerOk;
    const verifiedActive = rtpEnabled === true && antivirusEnabled !== false;

    return {
      available,
      source: 'Get-MpComputerStatus + Get-MpPreference + Get-BitLockerVolume',
      notes,
      productName,
      binaryPresent: statusOk,
      daemonRunning: amServiceEnabled,
      signatureDb: {
        present: signaturePresent,
        path: statusOk ? 'Microsoft Defender security intelligence (Windows-managed signature DB)' : null,
        lastUpdated: signatureLastUpdated,
      },
      // true ONLY when real-time protection could actually be verified
      verifiedActive,
    };
  } catch (err) {
    return unavailableEndpoint([`Collection error: ${err instanceof Error ? err.message : String(err)}`]);
  }
}
