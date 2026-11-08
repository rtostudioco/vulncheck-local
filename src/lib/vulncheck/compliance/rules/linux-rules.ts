/**
 * VulnCheck Local — Linux compliance rule registry (21 rules)
 * -------------------------------------------------------------
 * Every rule is versioned, evaluates the full EvidenceBundle defensively and
 * MUST handle every unavailable/missing inspection with NOT_ASSESSED and every
 * inapplicable case with NOT_APPLICABLE. A failed inspection is never treated
 * as secure. Evidence text is concise, multi-line and factual with real values.
 */

import type {
  Category,
  EvidenceBundle,
  RuleDefinition,
  RuleGuide,
  RuleResult,
} from '../../core/types';

// ---------------------------------------------------------------------------
// small text helpers (shared by all rule evidence builders)
// ---------------------------------------------------------------------------

function joinLines(...parts: (string | null | undefined | false)[]): string {
  return parts.filter((p): p is string => typeof p === 'string' && p.length > 0).join('\n');
}

function bulletList(items: string[], max = 10): string {
  const shown = items.slice(0, max).map((i) => `  - ${i}`);
  const more = items.length > max ? [`  … ${items.length - max} more`] : [];
  return [...shown, ...more].join('\n');
}

function na(evidence: string, note?: string): RuleResult {
  return { status: 'NOT_ASSESSED', evidence, ...(note ? { note } : {}) };
}

function yesNo(v: boolean | null): string {
  return v === null ? 'unknown' : v ? 'yes' : 'no';
}

// ---------------------------------------------------------------------------
// rule factory — wraps every evaluation in try/catch (rules never throw)
// ---------------------------------------------------------------------------

type LinuxEval = (ev: EvidenceBundle) => RuleResult;

interface RuleSpec {
  id: string;
  category: Category;
  title: string;
  description: string;
  severityIfFail: RuleDefinition['severityIfFail'];
  reference: string | null;
  guide: RuleGuide;
  evaluate: LinuxEval;
}

function defRule(spec: RuleSpec): RuleDefinition {
  return {
    ...spec,
    version: '1.0.0',
    osTarget: 'linux',
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

// ---------------------------------------------------------------------------
// FIREWALL
// ---------------------------------------------------------------------------

const RISKY_ANY_SOURCE_PORTS = new Set([21, 23, 69, 139, 445, 3389, 5900, 5901, 5902, 873]);

const FIREWALL_RULES: RuleDefinition[] = [
  defRule({
    id: 'VC-FW-001',
    category: 'FIREWALL',
    title: 'Host firewall is active',
    description:
      'Verifies that a host firewall product (ufw, firewalld, nftables or iptables) is installed AND actively enforcing on this Linux host. A firewall that is merely installed but inactive provides no protection.',
    severityIfFail: 'HIGH',
    reference: 'CIS benchmark concept: ensure firewall active',
    guide: {
      problem:
        'No packet filter is enforcing, or the detected firewall product reports an inactive state. Many server images ship without an enabled host firewall.',
      impact:
        'Every listening service is directly reachable from the network the host is attached to, including management and database services that were meant to be internal.',
      solution:
        'Enable UFW with restrictive defaults: `sudo ufw default deny incoming`, `sudo ufw default allow outgoing`, then `sudo ufw enable`. On RHEL-family hosts use `sudo systemctl enable --now firewalld`.',
      verification:
        'Run `sudo ufw status verbose` (expect "Status: active") or `sudo firewall-cmd --state` (expect "running").',
    },
    evaluate: (ev) => {
      const fw = ev.firewall;
      if (!fw.available) {
        return na(
          joinLines('Firewall evidence could not be collected on this host.', ...fw.notes),
          'Firewall collector did not run successfully.',
        );
      }
      if (fw.product === 'none-detected') {
        return {
          status: 'FAIL',
          evidence: joinLines(
            'No firewall product detected.',
            'Binary probe (ufw, firewalld, nftables, iptables) and configuration file inspection found nothing.',
            ...fw.notes,
          ),
        };
      }
      if (fw.active === true) {
        return {
          status: 'PASS',
          evidence: joinLines(
            `Host firewall '${fw.product}' is active.`,
            fw.defaultIncoming ? `Default incoming policy: ${fw.defaultIncoming}.` : null,
            fw.profiles.length ? `Profiles/zones: ${fw.profiles.join(', ')}.` : null,
            fw.rules.length ? `Parsed allow/deny rules: ${fw.rules.length}.` : null,
            ...fw.notes,
          ),
        };
      }
      if (fw.active === false) {
        return {
          status: 'FAIL',
          evidence: joinLines(
            `Firewall product '${fw.product}' is present but inactive.`,
            ...fw.notes,
          ),
        };
      }
      return na(
        joinLines(
          `Firewall product '${fw.product}' is present but its active state could not be verified.`,
          ...fw.notes,
        ),
        'Firewall state unverifiable (e.g. ruleset query requires elevated privileges).',
      );
    },
  }),
  defRule({
    id: 'VC-FW-002',
    category: 'FIREWALL',
    title: 'Default incoming policy is deny',
    description:
      'Verifies that the firewall default policy for incoming traffic is deny/drop/reject, so that only explicitly allowed connections are accepted.',
    severityIfFail: 'HIGH',
    reference: 'CIS benchmark concept: ensure default-deny incoming firewall policy',
    guide: {
      problem:
        'The default incoming policy is permissive (allow/accept), which means any service that starts listening becomes immediately reachable from the network.',
      impact:
        'Accidentally started or newly installed services are exposed by default — the security posture then depends on per-service configuration instead of a safe baseline.',
      solution:
        'For UFW: `sudo ufw default deny incoming`. For firewalld: set the zone target to DROP, e.g. `sudo firewall-cmd --permanent --zone=public --set-target=DROP` and reload. For nftables: define a base chain with `policy drop`.',
      verification:
        'Run `sudo ufw status verbose` and confirm "Default: deny (incoming)".',
    },
    evaluate: (ev) => {
      const fw = ev.firewall;
      if (!fw.available) {
        return na(joinLines('Firewall evidence could not be collected.', ...fw.notes));
      }
      const di = fw.defaultIncoming;
      if (!di) {
        return na(
          joinLines(
            `Firewall product: ${fw.product ?? 'unknown'}.`,
            'No default incoming policy could be determined from collected evidence.',
            ...fw.notes,
          ),
          'Product does not expose a single default incoming policy via read-only probes (firewalld uses per-zone policies; nftables/iptables often require elevated privileges).',
        );
      }
      if (/deny|drop|reject/i.test(di)) {
        return {
          status: 'PASS',
          evidence: `Default incoming policy: ${di} (deny-family). Product: ${fw.product ?? 'unknown'}.`,
        };
      }
      if (/allow|accept/i.test(di)) {
        return {
          status: 'FAIL',
          evidence: joinLines(
            `Default incoming policy: ${di} — incoming traffic is accepted by default.`,
            `Product: ${fw.product ?? 'unknown'}.`,
          ),
        };
      }
      return na(`Unrecognized default incoming policy value: '${di}'.`, 'Value not matching deny/drop/reject or allow/accept families.');
    },
  }),
  defRule({
    id: 'VC-FW-003',
    category: 'FIREWALL',
    title: 'No firewall exceptions expose risky services to any source',
    description:
      'Reviews parsed firewall allow rules for entries that expose high-risk services (FTP, Telnet, TFTP, NetBIOS/SMB, RDP, VNC, unauthenticated rsync) to any source address.',
    severityIfFail: 'MEDIUM',
    reference: 'CIS benchmark concept: review firewall allow rules for risky services',
    guide: {
      problem:
        'A firewall exception (ALLOW from Anywhere/0.0.0.0/::/0) exposes a legacy or high-risk service to the entire network.',
      impact:
        'Plaintext or historically vulnerable services (FTP, Telnet, SMB, VNC, RDP, rsync) become remotely attackable and are common initial-access vectors.',
      solution:
        'Restrict the rule to specific sources (`sudo ufw allow from 10.0.0.0/24 to any port 445 proto tcp`) or remove it (`sudo ufw delete allow 23/tcp`). Prefer encrypted alternatives (SFTP instead of FTP, SSH instead of Telnet).',
      verification:
        'Run `sudo ufw status verbose` and confirm no ALLOW IN rule for ports 21, 23, 69, 139, 445, 873, 3389 or 5900-5902 from Anywhere.',
    },
    evaluate: (ev) => {
      const fw = ev.firewall;
      if (!fw.available) {
        return na(joinLines('Firewall evidence could not be collected.', ...fw.notes));
      }
      const risky = fw.rules.filter((r) => {
        if (!/allow/i.test(r.action)) return false;
        if (!/anywhere|^any$|0\.0\.0\.0|::\/0/i.test(r.from ?? '')) return false;
        const m = /^(\d+)/.exec(r.port ?? '');
        return m ? RISKY_ANY_SOURCE_PORTS.has(Number(m[1])) : false;
      });
      if (risky.length > 0) {
        return {
          status: 'FAIL',
          evidence: joinLines(
            `${risky.length} firewall exception(s) expose risky services to any source:`,
            bulletList(risky.map((r) => `${r.target} → ${r.action} from ${r.from}`)),
          ),
        };
      }
      if (fw.rules.length > 0) {
        return {
          status: 'PASS',
          evidence: joinLines(
            `Parsed ${fw.rules.length} firewall rule(s); none expose ports 21, 23, 69, 139, 445, 873, 3389, 5900-5902 to any source.`,
            fw.product ? `Product: ${fw.product}.` : null,
          ),
        };
      }
      if (fw.product === 'ufw' && fw.active === true) {
        return {
          status: 'PASS',
          evidence: 'UFW is active and its live status output contains no allow rules.',
        };
      }
      return na(
        joinLines(
          `No structured firewall rule set available for exception analysis (product: ${fw.product ?? 'unknown'}).`,
          ...fw.notes,
        ),
        'Exception analysis requires a parseable live rule set.',
      );
    },
  }),
];

// ---------------------------------------------------------------------------
// ACCOUNTS
// ---------------------------------------------------------------------------

const ACCOUNT_RULES: RuleDefinition[] = [
  defRule({
    id: 'VC-AC-001',
    category: 'ACCOUNTS',
    title: 'SSH root login is disabled',
    description:
      'Verifies that the OpenSSH server configuration explicitly disables direct root login (PermitRootLogin no). Direct root login over SSH concentrates brute-force and credential-stuffing risk on the most privileged account.',
    severityIfFail: 'HIGH',
    reference: 'CIS benchmark concept: ensure SSH PermitRootLogin is disabled',
    guide: {
      problem:
        'The SSH daemon permits root to log in directly (PermitRootLogin yes), or relies on upstream defaults instead of an explicit policy.',
      impact:
        'Attackers can target the root account directly over SSH with password guessing or stolen credentials; every compromise is immediately total.',
      solution:
        'Set `PermitRootLogin no` in /etc/ssh/sshd_config (or a file under /etc/ssh/sshd_config.d/), then reload: `sudo systemctl reload ssh`.',
      verification:
        'Run `sudo sshd -T | grep -i permitrootlogin` — expect "permitrootlogin no".',
    },
    evaluate: (ev) => {
      const ssh = ev.accounts.ssh;
      const base = joinLines(
        `SSH service running: ${yesNo(ssh.serviceRunning)}.`,
        ssh.files.length ? `Parsed configuration files: ${ssh.files.join(', ')}.` : null,
        `PermitRootLogin: ${ssh.permitRootLogin ?? 'directive not set'}.`,
      );
      if (!ssh.available) {
        return na(
          joinLines('SSH server configuration could not be read.', base, ...ev.accounts.notes),
          'sshd_config unavailable — SSH hardening cannot be assessed.',
        );
      }
      if (ssh.serviceRunning === false) {
        return {
          status: 'NOT_APPLICABLE',
          evidence: joinLines('SSH service is not running on this host.', base),
          note: 'SSH service not running',
        };
      }
      const v = ssh.permitRootLogin;
      if (v === 'no') {
        return { status: 'PASS', evidence: joinLines('PermitRootLogin: no (explicitly configured).', base) };
      }
      if (v === 'yes') {
        return {
          status: 'FAIL',
          evidence: joinLines('PermitRootLogin: yes — direct root login over SSH is permitted.', base),
        };
      }
      if (v === 'prohibit-password' || v === 'forced-commands-only') {
        return {
          status: 'WARNING',
          evidence: joinLines(
            `PermitRootLogin: ${v} — root restrictions present, but a full disable is recommended (CIS: PermitRootLogin no).`,
            base,
          ),
        };
      }
      return {
        status: 'PASS',
        evidence: joinLines(
          'PermitRootLogin directive not set — OpenSSH default (prohibit-password) applies: password-based root login is refused.',
          base,
        ),
        note: 'OpenSSH default: prohibit-password',
      };
    },
  }),
  defRule({
    id: 'VC-AC-002',
    category: 'ACCOUNTS',
    title: 'SSH password authentication is disabled',
    description:
      'Verifies that the SSH server explicitly disables password authentication (PasswordAuthentication no), forcing key-based authentication that is resistant to online guessing.',
    severityIfFail: 'MEDIUM',
    reference: 'CIS benchmark concept: ensure SSH PasswordAuthentication is disabled',
    guide: {
      problem:
        'The SSH daemon accepts password authentication — either explicitly (PasswordAuthentication yes) or implicitly via the upstream default when the directive is absent.',
      impact:
        'SSH accounts are exposed to online brute-force and credential-stuffing attacks; weak or reused passwords directly yield shell access.',
      solution:
        'Set `PasswordAuthentication no` in /etc/ssh/sshd_config (or a drop-in under /etc/ssh/sshd_config.d/), ensure at least one key-based admin path works, then reload: `sudo systemctl reload ssh`.',
      verification:
        'Run `sudo sshd -T | grep -i passwordauthentication` — expect "passwordauthentication no".',
    },
    evaluate: (ev) => {
      const ssh = ev.accounts.ssh;
      const base = joinLines(
        `SSH service running: ${yesNo(ssh.serviceRunning)}.`,
        ssh.files.length ? `Parsed configuration files: ${ssh.files.join(', ')}.` : null,
        `PasswordAuthentication: ${ssh.passwordAuthentication ?? 'directive not set'}.`,
      );
      if (!ssh.available) {
        return na(
          joinLines('SSH server configuration could not be read.', base, ...ev.accounts.notes),
          'sshd_config unavailable — SSH hardening cannot be assessed.',
        );
      }
      if (ssh.serviceRunning === false) {
        return {
          status: 'NOT_APPLICABLE',
          evidence: joinLines('SSH service is not running on this host.', base),
          note: 'SSH service not running',
        };
      }
      const v = ssh.passwordAuthentication;
      if (v === 'no') return { status: 'PASS', evidence: joinLines('PasswordAuthentication: no (explicit).', base) };
      if (v === 'yes') {
        return {
          status: 'FAIL',
          evidence: joinLines('PasswordAuthentication: yes — SSH passwords are accepted.', base),
        };
      }
      return {
        status: 'WARNING',
        evidence: joinLines(
          'PasswordAuthentication directive not set — default yes in upstream OpenSSH; an explicit "no" is recommended.',
          base,
        ),
      };
    },
  }),
  defRule({
    id: 'VC-AC-003',
    category: 'ACCOUNTS',
    title: 'No accounts with empty password field',
    description:
      'Verifies that no local account has an empty password hash field in /etc/shadow, which would allow passwordless interactive login. Only the field shape (empty/locked/set) is inspected — no credential material is collected.',
    severityIfFail: 'CRITICAL',
    reference: 'CIS benchmark concept: ensure no accounts have empty password fields',
    guide: {
      problem:
        'One or more entries in /etc/shadow have an empty password field, allowing passwordless authentication for that account.',
      impact:
        'Anyone with local or remote (e.g. SSH) access can authenticate as that account without any credential — a near-total compromise primitive.',
      solution:
        'Lock the affected account (`sudo passwd -l <user>`) or set a strong password (`sudo passwd <user>`); investigate how the empty field appeared (account created with `passwd -d`).',
      verification:
        'Run `sudo awk -F: \'($2 == "") { print $1 }\' /etc/shadow` — it must output nothing.',
    },
    evaluate: (ev) => {
      const ac = ev.accounts;
      if (!ac.available) {
        return na(
          joinLines('Account evidence could not be collected on this host.', ...ac.notes),
          'Account collector did not run successfully.',
        );
      }
      if (!ac.shadowReadable) {
        return na(
          joinLines(
            '/etc/shadow is not readable without elevated privileges — the empty-password check cannot be verified.',
            `Accounts parsed from /etc/passwd: ${ac.users.length}.`,
            ...ac.notes,
          ),
          'Shadow unreadable without elevated privileges.',
        );
      }
      const empty = ac.users.filter((u) => u.passwordStatus === 'empty');
      if (empty.length > 0) {
        return {
          status: 'FAIL',
          evidence: joinLines(
            `Accounts with EMPTY password field: ${empty.length}.`,
            bulletList(empty.map((u) => `${u.name} (uid ${u.uid})`)),
          ),
        };
      }
      const counts = ac.users.reduce<Record<string, number>>((acc, u) => {
        acc[u.passwordStatus] = (acc[u.passwordStatus] ?? 0) + 1;
        return acc;
      }, {});
      return {
        status: 'PASS',
        evidence: joinLines(
          `No accounts with empty password field (${ac.users.length} accounts checked).`,
          Object.entries(counts)
            .map(([k, c]) => `${k}: ${c}`)
            .join(', '),
        ),
      };
    },
  }),
  defRule({
    id: 'VC-AC-004',
    category: 'ACCOUNTS',
    title: 'Password aging policy enforced (max ≤ 90 days)',
    description:
      'Verifies that /etc/login.defs defines PASS_MAX_DAYS at 90 days or less so that passwords must be rotated within a bounded window.',
    severityIfFail: 'MEDIUM',
    reference: 'CIS benchmark concept: ensure password expiration is 90 days or less',
    guide: {
      problem:
        'PASS_MAX_DAYS is unset or set above 90, so passwords never expire or expire only after an unreasonably long period.',
      impact:
        'Old, possibly leaked credentials remain valid indefinitely, widening the window for credential-based attacks.',
      solution:
        'Set `PASS_MAX_DAYS 90` in /etc/login.defs and apply to existing accounts: `sudo chage --maxdays 90 <user>`.',
      verification:
        'Run `grep ^PASS_MAX_DAYS /etc/login.defs` (expect 90 or less) and `sudo chage -l <user>` to confirm per-account values.',
    },
    evaluate: (ev) => {
      const p = ev.accounts.passwordPolicy;
      if (p.maxDays === null) {
        return na(
          joinLines(
            'PASS_MAX_DAYS could not be determined.',
            `Password policy source: ${p.source}.`,
            ...ev.accounts.notes,
          ),
          'Password aging policy unavailable.',
        );
      }
      const base = joinLines(
        `PASS_MAX_DAYS: ${p.maxDays}`,
        p.minDays !== null ? `PASS_MIN_DAYS: ${p.minDays}` : null,
        p.warnDays !== null ? `PASS_WARN_AGE: ${p.warnDays}` : null,
        `Source: ${p.source}.`,
      );
      if (p.maxDays <= 90) return { status: 'PASS', evidence: joinLines(`PASS_MAX_DAYS = ${p.maxDays} (≤ 90).`, base) };
      return {
        status: 'FAIL',
        evidence: joinLines(`PASS_MAX_DAYS = ${p.maxDays} — exceeds the 90-day maximum.`, base),
      };
    },
  }),
  defRule({
    id: 'VC-AC-005',
    category: 'ACCOUNTS',
    title: 'No duplicate UID 0 accounts',
    description:
      'Verifies that exactly one account (root) carries UID 0. Additional UID 0 accounts are hidden superusers that bypass per-account auditing.',
    severityIfFail: 'HIGH',
    reference: 'CIS benchmark concept: ensure root is the only UID 0 account',
    guide: {
      problem:
        'More than one account entry in /etc/passwd has UID 0, creating hidden superuser accounts.',
      impact:
        'UID 0 duplicates bypass identity controls: actions cannot be attributed to a person, and the extra accounts are prime backdoor targets.',
      solution:
        'Remove or rename the duplicate accounts: `sudo userdel <duplicate>` (or change their UID), after verifying they are not required.',
      verification:
        'Run `awk -F: \'($3 == 0) { print $1 }\' /etc/passwd` — it must list only "root".',
    },
    evaluate: (ev) => {
      const ac = ev.accounts;
      if (!ac.available) {
        return na(
          joinLines('Account evidence could not be collected on this host.', ...ac.notes),
          'Account collector did not run successfully.',
        );
      }
      const uid0 = ac.users.filter((u) => u.uid === 0);
      if (uid0.length === 0) {
        return na(
          joinLines('No user entries parsed from /etc/passwd — UID 0 check impossible.', ...ac.notes),
          'No user entries available.',
        );
      }
      if (uid0.length === 1 && uid0[0].name === 'root') {
        return {
          status: 'PASS',
          evidence: joinLines(
            'Exactly one UID 0 account: root.',
            `Total accounts parsed: ${ac.users.length}.`,
            ac.adminGroups.sudo?.length ? `sudo group members: ${ac.adminGroups.sudo.join(', ')}.` : null,
            ac.adminGroups.wheel?.length ? `wheel group members: ${ac.adminGroups.wheel.join(', ')}.` : null,
          ),
        };
      }
      return {
        status: 'FAIL',
        evidence: joinLines(
          `${uid0.length} accounts share UID 0:`,
          bulletList(uid0.map((u) => `${u.name} (uid 0, shell ${u.shell || 'n/a'})`)),
        ),
      };
    },
  }),
  defRule({
    id: 'VC-AC-006',
    category: 'ACCOUNTS',
    title: 'Minimum password length ≥ 12',
    description:
      'Verifies that /etc/login.defs defines PASS_MIN_LEN of at least 12 characters (consistent with a 14+ char modern policy for new deployments).',
    severityIfFail: 'LOW',
    reference: 'CIS benchmark concept: ensure minimum password length is 14 or more (12 accepted floor)',
    guide: {
      problem:
        'The minimum password length is below 12 characters (or not defined), allowing short, quickly brute-forceable passwords.',
      impact: 'Short passwords dramatically reduce offline cracking time if a hash is ever obtained.',
      solution:
        'Set `PASS_MIN_LEN 12` (or 14) in /etc/login.defs and enforce complexity via pam_pwquality (minlen=12).',
      verification:
        'Run `grep ^PASS_MIN_LEN /etc/login.defs` and `grep minlen /etc/security/pwquality.conf`.',
    },
    evaluate: (ev) => {
      const p = ev.accounts.passwordPolicy;
      if (p.minLength === null) {
        return na(
          joinLines(
            'PASS_MIN_LEN not defined or /etc/login.defs not readable.',
            `Password policy source: ${p.source}.`,
            ...ev.accounts.notes,
          ),
          'Minimum password length unavailable — check cannot be assessed.',
        );
      }
      if (p.minLength >= 12) {
        return { status: 'PASS', evidence: `PASS_MIN_LEN = ${p.minLength} (≥ 12). Source: ${p.source}.` };
      }
      return {
        status: 'FAIL',
        evidence: `PASS_MIN_LEN = ${p.minLength} — below the 12-character minimum. Source: ${p.source}.`,
      };
    },
  }),
];

// ---------------------------------------------------------------------------
// UPDATES
// ---------------------------------------------------------------------------

const UPDATE_RULES: RuleDefinition[] = [
  defRule({
    id: 'VC-UP-001',
    category: 'UPDATES',
    title: 'No pending package updates',
    description:
      'Verifies via `apt list --upgradable` that no installed packages have pending updates on this Debian/Ubuntu host.',
    severityIfFail: 'MEDIUM',
    reference: 'CIS benchmark concept: ensure package updates are applied promptly',
    guide: {
      problem: 'Installed packages have pending updates that have not been applied.',
      impact:
        'Known, publicly documented vulnerabilities in outdated packages remain exploitable; attackers routinely fingerprint exact package versions.',
      solution:
        'Review and apply updates: `sudo apt update && sudo apt upgrade` (or use a staged patch management process).',
      verification: 'Run `apt list --upgradable` — expect only the "Listing..." header with no entries.',
    },
    evaluate: (ev) => {
      const u = ev.updates;
      if (!u.available) {
        return na(
          joinLines('Update evidence could not be collected (apt unavailable or failed).', ...u.notes),
          'Update collector did not run successfully.',
        );
      }
      if (u.pendingUpdates === null) {
        return na(
          joinLines('Pending update count could not be determined.', ...u.notes),
          'apt list --upgradable failed.',
        );
      }
      if (u.pendingUpdates === 0) {
        return {
          status: 'PASS',
          evidence: joinLines(
            'No pending package updates.',
            u.lastUpdateCheck ? `Last apt lists refresh: ${u.lastUpdateCheck}.` : null,
          ),
        };
      }
      return {
        status: 'FAIL',
        evidence: joinLines(
          `Pending package updates: ${u.pendingUpdates}.`,
          u.pendingPackageNames.length ? 'First 10:' : null,
          u.pendingPackageNames.length ? bulletList(u.pendingPackageNames.slice(0, 10)) : null,
          u.lastUpdateCheck ? `Last apt lists refresh: ${u.lastUpdateCheck}.` : null,
        ),
      };
    },
  }),
  defRule({
    id: 'VC-UP-002',
    category: 'UPDATES',
    title: 'No pending security updates',
    description:
      'Verifies via `apt-get --simulate dist-upgrade` analysis that no pending package set is flagged as security-relevant (security suite/sources).',
    severityIfFail: 'HIGH',
    reference: 'CIS benchmark concept: ensure security updates are applied promptly',
    guide: {
      problem: 'Pending updates include packages from the security suite that fix known vulnerabilities.',
      impact:
        'Publicly disclosed CVEs with ready-made exploits remain exploitable — this is the single most commonly leveraged weakness class.',
      solution: 'Apply security updates promptly: `sudo apt update && sudo apt upgrade` or enable unattended-upgrades.',
      verification:
        'Run `sudo apt-get --simulate dist-upgrade | grep -i security` — expect no output after patching.',
    },
    evaluate: (ev) => {
      const u = ev.updates;
      if (!u.available) {
        return na(
          joinLines('Update evidence could not be collected (apt unavailable or failed).', ...u.notes),
          'Update collector did not run successfully.',
        );
      }
      if (u.pendingSecurityUpdates === null) {
        return na(
          joinLines('Security update count could not be determined.', ...u.notes),
          'apt-get --simulate dist-upgrade failed.',
        );
      }
      if (u.pendingSecurityUpdates === 0) {
        return {
          status: 'PASS',
          evidence: joinLines(
            'No pending security updates (apt-get --simulate dist-upgrade analysis).',
            u.pendingUpdates !== null ? `Total pending (non-security included): ${u.pendingUpdates}.` : null,
          ),
        };
      }
      return {
        status: 'FAIL',
        evidence: joinLines(
          `Pending SECURITY updates: ${u.pendingSecurityUpdates}.`,
          u.pendingPackageNames.length ? 'Pending packages (first 10):' : null,
          u.pendingPackageNames.length ? bulletList(u.pendingPackageNames.slice(0, 10)) : null,
        ),
      };
    },
  }),
  defRule({
    id: 'VC-UP-003',
    category: 'UPDATES',
    title: 'Automatic security updates enabled',
    description:
      'Verifies that unattended-upgrades is configured with a periodic schedule (APT::Periodic::Unattended-Upgrade "1") so security patches are applied without manual intervention.',
    severityIfFail: 'MEDIUM',
    reference: 'CIS benchmark concept: ensure automatic updates are enabled',
    guide: {
      problem:
        'Automatic security updates are disabled or not configured, leaving patching dependent on manual operator action.',
      impact: 'Unattended hosts silently accumulate known-vulnerable package versions over time.',
      solution:
        'Install and enable: `sudo apt install unattended-upgrades`, then ensure /etc/apt/apt.conf.d/20auto-upgrades contains `APT::Periodic::Update-Package-Lists "1";` and `APT::Periodic::Unattended-Upgrade "1";`.',
      verification:
        'Run `cat /etc/apt/apt.conf.d/20auto-upgrades` — Unattended-Upgrade must be "1"; check `systemctl status apt-daily-upgrade.timer`.',
    },
    evaluate: (ev) => {
      const u = ev.updates;
      if (u.autoUpdatesEnabled === null) {
        return na(
          joinLines('Automatic update configuration could not be determined.', ...u.notes),
          'Unattended-upgrades configuration absent or unreadable.',
        );
      }
      if (u.autoUpdatesEnabled === true) {
        return { status: 'PASS', evidence: 'Unattended-upgrades periodic schedule enabled (Unattended-Upgrade "1").' };
      }
      return {
        status: 'FAIL',
        evidence: joinLines(
          'Automatic security updates are disabled (Unattended-Upgrade "0").',
          ...u.notes,
        ),
      };
    },
  }),
  defRule({
    id: 'VC-UP-004',
    category: 'UPDATES',
    title: 'Reboot not required for kernel/security updates',
    description:
      'Verifies that the /var/run/reboot-required flag is absent, i.e. no installed kernel or library update is waiting for a reboot to take effect.',
    severityIfFail: 'MEDIUM',
    reference: 'CIS benchmark concept: ensure systems are rebooted after kernel updates',
    guide: {
      problem: 'A kernel or core library update has been installed but the host has not been rebooted yet.',
      impact:
        'The running kernel/libraries remain the vulnerable pre-update versions even though "patched" packages are on disk — scanners and patch reports overstate actual protection.',
      solution: 'Schedule a maintenance window and reboot the host: `sudo reboot` (verify afterwards that /var/run/reboot-required is gone).',
      verification: 'Run `ls /var/run/reboot-required` — the file should not exist; `uname -r` should match the newest installed kernel.',
    },
    evaluate: (ev) => {
      const u = ev.updates;
      if (u.rebootRequired === null) {
        return na(
          joinLines('Reboot-required flag could not be checked.', ...u.notes),
          'Update collector did not run successfully.',
        );
      }
      if (u.rebootRequired === false) {
        return { status: 'PASS', evidence: 'No reboot required (/var/run/reboot-required absent).' };
      }
      return {
        status: 'FAIL',
        evidence: joinLines(
          'Reboot required: /var/run/reboot-required is present — running kernel/libraries predate installed security updates.',
          ...u.notes,
        ),
      };
    },
  }),
];

// ---------------------------------------------------------------------------
// NETWORK
// ---------------------------------------------------------------------------

const MGMT_DB_PORTS = new Set([111, 1433, 1521, 2049, 3306, 5432, 5555, 6379, 8080, 9200, 11211, 27017]);

const NETWORK_RULES: RuleDefinition[] = [
  defRule({
    id: 'VC-NE-001',
    category: 'NETWORK',
    title: 'No high-risk services listening on all interfaces',
    description:
      'Verifies that no socket classified as CRITICAL or HIGH risk (e.g. Telnet, plaintext FTP, VNC, RDP, SMB, memcached) is bound to all interfaces (0.0.0.0/[::/*).',
    severityIfFail: 'HIGH',
    reference: 'CIS benchmark concept: restrict network services to necessary interfaces',
    guide: {
      problem: 'A high-risk service is listening on all interfaces instead of localhost or a restricted network.',
      impact: 'The service is reachable by every network the host is attached to, including untrusted segments.',
      solution:
        'Bind the service to localhost or a management interface (e.g. for Redis: `bind 127.0.0.1`), or restrict access with the host firewall: `sudo ufw deny <port>/tcp`.',
      verification: 'Run `ss -tuln` and confirm no CRITICAL/HIGH-risk port is bound to 0.0.0.0, [::] or *.',
    },
    evaluate: (ev) => {
      const n = ev.network;
      if (!n.available) {
        return na(
          joinLines('Network evidence could not be collected on this host.', ...n.notes),
          'Network collector did not run successfully.',
        );
      }
      const risky = n.listeningPorts.filter(
        (p) => p.bindScope === 'ALL' && (p.risk === 'CRITICAL' || p.risk === 'HIGH'),
      );
      if (risky.length > 0) {
        return {
          status: 'FAIL',
          evidence: joinLines(
            `${risky.length} high-risk socket(s) bound to ALL interfaces:`,
            bulletList(risky.map((p) => `${p.proto}/${p.port} ${p.service} — ${p.note}`)),
          ),
        };
      }
      const all = n.listeningPorts.filter((p) => p.bindScope === 'ALL').length;
      const local = n.listeningPorts.filter((p) => p.bindScope === 'LOCAL').length;
      return {
        status: 'PASS',
        evidence: joinLines(
          'No CRITICAL/HIGH-risk services listening on all interfaces.',
          `Listening sockets: ${n.listeningPorts.length} (ALL-bound: ${all}, local-only: ${local}).`,
        ),
      };
    },
  }),
  defRule({
    id: 'VC-NE-002',
    category: 'NETWORK',
    title: 'Management and database services not reachable from all interfaces',
    description:
      'Verifies that management/database services (rpcbind, MSSQL, Oracle, NFS, MySQL, PostgreSQL, ADB, Redis, http-alt, Elasticsearch, memcached, MongoDB) are not bound to all interfaces.',
    severityIfFail: 'MEDIUM',
    reference: 'CIS benchmark concept: bind management services to trusted interfaces',
    guide: {
      problem: 'A management or database service listens on all interfaces instead of localhost or a dedicated internal network.',
      impact:
        'Infrastructure services (databases, caches, RPC brokers) are reachable from untrusted networks; combined with default credentials or unauthenticated modes this is a frequent breach path.',
      solution:
        'Bind to localhost/management interface (e.g. MySQL `bind-address=127.0.0.1`, PostgreSQL `listen_addresses`), and/or enforce firewall restrictions to known CIDRs.',
      verification: 'Run `ss -tuln` and confirm ports 111, 1433, 1521, 2049, 3306, 5432, 5555, 6379, 8080, 9200, 11211, 27017 are not bound to 0.0.0.0/[::]/*.',
    },
    evaluate: (ev) => {
      const n = ev.network;
      if (!n.available) {
        return na(
          joinLines('Network evidence could not be collected on this host.', ...n.notes),
          'Network collector did not run successfully.',
        );
      }
      const exposed = n.listeningPorts.filter((p) => p.bindScope === 'ALL' && MGMT_DB_PORTS.has(p.port));
      if (exposed.length > 0) {
        return {
          status: 'FAIL',
          evidence: joinLines(
            `${exposed.length} management/database socket(s) bound to ALL interfaces:`,
            bulletList(exposed.map((p) => `${p.proto}/${p.port} ${p.service} — ${p.note}`)),
          ),
        };
      }
      return {
        status: 'PASS',
        evidence: joinLines(
          'No management/database services bound to all interfaces.',
          `Listening sockets: ${n.listeningPorts.length}.`,
        ),
      };
    },
  }),
  defRule({
    id: 'VC-NE-003',
    category: 'NETWORK',
    title: 'Listening surface within reviewed baseline',
    description:
      'Reports the total number of listening TCP/UDP sockets against a reviewed baseline of 15. Exceeding the baseline is a WARNING that the surface should be re-reviewed for unnecessary listeners.',
    severityIfFail: 'LOW',
    reference: 'CIS benchmark concept: review listening services baseline',
    guide: {
      problem: 'The host exposes more listening sockets than the reviewed baseline (15).',
      impact: 'Every additional listener enlarges the attack surface and the patch/monitoring burden; stale services often run unmaintained.',
      solution:
        'Identify owners of each listener (`ss -tulnp` as root), disable unused services (`sudo systemctl disable --now <unit>`) and re-baseline.',
      verification: 'Run `ss -tuln | wc -l` and compare against the agreed baseline.',
    },
    evaluate: (ev) => {
      const n = ev.network;
      if (!n.available) {
        return na(
          joinLines('Network evidence could not be collected on this host.', ...n.notes),
          'Network collector did not run successfully.',
        );
      }
      const total = n.listeningPorts.length;
      const all = n.listeningPorts.filter((p) => p.bindScope === 'ALL').length;
      const local = n.listeningPorts.filter((p) => p.bindScope === 'LOCAL').length;
      const base = joinLines(
        `Listening sockets: ${total} (ALL-bound: ${all}, local-only: ${local}, other: ${total - all - local}).`,
      );
      if (total <= 15) {
        return { status: 'PASS', evidence: joinLines('Listening surface within baseline (≤ 15).', base) };
      }
      return {
        status: 'WARNING',
        evidence: joinLines(
          `Listening surface exceeds the reviewed baseline of 15 (${total} sockets) — review for unnecessary listeners.`,
          base,
        ),
      };
    },
  }),
];

// ---------------------------------------------------------------------------
// ENDPOINT
// ---------------------------------------------------------------------------

const ENDPOINT_RULES: RuleDefinition[] = [
  defRule({
    id: 'VC-EP-001',
    category: 'ENDPOINT',
    title: 'Anti-malware protection present',
    description:
      'Verifies that an anti-malware product (ClamAV on Linux builds) is installed and that real-time protection (clamav-daemon) is verifiably running. Protection is never claimed active without verification.',
    severityIfFail: 'MEDIUM',
    reference: 'CIS benchmark concept: ensure anti-malware solution is installed and running',
    guide: {
      problem: 'No anti-malware product was detected, or it is installed but its daemon is not running.',
      impact: 'Malware payloads (webshells, cryptominers, ransomware droppers) are not intercepted on-access.',
      solution:
        'Install and enable ClamAV: `sudo apt install clamav clamav-daemon`, `sudo systemctl enable --now clamav-daemon clamav-freshclam`, and verify signatures update automatically.',
      verification:
        'Run `systemctl is-active clamav-daemon` (expect "active") and `ls /var/lib/clamav/*.cvd` for fresh signature databases.',
    },
    evaluate: (ev) => {
      const ep = ev.endpoint;
      if (!ep.available) {
        return na(
          joinLines('Endpoint protection evidence could not be collected.', ...ep.notes),
          'Endpoint collector did not run successfully.',
        );
      }
      const sig = ep.signatureDb.present
        ? `Signature DB: present at ${ep.signatureDb.path}${ep.signatureDb.lastUpdated ? `, newest signature file ${ep.signatureDb.lastUpdated}` : ' (no .cvd/.cld files found)'}.`
        : 'Signature DB: not found (/var/lib/clamav absent).';
      if (ep.verifiedActive) {
        return {
          status: 'PASS',
          evidence: joinLines(
            `Anti-malware: ${ep.productName} — daemon verified running (systemctl is-active clamav-daemon).`,
            sig,
          ),
        };
      }
      if (ep.productName === null) {
        return {
          status: 'FAIL',
          evidence: joinLines('No anti-malware product detected.', ...ep.notes),
        };
      }
      return {
        status: 'WARNING',
        evidence: joinLines(
          `${ep.productName} is installed but real-time protection could not be verified.`,
          `Daemon running: ${yesNo(ep.daemonRunning)}.`,
          sig,
          ...ep.notes,
        ),
      };
    },
  }),
];

// ---------------------------------------------------------------------------
// SERVICES
// ---------------------------------------------------------------------------

const SERVICE_RULES: RuleDefinition[] = [
  defRule({
    id: 'VC-SV-001',
    category: 'SERVICES',
    title: 'No legacy insecure services running',
    description:
      'Verifies that no legacy insecure services (Telnet, r-services, TFTP, plaintext FTP daemons) are running. Medium/low-risk findings (Samba, NFS, SNMP, memcached, redis, CUPS) are reported in the evidence for review.',
    severityIfFail: 'HIGH',
    reference: 'CIS benchmark concept: ensure legacy insecure services are removed',
    guide: {
      problem: 'A legacy insecure service (Telnet, rsh/rlogin/rexec, TFTP, plaintext FTP) is running on this host.',
      impact:
        'These services transmit credentials and data in plaintext and have decades of known exploitation history — they are effectively open doors.',
      solution:
        'Disable and remove the service: `sudo systemctl disable --now <unit>` and `sudo apt remove <package>`; replace with encrypted equivalents (SSH, SFTP/FTPS, HTTPS).',
      verification: 'Run `ss -tuln` and confirm ports 23 (telnet), 21 (ftp), 69 (tftp), 513/514 (r-services) have no listeners.',
    },
    evaluate: (ev) => {
      const s = ev.services;
      if (!s.available) {
        return na(
          joinLines('Service evidence could not be collected on this host.', ...s.notes),
          'Service collector did not run successfully.',
        );
      }
      const bad = s.riskyServices.filter((r) => r.severity === 'CRITICAL' || r.severity === 'HIGH');
      const others = s.riskyServices.filter((r) => r.severity === 'MEDIUM' || r.severity === 'LOW');
      if (bad.length > 0) {
        return {
          status: 'FAIL',
          evidence: joinLines(
            `Legacy insecure services running: ${bad.length}.`,
            bulletList(bad.map((r) => `${r.name} — ${r.reason} (${r.severity})`)),
            others.length ? `Also running (medium/low risk): ${others.map((o) => o.name).join(', ')}.` : null,
          ),
        };
      }
      return {
        status: 'PASS',
        evidence: joinLines(
          'No legacy insecure services detected.',
          others.length
            ? `Lower-risk services running (review recommended): ${bulletList(others.map((o) => `${o.name} — ${o.reason} (${o.severity})`), 6)}`
            : null,
          `Running service units known: ${s.runningServices.length}, unique process names: ${s.runningProcesses.length}.`,
        ),
      };
    },
  }),
  defRule({
    id: 'VC-SV-002',
    category: 'SERVICES',
    title: 'Running service inventory reviewed',
    description:
      'Reports the size of the running service inventory against a threshold of 60. A large surface is a WARNING prompting a review for unnecessary services.',
    severityIfFail: 'INFO',
    reference: null,
    guide: {
      problem: 'The host runs more services than the review threshold, indicating accumulated, possibly unnecessary software.',
      impact: 'More services mean more listeners, more credentials, more patching and more privileged code paths.',
      solution:
        'List unit states (`systemctl list-units --type=service --state=running`), map each to its owner, and disable clearly unnecessary ones.',
      verification: 'Run `systemctl list-units --type=service --state=running --no-pager --no-legend | wc -l`.',
    },
    evaluate: (ev) => {
      const s = ev.services;
      if (!s.available) {
        return na(
          joinLines('Service evidence could not be collected on this host.', ...s.notes),
          'Service collector did not run successfully.',
        );
      }
      const count = s.systemdAvailable ? s.runningServices.length : s.runningProcesses.length;
      const basis = s.systemdAvailable
        ? `${count} running systemd service units`
        : `${count} unique process names (systemd unavailable — process-table fallback)`;
      const base = joinLines(
        `Service inventory: ${basis}.`,
        s.systemdAvailable && s.runningServices.length
          ? `Sample: ${s.runningServices.slice(0, 10).join(', ')}.`
          : null,
        ...s.notes,
      );
      if (count <= 60) {
        return { status: 'PASS', evidence: joinLines('Service count within review threshold (≤ 60).', base) };
      }
      return {
        status: 'WARNING',
        evidence: joinLines(
          'Large service surface — review for unnecessary services.',
          base,
        ),
      };
    },
  }),
];

// ---------------------------------------------------------------------------
// BACKUP
// ---------------------------------------------------------------------------

const BACKUP_RULES: RuleDefinition[] = [
  defRule({
    id: 'VC-BK-001',
    category: 'BACKUP',
    title: 'Backup tooling or scheduled backup jobs detected',
    description:
      'Verifies that at least one backup mechanism exists on this host: a backup tool binary (timeshift, rsnapshot, restic, borg, borgmatic, duplicity, deja-dup, bacula, kopia) or a scheduled cron job matching backup patterns.',
    severityIfFail: 'MEDIUM',
    reference: 'CIS benchmark concept: ensure a backup/recovery mechanism exists',
    guide: {
      problem: 'No backup tool and no scheduled backup job could be detected on this host.',
      impact: 'If the host is compromised, encrypted by ransomware, or its disk fails, there is no recovery path — data loss becomes permanent.',
      solution:
        'Deploy a backup mechanism appropriate to the host role (e.g. `restic` snapshots to remote storage or `timeshift` for system state) and schedule it in /etc/cron.d or systemd timers.',
      verification:
        'Check `/etc/crontab`, `/etc/cron.d/` for backup entries and run `which restic borg timeshift` to confirm tooling.',
    },
    evaluate: (ev) => {
      const b = ev.backup;
      if (!b.available) {
        return na(
          joinLines('Backup evidence could not be collected on this host.', ...b.notes),
          'Backup collector did not run successfully.',
        );
      }
      if (b.toolsDetected.length === 0 && b.scheduledJobs.length === 0) {
        return {
          status: 'FAIL',
          evidence: joinLines(
            'No backup software or scheduled backup jobs detected.',
            'Tools probed: timeshift, rsnapshot, restic, borg, borgmatic, duplicity, deja-dup, bacula, kopia.',
            b.snapshotDirs.length ? `Snapshot/backup directories present: ${b.snapshotDirs.join(', ')} (no tooling or jobs).` : null,
            ...b.notes,
          ),
        };
      }
      return {
        status: 'PASS',
        evidence: joinLines(
          'Backup indicators found.',
          b.toolsDetected.length ? `Tools: ${b.toolsDetected.join(', ')}.` : null,
          b.scheduledJobs.length ? `Scheduled jobs (${b.scheduledJobs.length}):` : null,
          b.scheduledJobs.length
            ? bulletList(b.scheduledJobs.map((j) => `${j.file} [${j.schedule}] ${j.command.slice(0, 80)}`), 8)
            : null,
        ),
      };
    },
  }),
  defRule({
    id: 'VC-BK-002',
    category: 'BACKUP',
    title: 'Backup recency verifiable',
    description:
      'Reports the newest backup indicator timestamp found on the host. Recency is NEVER treated as validity: the rule evidence always states that a timestamp is not proof of a restorable backup.',
    severityIfFail: 'LOW',
    reference: null,
    guide: {
      problem: 'No backup artifact, snapshot directory or backup-scheduled job could be found, so recency cannot be verified.',
      impact: 'Without any recency indicator, the actual recoverability of the host is unknown — possibly zero protection.',
      solution:
        'Run and verify a backup, then record its provenance: e.g. `restic backup /etc /home`, followed by a restore test (`restic restore latest --target /tmp/restore-test`).',
      verification:
        'Check `ls -lt /var/backups` or snapshot directories for recent artifacts — and always validate with a restore test, not the timestamp.',
    },
    evaluate: (ev) => {
      const b = ev.backup;
      if (!b.available) {
        return na(
          joinLines('Backup evidence could not be collected on this host.', ...b.notes),
          'Backup collector did not run successfully.',
        );
      }
      if (b.lastBackupDate) {
        return {
          status: 'PASS',
          evidence: joinLines(
            `Newest backup indicator: ${b.lastBackupDate} (recency ≠ validity).`,
            'This is a filesystem timestamp — NOT proof of a valid, restorable backup. Validate with a restore test.',
            ...b.notes,
          ),
          note: 'Backup recency ≠ validity; validity never claimed without verification.',
        };
      }
      return na(
        joinLines(
          'Backup recency could not be verified — no backup artifacts, snapshot directories or backup-scheduled jobs were found.',
          ...b.notes,
        ),
        'Backup recency could not be verified — validity never claimed without verification.',
      );
    },
  }),
];

// ---------------------------------------------------------------------------

export const LINUX_RULES: RuleDefinition[] = [
  ...FIREWALL_RULES,
  ...ACCOUNT_RULES,
  ...UPDATE_RULES,
  ...NETWORK_RULES,
  ...ENDPOINT_RULES,
  ...SERVICE_RULES,
  ...BACKUP_RULES,
];
